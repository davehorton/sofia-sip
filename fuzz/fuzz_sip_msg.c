/*
 * libFuzzer harness: SIP message parsing as tport/nta does it.
 *
 * Byte 0 selects the mode:
 *   bit 0 = 0 : datagram (UDP) -- whole input committed at once, eos=1
 *   bit 0 = 1 : stream (TCP/TLS/WS) -- fed in chunks of ((byte0>>1)+1) bytes,
 *               parsed after every chunk like tport_parse(), pipelined
 *               messages split with msg_next().
 * Each successfully parsed message is then exercised the way nta/drachtio
 * touch it: sanity check, serialize, encode to string, dup/copy, URL print.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <sofia-sip/su.h>
#include <sofia-sip/su_alloc.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/msg_buffer.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/msg_parser.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_parser.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/url.h>

static void exercise(msg_t *msg)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_t *sip = sip_object(msg);
  size_t len = 0;
  char *s;
  msg_t *dup;

  if (!sip)
    return;

  (void)sip_sanity_check(sip);

  if (sip->sip_request && sip->sip_request->rq_url) {
    char *u = url_as_string(home, sip->sip_request->rq_url);
    if (u) {
      url_t *u2 = url_hdup(home, url_make(home, u));
      (void)u2;
    }
  }
  /* what nta/drachtio do with routing URIs (nta.c leg route, controller.cpp) */
  if (sip->sip_record_route) {
    sip_route_t *r = sip_route_dup(home, (sip_route_t *)sip->sip_record_route);
    if (r && r->r_url->url_params) (void)url_has_param(r->r_url, "lr");
  }
  if (sip->sip_route) {
    sip_route_t *r = sip_route_dup(home, sip->sip_route);
    if (r) {
      (void)url_has_param(r->r_url, "lr");
      if (r->r_url->url_params) {
        char tp[16];
        (void)url_param(r->r_url->url_params, "transport", tp, sizeof tp);
        (void)url_param(r->r_url->url_params, "maddr", NULL, 0);
      }
    }
  }
  if (sip->sip_request && sip->sip_request->rq_url) {
    url_t *a = url_hdup(home, sip->sip_request->rq_url);
    if (a) (void)url_cmp(a, sip->sip_request->rq_url);
  }
  if (sip->sip_via) {
    sip_via_t *v = sip_via_dup(home, sip->sip_via);
    (void)v;
  }
  if (sip->sip_contact) {
    sip_contact_t *m = sip_contact_dup(home, sip->sip_contact);
    (void)m;
  }

  if (msg_serialize(msg, (msg_pub_t *)sip) == 0) {
    s = msg_as_string(home, msg, NULL, 0, &len);
    (void)s;
  }

  dup = msg_dup(msg);
  if (dup) msg_destroy(dup);
  dup = msg_copy(msg);
  if (dup) msg_destroy(dup);

  su_home_deinit(home);
}

static int do_datagram(const uint8_t *data, size_t size)
{
  msg_t *msg = msg_create(sip_default_mclass(), MSG_DO_EXTRACT_COPY);
  msg_iovec_t iov[msg_n_fragments];
  isize_t veclen;
  size_t i, off = 0;

  if (!msg) return 0;
  if (size == 0) { msg_destroy(msg); return 0; }

  veclen = msg_recv_iovec(msg, iov, msg_n_fragments, size, 1);
  if (veclen < 0) { msg_destroy(msg); return 0; }
  for (i = 0; i < (size_t)veclen && off < size; i++) {
    size_t n = iov[i].mv_len;
    if (n > size - off) n = size - off;
    memcpy(iov[i].mv_base, data + off, n);
    off += n;
  }
  msg_recv_commit(msg, size, 1);
  if (msg_extract(msg) > 0)
    exercise(msg);
  msg_destroy(msg);
  return 0;
}

static int do_stream(const uint8_t *data, size_t size, size_t chunk)
{
  msg_t *msg = NULL, *next;
  size_t off = 0;
  int guard = 0;

  while (off < size || msg) {
    if (++guard > 100000) break;

    if (off < size) {
      msg_iovec_t iov[msg_n_fragments];
      isize_t veclen;
      size_t n = size - off < chunk ? size - off : chunk, i, c = 0;
      int eos;

      if (!msg && !(msg = msg_create(sip_default_mclass(), MSG_DO_EXTRACT_COPY)))
        return 0;
      veclen = msg_recv_iovec(msg, iov, msg_n_fragments, n, 0);
      if (veclen < 0) { msg_destroy(msg); return 0; }
      for (i = 0; i < (size_t)veclen && c < n; i++) {
        size_t k = iov[i].mv_len;
        if (k > n - c) k = n - c;
        memcpy(iov[i].mv_base, data + off + c, k);
        c += k;
      }
      off += n;
      eos = off >= size;
      msg_recv_commit(msg, n, eos);
    }
    else {
      /* no more input: if a message is pending it is incomplete */
      msg_recv_commit(msg, 0, 1);
    }

    /* parse loop, mirrors tport_parse() for stream transports */
    for (; msg; msg = next) {
      int r = msg_extract(msg);
      int complete = off >= size;
      next = NULL;
      if (r == 0) {
        if (complete) { msg_destroy(msg); msg = NULL; }
        break;                      /* need more data */
      }
      if (r > 0) {
        next = msg_next(msg);
        exercise(msg);
      }
      msg_destroy(msg);
      if (r < 0) { next = NULL; msg = NULL; return 0; }
    }
  }
  if (msg) msg_destroy(msg);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1) return 0;
  if (data[0] & 1)
    return do_stream(data + 1, size - 1, (size_t)(data[0] >> 1) + 1);
  return do_datagram(data + 1, size - 1);
}
