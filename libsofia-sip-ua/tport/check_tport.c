/*
 * This file is part of the Sofia-SIP package
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**@CFILE check_tport.c
 *
 * @brief Black-box tests for the stream transports: TCP, TLS, WS and WSS.
 *
 * The peer is not sofia-sip: it is plain non-blocking sockets and OpenSSL
 * driven from the test, as a SIP phone, a browser or a carrier would be.
 * Peer and tport share one thread, so the peer never blocks; it pumps the
 * su_root while it waits. That also measures how long tport keeps the
 * thread: every su_root_step() is timed, and a step that takes longer than
 * STALL_MS fails the test. A stalled sofia thread stalls all of
 * drachtio-server.
 */

#include "config.h"

#include <sofia-sip/su.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/su_string.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/tport_tag.h>

#include "tport_internal.h"

#include <s2check.h>
#include <s2base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* Longest su_root_step() allowed, in milliseconds */
#define STALL_MS 500

/* ---------------------------------------------------------------------- */
/* Transports under test */

enum { TCP, TLS, WS, WSS, NPROTOS };

static char const * const protos[NPROTOS] = { "tcp", "tls", "ws", "wss" };
static char const * const via_protos[NPROTOS] = { "TCP", "TLS", "WS", "WSS" };

static int is_secure(int p) { return p == TLS || p == WSS; }
static int is_ws(int p) { return p == WS || p == WSS; }

/* ---------------------------------------------------------------------- */
/* Time and the event loop */

static long long
now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static long long max_stall;	/* longest su_root_step() so far, ms */

static void
step(void)
{
  long long t0 = now_ms(), dt;

  su_root_step(s2base->root, 1);

  dt = now_ms() - t0;
  if (dt > max_stall)
    max_stall = dt;
}

static void
pump(int ms)
{
  long long until = now_ms() + ms;

  do
    step();
  while (now_ms() < until);
}

#define NO_STALL()						\
  ck_assert_msg(max_stall <= STALL_MS,				\
		"sofia thread blocked for %lld ms", max_stall)

/* ---------------------------------------------------------------------- */
/* The stack above tport: collects what it receives */

struct rx {
  struct rx *next;
  msg_t *msg;
  tport_t *tport;
};

static struct rx *received;
static int errors;

static void
stack_recv(tp_stack_t *stack, tport_t *tp, msg_t *msg,
	   tp_magic_t *magic, su_time_t when)
{
  struct rx *r = calloc(1, sizeof *r), **tail;

  fail_unless(r != NULL);
  r->msg = msg;
  r->tport = tport_ref(tp);

  for (tail = &received; *tail; tail = &(*tail)->next)
    ;
  *tail = r;
}

static void
stack_error(tp_stack_t *stack, tport_t *tp, int errcode, char const *remote)
{
  errors++;
}

static msg_t *
stack_alloc(tp_stack_t *stack, int flags,
	    char const data[], usize_t len,
	    tport_t const *tp, tp_client_t *tpc)
{
  msg_t *msg = msg_create(sip_default_mclass(), flags);
  msg_maxsize(msg, 1024 * 1024);
  return msg;
}

static tp_stack_class_t const stack_class[1] = {{
    sizeof stack_class,
    stack_recv,
    stack_error,
    stack_alloc,
  }};

static void
free_rx(struct rx *r)
{
  if (r) {
    msg_destroy(r->msg);
    tport_unref(r->tport);
    free(r);
  }
}

/** Wait for tport to deliver a message; NULL if none within ms */
static struct rx *
wait_rx(int ms)
{
  long long until = now_ms() + ms;
  struct rx *r;

  while (!received && now_ms() < until)
    step();

  if ((r = received))
    received = r->next, r->next = NULL;

  return r;
}

/* ---------------------------------------------------------------------- */
/* The tport under test */

static tport_t *master;
static char const *ports[NPROTOS];
static char certdir[1024];

static char *
cert(char const *name)
{
  static char paths[4][1100];
  static int i;
  char *p = paths[i++ % 4];

  snprintf(p, sizeof paths[0], "%s/%s", certdir, name);
  return p;
}

/** Bind a server primary for proto on 127.0.0.1 */
static char const *
bind_server(tport_t *mr, int p, tag_type_t tag, tag_value_t value, ...)
{
  tp_name_t tpn[1] = {{ NULL, NULL, "127.0.0.1", "*", NULL, NULL }};
  char const *list[2] = { NULL, NULL };
  tport_t *tp;
  ta_list ta;
  int rv;

  list[0] = protos[p];
  tpn->tpn_proto = protos[p];

  ta_start(ta, tag, value);
  rv = tport_tbind(mr, tpn, list,
		   TPTAG_SERVER(1),
		   TPTAG_PONG2PING(1),
		   TAG_IF(is_secure(p),
			  TPTAG_TLS_CERTIFICATE_KEY_FILE(cert("server.pem"))),
		   TAG_IF(is_secure(p),
			  TPTAG_TLS_CERTIFICATE_FILE(cert("server.pem"))),
		   ta_tags(ta));
  ta_end(ta);
  ck_assert_msg(rv == 0, "cannot bind %s", protos[p]);

  for (tp = tport_primaries(mr); tp; tp = tport_next(tp))
    if (su_casematch(tport_name(tp)->tpn_proto, protos[p]))
      return tport_name(tp)->tpn_port;

  ck_abort_msg("no %s primary", protos[p]);
  return NULL;
}

static void
setup(void)
{
  char const *srcdir = getenv("srcdir");
  int p;

  snprintf(certdir, sizeof certdir, "%s/tls", srcdir ? srcdir : ".");

  s2_setup("tport");

  master = tport_tcreate((tp_stack_t *)stack_class, stack_class,
			 s2base->root, TAG_END());
  fail_unless(master != NULL);

  for (p = 0; p < NPROTOS; p++)
    ports[p] = bind_server(master, p, TAG_END());

  max_stall = 0, errors = 0, received = NULL;
}

static void
teardown(void)
{
  struct rx *r;

  while ((r = received))
    received = r->next, free_rx(r);

  tport_destroy(master), master = NULL;
  s2_teardown();
}

/** Count secondary transports, open and closed-but-not-freed */
static int
secondaries(tport_t *mr)
{
  tport_primary_t *pri;
  tport_t *tp;
  int n = 0;

  for (pri = ((tport_master_t *)mr)->mr_primaries; pri; pri = pri->pri_next) {
    for (tp = tport_secondary(pri->pri_primary); tp; tp = tport_next(tp))
      n++;
    for (tp = pri->pri_closed; tp; tp = tp->tp_right)
      n++;
  }

  return n;
}

/** Wait until all connections are gone */
static int
wait_no_secondaries(tport_t *mr, int ms)
{
  long long until = now_ms() + ms;

  while (secondaries(mr) && now_ms() < until)
    step();

  return secondaries(mr);
}

/** Send a response on the connection a request came in on */
static int
reply(struct rx *r, char const *callid)
{
  char text[512];
  msg_t *msg;
  tport_t *tp;

  snprintf(text, sizeof text,
	   "SIP/2.0 200 OK\r\n"
	   "Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK.check.tport\r\n"
	   "From: <sip:peer@example.org>;tag=1\r\n"
	   "To: <sip:drachtio@127.0.0.1>;tag=2\r\n"
	   "Call-ID: %s\r\n"
	   "CSeq: 1 OPTIONS\r\n"
	   "Content-Length: 0\r\n"
	   "\r\n", callid);

  msg = msg_make(sip_default_mclass(), 0, text, strlen(text));
  fail_unless(msg != NULL);
  tp = tport_tsend(r->tport, msg, tport_name(r->tport), TAG_END());
  msg_destroy(msg);

  return tp ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* The peer */

struct peer {
  int proto;
  int fd;
  SSL *ssl;
  int eof;			/* connection closed by tport */
  int ws_closed;		/* WebSocket close frame received */
  size_t rawlen;		/* WebSocket frames not yet decoded */
  size_t len;			/* application data received */
  char raw[256 * 1024];
  char buf[256 * 1024];
};

static SSL_CTX *client_ctx(int with_cert)
{
  static SSL_CTX *ctx[2];

  if (!ctx[with_cert]) {
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    fail_unless(c != NULL);
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    if (with_cert) {
      fail_unless(SSL_CTX_use_certificate_file(c, cert("client.pem"),
					       SSL_FILETYPE_PEM) == 1);
      fail_unless(SSL_CTX_use_PrivateKey_file(c, cert("client.pem"),
					      SSL_FILETYPE_PEM) == 1);
    }
    ctx[with_cert] = c;
  }

  return ctx[with_cert];
}

static void
nonblocking(int fd)
{
  int one = 1;
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

/** Write all of data, pumping the event loop while the socket is full */
static int
peer_write(struct peer *pe, void const *data, size_t len)
{
  char const *b = data;
  long long until = now_ms() + 5000;

  while (len > 0 && now_ms() < until) {
    ssize_t n;

    if (pe->ssl) {
      n = SSL_write(pe->ssl, b, (int)len);
      if (n <= 0) {
	int e = SSL_get_error(pe->ssl, (int)n);
	if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
	  return -1;
	n = 0;
      }
    }
    else {
      n = send(pe->fd, b, len, MSG_NOSIGNAL);
      if (n < 0) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	  return -1;
	n = 0;
      }
    }

    b += n, len -= n;
    if (len)
      step();
  }

  return len ? -1 : 0;
}

/** Decode complete WebSocket frames from raw into buf */
static void
ws_decode(struct peer *pe)
{
  for (;;) {
    unsigned char const *f = (unsigned char *)pe->raw;
    size_t hdr = 2, plen, i;

    if (pe->rawlen < 2)
      return;

    plen = f[1] & 0x7f;
    if (plen == 126) {
      if (pe->rawlen < 4)
	return;
      plen = (f[2] << 8) | f[3], hdr = 4;
    }
    else if (plen == 127) {
      if (pe->rawlen < 10)
	return;
      for (plen = 0, i = 2; i < 10; i++)
	plen = (plen << 8) | f[i];
      hdr = 10;
    }
    ck_assert_msg(!(f[1] & 0x80), "server frames must not be masked");

    if (pe->rawlen < hdr + plen)
      return;

    if ((f[0] & 0x0f) == 0x8)
      pe->ws_closed = 1;
    else if ((f[0] & 0x0f) <= 0x2) {	/* continuation, text, binary */
      fail_unless(pe->len + plen < sizeof pe->buf);
      memcpy(pe->buf + pe->len, f + hdr, plen);
      pe->len += plen;
      pe->buf[pe->len] = '\0';
    }

    memmove(pe->raw, pe->raw + hdr + plen, pe->rawlen - hdr - plen);
    pe->rawlen -= hdr + plen;
  }
}

/** Read whatever has arrived */
static void
peer_read(struct peer *pe)
{
  for (;;) {
    char *b = is_ws(pe->proto) ? pe->raw + pe->rawlen : pe->buf + pe->len;
    size_t room = is_ws(pe->proto)
      ? sizeof pe->raw - pe->rawlen - 1 : sizeof pe->buf - pe->len - 1;
    ssize_t n;

    if (pe->eof || room == 0)
      return;

    if (pe->ssl) {
      n = SSL_read(pe->ssl, b, (int)room);
      if (n <= 0) {
	int e = SSL_get_error(pe->ssl, (int)n);
	if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
	  return;
	pe->eof = 1;
	return;
      }
    }
    else {
      n = recv(pe->fd, b, room, 0);
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
	return;
      if (n <= 0) {
	pe->eof = 1;
	return;
      }
    }

    if (is_ws(pe->proto)) {
      pe->rawlen += n;
      ws_decode(pe);
    }
    else {
      pe->len += n;
      pe->buf[pe->len] = '\0';
    }
  }
}

/** Wait until the peer has received text (NULL: until connection closes) */
static int
peer_wait(struct peer *pe, char const *text, int ms)
{
  long long until = now_ms() + ms;

  for (;;) {
    peer_read(pe);
    if (text ? strstr(pe->buf, text) != NULL : pe->eof)
      return 1;
    if (pe->eof || now_ms() >= until)
      return 0;
    step();
  }
}

/** Open a TCP connection to port, TLS handshake if ssl_ctx */
static int
peer_open(struct peer *pe, int proto, char const *port, SSL_CTX *ssl_ctx)
{
  struct sockaddr_in sin[1];
  long long until = now_ms() + 3000;

  memset(pe, 0, offsetof(struct peer, raw));
  pe->proto = proto;

  pe->fd = socket(AF_INET, SOCK_STREAM, 0);
  fail_unless(pe->fd >= 0);
  nonblocking(pe->fd);

  memset(sin, 0, sizeof sin);
  sin->sin_family = AF_INET;
  sin->sin_port = htons(atoi(port));
  sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect(pe->fd, (struct sockaddr *)sin, sizeof sin) < 0 &&
      errno != EINPROGRESS)
    return -1;

  for (;;) {
    struct pollfd pfd = { pe->fd, POLLOUT, 0 };
    if (poll(&pfd, 1, 0) == 1)
      break;
    if (now_ms() >= until)
      return -1;
    step();
  }

  if (ssl_ctx) {
    pe->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(pe->ssl, pe->fd);
    SSL_set_tlsext_host_name(pe->ssl, "localhost");

    for (;;) {
      int r = SSL_connect(pe->ssl), e;
      if (r == 1)
	break;
      e = SSL_get_error(pe->ssl, r);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
	return -1;
      if (now_ms() >= until)
	return -1;
      step();
    }
  }

  return 0;
}

/** Connect as a SIP client over proto: TCP, TLS, WebSocket upgrade */
static int
peer_connect(struct peer *pe, int proto)
{
  static char const upgrade[] =
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: sip\r\n"
    "\r\n";

  if (peer_open(pe, proto, ports[proto],
		is_secure(proto) ? client_ctx(0) : NULL) < 0)
    return -1;

  if (is_ws(proto)) {
    /* The handshake response is not framed */
    pe->proto = TCP;
    if (peer_write(pe, upgrade, strlen(upgrade)) < 0 ||
	!peer_wait(pe, "\r\n\r\n", 3000))
      return -1;
    if (strncmp(pe->buf, "HTTP/1.1 101", 12))
      return -1;
    pe->proto = proto;
    pe->len = 0, pe->buf[0] = '\0';
  }

  return 0;
}

static void
peer_close(struct peer *pe)
{
  if (pe->ssl)
    SSL_free(pe->ssl), pe->ssl = NULL;
  if (pe->fd >= 0)
    close(pe->fd), pe->fd = -1;
}

/** Close with a TCP RST instead of FIN */
static void
peer_reset(struct peer *pe)
{
  struct linger l = { 1, 0 };
  setsockopt(pe->fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
  peer_close(pe);
}

/** Frame data as one masked WebSocket frame (as a client must) */
static size_t
ws_frame(char *out, int opcode, char const *data, size_t len)
{
  static unsigned char const mask[4] = { 0x37, 0xfa, 0x21, 0x3d };
  unsigned char *o = (unsigned char *)out;
  size_t n = 0, i;

  o[n++] = 0x80 | opcode;
  if (len < 126)
    o[n++] = 0x80 | len;
  else if (len < 65536)
    o[n++] = 0x80 | 126, o[n++] = len >> 8, o[n++] = len & 0xff;
  else {
    o[n++] = 0x80 | 127;
    for (i = 8; i > 0; i--)
      o[n++] = (len >> (8 * (i - 1))) & 0xff;
  }
  memcpy(o + n, mask, 4), n += 4;
  for (i = 0; i < len; i++)
    o[n + i] = data[i] ^ mask[i % 4];

  return n + len;
}

/** Send SIP text, framed for WebSocket; byte by byte if trickle */
static int
peer_send(struct peer *pe, char const *text, size_t len, int trickle)
{
  static char framed[300 * 1024];
  char const *b = text;
  size_t i;

  if (is_ws(pe->proto)) {
    fail_unless(len + 14 < sizeof framed);
    len = ws_frame(framed, 0x1, text, len);
    b = framed;
  }

  if (!trickle)
    return peer_write(pe, b, len);

  for (i = 0; i < len; i++) {
    if (peer_write(pe, b + i, 1) < 0)
      return -1;
    pump(2);
  }

  return 0;
}

/** A SIP request with body bytes of payload */
static char *
request(int proto, char const *callid, size_t body)
{
  static char text[256 * 1024];
  int n;

  n = snprintf(text, sizeof text,
	       "OPTIONS sip:drachtio@127.0.0.1 SIP/2.0\r\n"
	       "Via: SIP/2.0/%s 127.0.0.1:5060;branch=z9hG4bK.%s\r\n"
	       "Max-Forwards: 70\r\n"
	       "From: <sip:peer@example.org>;tag=1\r\n"
	       "To: <sip:drachtio@127.0.0.1>\r\n"
	       "Call-ID: %s\r\n"
	       "CSeq: 1 OPTIONS\r\n"
	       "Content-Type: text/plain\r\n"
	       "Content-Length: %zu\r\n"
	       "\r\n", via_protos[proto], callid, callid, body);
  fail_unless(n > 0 && n + body < sizeof text);
  memset(text + n, 'x', body);
  text[n + body] = '\0';

  return text;
}

static int
callid_is(struct rx *r, char const *callid)
{
  sip_t const *sip = sip_object(r->msg);
  return sip && sip->sip_call_id && su_strmatch(sip->sip_call_id->i_id, callid);
}

/* ====================================================================== */
/* 1 - Messages over each stream transport */

START_TEST(tport_1_0)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  char callid[64];

  S2_CASE("tport-1.0", "Request and response",
	  "Over each of tcp, tls, ws, wss; the connection is freed "
	  "when the peer closes it");

  snprintf(callid, sizeof callid, "1.0-%s", protos[p]);

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, request(p, callid, 0), strlen(request(p, callid, 0)), 0));

  r = wait_rx(3000);
  ck_assert_msg(r != NULL, "nothing received over %s", protos[p]);
  fail_unless(callid_is(r, callid));
  fail_if(reply(r, "1.0-reply"));
  fail_unless(peer_wait(pe, "Call-ID: 1.0-reply", 3000));
  free_rx(r);

  peer_close(pe);
  ck_assert_msg(!(wait_no_secondaries(master, 3000)), "connection not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_1_1)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  char const *text;

  S2_CASE("tport-1.1", "Request trickled one byte at a time",
	  "A slow peer: tport reassembles the message and does not "
	  "block the thread while waiting for the rest");

  fail_if(peer_connect(pe, p));
  text = request(p, "1.1", 200);
  fail_if(peer_send(pe, text, strlen(text), 1));

  r = wait_rx(3000);
  ck_assert_msg(r != NULL, "nothing received over %s", protos[p]);
  fail_unless(callid_is(r, "1.1"));
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_1_2)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  char const *text;
  sip_t const *sip;

  S2_CASE("tport-1.2", "Large request",
	  "60 kB, as large INVITEs with many SDP lines get");

  fail_if(peer_connect(pe, p));
  text = request(p, "1.2", 60000);
  fail_if(peer_send(pe, text, strlen(text), 0));

  r = wait_rx(3000);
  ck_assert_msg(r != NULL, "nothing received over %s", protos[p]);
  sip = sip_object(r->msg);
  fail_unless(sip->sip_payload && sip->sip_payload->pl_len == 60000);
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_1_3)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  char const *text;
  char *two;
  size_t len, half;

  S2_CASE("tport-1.3", "Two requests, split anywhere",
	  "Pipelined requests arriving in two pieces, split in the "
	  "middle of the second one; both are delivered");

  fail_if(peer_connect(pe, p));

  text = request(p, "1.3-a", 100);
  len = strlen(text);
  two = malloc(2 * len + 1);
  memcpy(two, text, len);
  text = request(p, "1.3-b", 100);
  memcpy(two + len, text, len);
  two[2 * len] = '\0';

  if (is_ws(p)) {
    /* One message per frame; split the second frame */
    fail_if(peer_send(pe, two, len, 0));
    {
      static char framed[4096];
      size_t n = ws_frame(framed, 0x1, two + len, len);
      half = n / 2;
      fail_if(peer_write(pe, framed, half));
      pump(20);
      fail_if(peer_write(pe, framed + half, n - half));
    }
  }
  else {
    half = len + len / 2;
    fail_if(peer_write(pe, two, half));
    pump(20);
    fail_if(peer_write(pe, two + half, 2 * len - half));
  }
  free(two);

  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "1.3-a"));
  free_rx(r);
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "1.3-b"));
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_1_4)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  char const *text;

  S2_CASE("tport-1.4", "CRLF keepalive",
	  "A double-CRLF ping gets a CRLF pong (TPTAG_PONG2PING), "
	  "in a text frame over WebSocket; requests and responses "
	  "carry on normally after it");

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, "\r\n\r\n", 4, 0));
  ck_assert_msg(peer_wait(pe, "\r\n", 3000), "no pong over %s", protos[p]);
  fail_if(received != NULL);

  /* Ping split in two, then a request right behind a ping */
  pe->len = 0, pe->buf[0] = '\0';
  fail_if(peer_send(pe, "\r\n", 2, 0));
  pump(20);
  fail_if(peer_send(pe, "\r\n", 2, 0));
  if (!is_ws(p))		/* over WebSocket a ping is its own frame */
    ck_assert_msg(peer_wait(pe, "\r\n", 3000), "no pong to a split ping");

  text = request(p, "1.4", 0);
  if (!is_ws(p)) {
    static char both[4096];
    snprintf(both, sizeof both, "\r\n\r\n%s", text);
    fail_if(peer_write(pe, both, strlen(both)));
  }
  else
    fail_if(peer_send(pe, text, strlen(text), 0));

  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "1.4"));
  fail_if(reply(r, "1.4-reply"));
  fail_unless(peer_wait(pe, "Call-ID: 1.4-reply", 3000));
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_1_5)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  static char two[8192];
  char const *text;
  size_t n;

  S2_CASE("tport-1.5", "Two requests in one write",
	  "Both are delivered at once; over TLS and WSS they share a TLS "
	  "record, so the second is already decrypted and the socket "
	  "has nothing more to read");

  fail_if(peer_connect(pe, p));

  text = request(p, "1.5-a", 0);
  if (is_ws(p))
    n = ws_frame(two, 0x1, text, strlen(text));
  else
    n = strlen(text), memcpy(two, text, n);
  text = request(p, "1.5-b", 0);
  if (is_ws(p))
    n += ws_frame(two + n, 0x1, text, strlen(text));
  else
    memcpy(two + n, text, strlen(text)), n += strlen(text);

  fail_if(peer_write(pe, two, n));

  r = wait_rx(1000);
  fail_unless(r && callid_is(r, "1.5-a"));
  free_rx(r);
  r = wait_rx(1000);
  ck_assert_msg(r && callid_is(r, "1.5-b"), "second request stuck over %s",
	      protos[p]);
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_1_6)
{
  struct peer pe[1];
  struct rx *r;
  int i, small = 1024;

  S2_CASE("tport-1.6", "Pongs to a peer that is not reading (TLS)",
	  "Pings keep coming while the connection is full, so a pong "
	  "cannot be written at once; it is finished before the next "
	  "message and the stream stays intact");

  fail_if(peer_open(pe, TLS, ports[TLS], client_ctx(0)));
  setsockopt(pe->fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
  fail_if(peer_write(pe, request(TLS, "1.6-a", 0),
		     strlen(request(TLS, "1.6-a", 0))));
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "1.6-a"));
  setsockopt(r->tport->tp_socket, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);

  for (i = 0; i < 3000; i++) {
    if (peer_write(pe, "\r\n\r\n", 4) < 0)
      break;
    step();
  }

  /* The response goes out behind whatever pong is pending */
  reply(r, "1.6-reply");
  free_rx(r);
  ck_assert_msg(peer_wait(pe, "Call-ID: 1.6-reply", 5000),
		"response lost behind pongs");

  /* And the connection still works */
  pe->len = 0, pe->buf[0] = '\0';
  fail_if(peer_write(pe, request(TLS, "1.6-b", 0),
		     strlen(request(TLS, "1.6-b", 0))));
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "1.6-b"));
  fail_if(reply(r, "1.6-reply-b"));
  fail_unless(peer_wait(pe, "Call-ID: 1.6-reply-b", 3000));
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

TCase *check_tport_1(void)
{
  TCase *tc = tcase_create("1 - Stream transports");

  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_set_timeout(tc, 30);

  tcase_add_loop_test(tc, tport_1_0, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_1_1, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_1_2, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_1_3, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_1_4, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_1_5, 0, NPROTOS);
  tcase_add_test(tc, tport_1_6);

  return tc;
}

/* ====================================================================== */
/* 2 - Connection teardown */

START_TEST(tport_2_0)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;
  int i;

  S2_CASE("tport-2.0", "Peer resets the connection before the response",
	  "Sending on the dead connection reports an error; no SIGPIPE, "
	  "no crash, and the connection is freed");

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, request(p, "2.0", 0), strlen(request(p, "2.0", 0)), 0));
  r = wait_rx(3000);
  fail_unless(r != NULL);

  peer_reset(pe);

  /* The first write may succeed; later ones hit the reset connection */
  for (i = 0; i < 3; i++) {
    reply(r, "2.0-reply");
    pump(20);
  }
  free_rx(r);

  ck_assert_msg(!(wait_no_secondaries(master, 3000)), "connection not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_2_1)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;

  S2_CASE("tport-2.1", "Peer closes, stack still holds the transport",
	  "drachtio keeps a reference to the transport of a dialog; the "
	  "closed connection stays until it is released, then goes");

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, request(p, "2.1", 0), strlen(request(p, "2.1", 0)), 0));
  r = wait_rx(3000);
  fail_unless(r != NULL);

  peer_close(pe);
  pump(200);

  fail_unless(tport_is_closed(r->tport) || tport_is_shutdown(r->tport));
  fail_unless(secondaries(master) == 1);
  reply(r, "2.1-reply");	/* fails, must not crash */

  free_rx(r);
  ck_assert_msg(!(wait_no_secondaries(master, 3000)), "connection not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_2_2)
{
  int p = _i;
  struct peer pe[1];
  struct rx *r;

  S2_CASE("tport-2.2", "Stack shuts the connection down",
	  "As drachtio does with tport_shutdown(tp, 2): the peer sees "
	  "the connection close, and the thread is not held while it "
	  "closes");

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, request(p, "2.2", 0), strlen(request(p, "2.2", 0)), 0));
  r = wait_rx(3000);
  fail_unless(r != NULL);

  /* The peer does not answer close_notify or the WebSocket close */
  {
    long long t0 = now_ms(), dt;
    tport_shutdown(r->tport, 2);
    dt = now_ms() - t0;
    ck_assert_msg(dt <= STALL_MS, "tport_shutdown() took %lld ms", dt);
  }

  ck_assert_msg(peer_wait(pe, NULL, 3000) || pe->ws_closed,
	      "peer did not see the connection close");
  free_rx(r);
  peer_close(pe);

  ck_assert_msg(!(wait_no_secondaries(master, 3000)), "connection not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_2_3)
{
  int p = _i, i;
  struct peer *pe = calloc(20, sizeof *pe);
  struct rx *r;

  S2_CASE("tport-2.3", "Many short connections",
	  "Each sends a request and goes away; none is left behind");

  for (i = 0; i < 20; i++) {
    fail_if(peer_connect(&pe[i], p));
    fail_if(peer_send(&pe[i], request(p, "2.3", 0),
		      strlen(request(p, "2.3", 0)), 0));
  }
  for (i = 0; i < 20; i++) {
    r = wait_rx(3000);
    fail_unless(r != NULL);
    free_rx(r);
  }
  for (i = 0; i < 20; i++) {
    if (i % 2)
      peer_reset(&pe[i]);
    else
      peer_close(&pe[i]);
  }

  free(pe);
  ck_assert_msg(!(wait_no_secondaries(master, 5000)), "connections not freed");
  NO_STALL();
}
END_TEST

TCase *check_tport_2(void)
{
  TCase *tc = tcase_create("2 - Connection teardown");

  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_set_timeout(tc, 30);

  tcase_add_loop_test(tc, tport_2_0, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_2_1, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_2_2, 0, NPROTOS);
  tcase_add_loop_test(tc, tport_2_3, 0, NPROTOS);

  return tc;
}

/* ====================================================================== */
/* 3 - Hostile and broken peers */

static int const secure_protos[] = { TLS, WSS };
static int const ws_protos[] = { WS, WSS };

START_TEST(tport_3_0)
{
  int p = secure_protos[_i];
  struct peer pe[1];
  char const *text = request(TCP, "3.0", 0);

  S2_CASE("tport-3.0", "Plain text to a TLS port",
	  "The connection is closed; nothing is delivered");

  fail_if(peer_open(pe, p, ports[p], NULL));
  fail_if(peer_write(pe, text, strlen(text)));

  ck_assert_msg(peer_wait(pe, NULL, 7000), "connection not closed");
  fail_if(received != NULL);
  peer_close(pe);

  ck_assert_msg(!(wait_no_secondaries(master, 3000)), "connection not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_3_1)
{
  int p = secure_protos[_i];
  struct peer stalled[1], pe[1];
  struct rx *r;

  S2_CASE("tport-3.1", "Stalled TLS handshake",
	  "A peer connects and never sends a ClientHello; other peers "
	  "are still served");

  fail_if(peer_open(stalled, p, ports[p], NULL));
  pump(100);

  fail_if(peer_connect(pe, p));
  fail_if(peer_send(pe, request(p, "3.1", 0), strlen(request(p, "3.1", 0)), 0));
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "3.1"));
  free_rx(r);

  peer_close(pe);
  peer_close(stalled);
  ck_assert_msg(!(wait_no_secondaries(master, 7000)), "connections not freed");
  NO_STALL();
}
END_TEST

START_TEST(tport_3_2)
{
  int p = ws_protos[_i];
  struct peer pe[1], other[1];
  struct rx *r;
  char frame[16];
  size_t n;

  S2_CASE("tport-3.2", "Partial WebSocket frame header",
	  "A peer sends the first byte of a frame and stops; the "
	  "thread is not blocked and other peers are still served");

  fail_if(peer_connect(pe, p));
  n = ws_frame(frame, 0x1, "\r\n", 2);
  fail_unless(n > 1);
  fail_if(peer_write(pe, frame, 1));
  pump(100);

  fail_if(peer_connect(other, p));
  fail_if(peer_send(other, request(p, "3.2", 0),
		    strlen(request(p, "3.2", 0)), 0));
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "3.2"));
  free_rx(r);

  peer_close(other);
  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

START_TEST(tport_3_3)
{
  int p = ws_protos[_i];
  struct peer pe[1];
  struct rx *r;
  char const *text = request(p, "3.3", 100);
  size_t len = strlen(text), half = len / 2;
  static char framed[2][1024];
  unsigned char *f;
  size_t n0, n1;

  S2_CASE("tport-3.3", "Fragmented WebSocket message",
	  "A message in two frames (FIN clear on the first) that "
	  "arrive separately is delivered whole");

  fail_if(peer_connect(pe, p));

  n0 = ws_frame(framed[0], 0x1, text, half);
  f = (unsigned char *)framed[0];
  f[0] &= 0x7f;			/* not the final fragment */
  n1 = ws_frame(framed[1], 0x0, text + half, len - half);	/* continuation */

  fail_if(peer_write(pe, framed[0], n0));
  pump(50);
  fail_if(peer_write(pe, framed[1], n1));

  r = wait_rx(3000);
  ck_assert_msg(r && callid_is(r, "3.3"), "fragmented message lost");
  fail_unless(sip_object(r->msg)->sip_payload &&
	      sip_object(r->msg)->sip_payload->pl_len == 100);
  free_rx(r);

  peer_close(pe);
  fail_if(wait_no_secondaries(master, 3000));
  NO_STALL();
}
END_TEST

TCase *check_tport_3(void)
{
  TCase *tc = tcase_create("3 - Hostile and broken peers");

  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_set_timeout(tc, 60);

  tcase_add_loop_test(tc, tport_3_0, 0, 2);
  tcase_add_loop_test(tc, tport_3_1, 0, 2);
  tcase_add_loop_test(tc, tport_3_2, 0, 2);
  tcase_add_loop_test(tc, tport_3_3, 0, 2);

  return tc;
}

/* ====================================================================== */
/* 4 - Mutual TLS */

START_TEST(tport_4_0)
{
  tport_t *mr;
  char const *port;
  struct peer pe[1];
  struct rx *r;
  char const *text = request(TLS, "4.0", 0);

  S2_CASE("tport-4.0", "Server requires a client certificate",
	  "TPTLS_VERIFY_IN: a client without a certificate is refused, "
	  "one with a certificate from the trusted CA is served");

  mr = tport_tcreate((tp_stack_t *)stack_class, stack_class,
		     s2base->root, TAG_END());
  fail_unless(mr != NULL);
  port = bind_server(mr, TLS,
		     TPTAG_TLS_VERIFY_POLICY(TPTLS_VERIFY_IN),
		     TPTAG_TLS_CERTIFICATE_CHAIN_FILE(cert("ca.pem")),
		     TAG_END());

  /* Without a certificate: the handshake fails or the server hangs up */
  if (peer_open(pe, TLS, port, client_ctx(0)) == 0) {
    peer_write(pe, text, strlen(text));
    peer_wait(pe, NULL, 3000);
  }
  ck_assert_msg(!(received != NULL), "request from an unverified client delivered");
  peer_close(pe);

  /* With one */
  fail_if(peer_open(pe, TLS, port, client_ctx(1)));
  fail_if(peer_write(pe, text, strlen(text)));
  r = wait_rx(3000);
  fail_unless(r && callid_is(r, "4.0"));
  free_rx(r);
  peer_close(pe);

  wait_no_secondaries(mr, 3000);
  tport_destroy(mr);
  NO_STALL();
}
END_TEST

START_TEST(tport_4_1)
{
  tport_t *mr, *tp;
  int lfd, fd = -1, one = 1;
  struct sockaddr_in sin[1];
  socklen_t sinlen = sizeof sin;
  char port[16];
  SSL_CTX *ctx;
  SSL *ssl;
  X509 *peer_cert;
  char cn[256] = "";
  tp_name_t tpn[1] = {{ "tls", NULL, "127.0.0.1", NULL, NULL, NULL }};
  msg_t *msg;
  char const *text = request(TLS, "4.1", 0);
  char buf[4096];
  long long until;
  int done = 0, got = 0;

  S2_CASE("tport-4.1", "Outbound identity",
	  "With TPTAG_TLS_CLIENT_CERTIFICATE_FILE, tport presents the "
	  "client certificate, not the server's, on connections it opens");

  /* A TLS server that requires a client certificate */
  lfd = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset(sin, 0, sizeof sin);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  fail_if(bind(lfd, (struct sockaddr *)sin, sizeof sin));
  fail_if(listen(lfd, 5));
  getsockname(lfd, (struct sockaddr *)sin, &sinlen);
  snprintf(port, sizeof port, "%u", ntohs(sin->sin_port));
  nonblocking(lfd);

  ctx = SSL_CTX_new(TLS_server_method());
  fail_unless(SSL_CTX_use_certificate_file(ctx, cert("server.pem"),
					   SSL_FILETYPE_PEM) == 1);
  fail_unless(SSL_CTX_use_PrivateKey_file(ctx, cert("server.pem"),
					  SSL_FILETYPE_PEM) == 1);
  fail_unless(SSL_CTX_load_verify_locations(ctx, cert("ca.pem"), NULL) == 1);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		     NULL);

  /* tport with a listener identity and a distinct outbound identity */
  mr = tport_tcreate((tp_stack_t *)stack_class, stack_class,
		     s2base->root, TAG_END());
  fail_unless(mr != NULL);
  bind_server(mr, TLS,
	      TPTAG_TLS_CLIENT_CERTIFICATE_FILE(cert("client.pem")),
	      TPTAG_TLS_CLIENT_CERTIFICATE_KEY_FILE(cert("client.pem")),
	      TAG_END());

  tpn->tpn_port = port;
  msg = msg_make(sip_default_mclass(), 0, text, strlen(text));
  tp = tport_tsend(mr, msg, tpn, TAG_END());
  fail_unless(tp != NULL);
  msg_destroy(msg);

  until = now_ms() + 5000;
  while (fd < 0 && now_ms() < until) {
    fd = accept(lfd, NULL, NULL);
    if (fd < 0)
      step();
  }
  ck_assert_msg(fd >= 0, "tport did not connect");
  nonblocking(fd);

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  while (!done && now_ms() < until) {
    int r = SSL_accept(ssl), e;
    if (r == 1) {
      done = 1;
      break;
    }
    e = SSL_get_error(ssl, r);
    ck_assert_msg(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE,
		"TLS handshake with tport failed");
    step();
  }
  ck_assert_msg(done, "TLS handshake with tport timed out");

  peer_cert = SSL_get_peer_certificate(ssl);
  ck_assert_msg(peer_cert != NULL, "tport presented no client certificate");
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
			    NID_commonName, cn, sizeof cn);
  X509_free(peer_cert);
  ck_assert_str_eq(cn, "sofia-sip test client");

  while (!got && now_ms() < until) {
    int n = SSL_read(ssl, buf, sizeof buf - 1);
    if (n > 0) {
      buf[n] = '\0';
      got = strstr(buf, "Call-ID: 4.1") != NULL;
    }
    else
      step();
  }
  ck_assert_msg(got, "request not received over the outbound connection");

  SSL_free(ssl);
  close(fd);
  close(lfd);
  SSL_CTX_free(ctx);
  tport_destroy(mr);
  NO_STALL();
}
END_TEST

TCase *check_tport_4(void)
{
  TCase *tc = tcase_create("4 - Mutual TLS");

  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_set_timeout(tc, 30);

  tcase_add_test(tc, tport_4_0);
  tcase_add_test(tc, tport_4_1);

  return tc;
}

/* ====================================================================== */

static void usage(int exitcode)
{
  fprintf(exitcode ? stderr : stdout,
	  "usage: %s [--xml=logfile] case,...\n", s2_tester);
  exit(exitcode);
}

int main(int argc, char *argv[])
{
  int i, failed = 0, selected = 0;
  char const *xml = NULL;
  Suite *suite;
  SRunner *runner;

  s2_tester = "check_tport";
  s2_suite("TPORT");

  if (getenv("CHECK_TPORT_VERBOSE"))
    s2_start_stop = strtoul(getenv("CHECK_TPORT_VERBOSE"), NULL, 10);

  for (i = 1; argv[i]; i++) {
    if (su_strnmatch(argv[i], "--xml=", strlen("--xml=")))
      xml = argv[i] + strlen("--xml=");
    else if (su_strmatch(argv[i], "-v"))
      s2_start_stop = 1;
    else if (su_strmatch(argv[i], "-?") || su_strmatch(argv[i], "-h") ||
	     su_strmatch(argv[i], "--help"))
      usage(0);
    else
      s2_select_tests(argv[i]), selected = 1;
  }

  if (!selected)
    s2_select_tests(getenv("CHECK_TPORT_CASES"));

  suite = suite_create("Black-box tests for tport stream transports");

  suite_add_tcase(suite, check_tport_1());
  suite_add_tcase(suite, check_tport_2());
  suite_add_tcase(suite, check_tport_3());
  suite_add_tcase(suite, check_tport_4());

  runner = srunner_create(suite);

  if (xml)
    srunner_set_xml(runner, xml);

  srunner_run_all(runner, CK_ENV);
  failed = srunner_ntests_failed(runner);
  srunner_free(runner);

  exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
