/*
 * libFuzzer target: URI parsing, printing, comparison and parameter
 * lookup (url.c), as nta and drachtio use them on peer-supplied
 * Request-URIs, Contact, Route and Record-Route.
 *
 * The input is one URI, or two separated by a newline: the second one is
 * compared against the first (url_cmp/url_cmp_all, which includes the
 * tel: number comparison).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sofia-sip/su_alloc.h>
#include <sofia-sip/url.h>

/* Exactly-sized heap copy, so ASan sees any read past the NUL */
static char *xdup(const uint8_t *data, size_t size)
{
  char *s = malloc(size + 1);
  if (s) {
    memcpy(s, data, size);
    s[size] = 0;
  }
  return s;
}

static void exercise(su_home_t *home, url_t *url)
{
  char buf[512];
  url_t *u2;

  (void)url_e(buf, sizeof buf, url);
  (void)url_as_string(home, url);

  u2 = url_hdup(home, url);
  if (!u2)
    return;

  (void)url_cmp(url, u2);
  (void)url_cmp_all(url, u2);
  (void)url_has_param(u2, "lr");
  (void)url_has_param(u2, "transport");
  (void)url_param(u2->url_params, "maddr", buf, sizeof buf);
  (void)url_param(u2->url_params, "lr", NULL, 0);
  if (u2->url_params)
    (void)url_strip_transport(u2);
  if (u2->url_headers)
    (void)url_query_as_header_string(home, u2->url_headers);
  (void)url_sanitize(u2);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  const uint8_t *nl = memchr(data, '\n', size);
  size_t n1 = nl ? (size_t)(nl - data) : size;
  char *s1, *s2 = NULL, *s;
  url_t a[1], b[1];
  int ra = -1, rb = -1;

  /* url_d() parses in place, leaving pointers into the copy */
  s1 = xdup(data, n1);
  if (s1 && (ra = url_d(a, s1)) >= 0)
    exercise(home, a);

  if (nl) {
    s2 = xdup(nl + 1, size - n1 - 1);
    if (s2 && (rb = url_d(b, s2)) >= 0)
      exercise(home, b);
    if (ra >= 0 && rb >= 0) {
      (void)url_cmp(a, b);
      (void)url_cmp_all(a, b);
    }
  }

  /* url_make() (heap copy) and url_unescape() on the raw input */
  s = xdup(data, size);
  if (s) {
    url_t *u = url_make(home, s);
    if (u)
      (void)url_as_string(home, u);
    (void)url_unescape(s, s);
  }

  free(s), free(s2), free(s1);
  su_home_deinit(home);
  return 0;
}
