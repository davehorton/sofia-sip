/*
 * libFuzzer target: DNS response decoding (sres.c), as the resolver does
 * it for every answer it receives.
 *
 * Byte 0 picks the query type; the rest is the DNS response. Its ID is
 * overwritten with that of a pending query so that sres_decode_msg()
 * accepts it and decodes the question, answer, authority and additional
 * sections (all record types, name compression, error and CNAME paths).
 *
 * sres.c is included so the static decoder can be reached, as
 * torture_sres_domain.c does.
 */
#include "config.h"
#include "sres.c"

#include <stdint.h>
#include <stddef.h>

static sres_resolver_t *res;
static unsigned runs;

static uint16_t const qtypes[] = {
  sres_type_a, sres_type_aaaa, sres_type_srv, sres_type_naptr,
  sres_type_cname, sres_type_ptr, sres_type_soa, sres_type_a6,
  sres_qtype_any,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  sres_message_t m[1];
  sres_query_t *query, *matched = NULL;
  sres_record_t **reply = NULL;
  uint16_t qtype;
  size_t n;

  if (size < 1)
    return 0;

  /* Recreate the resolver now and then, so that decoded records do not
   * accumulate in its cache across runs */
  if (res && ++runs % 256 == 0)
    sres_resolver_unref(res), res = NULL;
  if (!res) {
    su_log_set_level(sresolv_log, 0);
    res = sres_resolver_new("/dev/null");
    if (!res)
      abort();
  }

  qtype = qtypes[data[0] % (sizeof qtypes / sizeof qtypes[0])];
  data++, size--;

  query = sres_query_alloc(res, NULL, NULL, qtype, "example.com");
  if (!query)
    return 0;

  memset(m, 0, sizeof *m);
  n = size < sizeof m->m_data ? size : sizeof m->m_data;
  memcpy(m->m_data, data, n);
  m->m_size = (uint16_t)n;
  if (n >= sizeof m->m_id)
    m->m_id = query->q_id;	/* match the pending query */

  (void)sres_decode_msg(res, m, &matched, &reply);

  if (reply)
    sres_free_answers(res, reply);
  sres_free_query(res, query);

  return 0;
}
