/**@internal
 *
 * @CFILE torture_sres_domain.c Unit tests for DNS name decompression.
 *
 * Exercises the resolver's domain-name decoder (`m_get_domain()`) directly
 * with hand-built messages. The core file is included so the otherwise static
 * decoder can be called without going through the network receive path.
 */

#include "config.h"

#include "sres.c"

#include <sofia-sip/su_log.h>

#if HAVE_ALARM
#include <signal.h>
#endif

#define TSTFLAGS tstflags
int tstflags;

#include <sofia-sip/tstdef.h>

char const name[] = "torture_sres_domain";

extern su_log_t sresolv_log[];

/* Encode a 16-bit compression pointer to the given offset (two bytes). */
static void put_pointer(uint8_t *p, unsigned at, unsigned target)
{
  p[at]     = (uint8_t)(0xc0 | ((target >> 8) & 0x3f));
  p[at + 1] = (uint8_t)(target & 0xff);
}

/* A name whose compression pointers form a cycle must be rejected and the
   decode must terminate rather than loop. */
static int test_pointer_cycle(void)
{
  sres_message_t m[1];
  char buf[1026];
  unsigned len;

  BEGIN();

  /* Two pointers referencing each other: offset 12 -> 14 -> 12. */
  memset(m, 0, sizeof m);
  put_pointer(m->m_data, 12, 14);
  put_pointer(m->m_data, 14, 12);
  m->m_size = 64;
  len = m_get_domain(buf, sizeof buf, m, 12);
  TEST(len, 0);
  TEST_1(m->m_error != NULL);
  TEST_S(m->m_error, "invalid domain compression");

  /* A pointer that references its own offset: 12 -> 12. */
  memset(m, 0, sizeof m);
  put_pointer(m->m_data, 12, 12);
  m->m_size = 64;
  len = m_get_domain(buf, sizeof buf, m, 12);
  TEST(len, 0);
  TEST_1(m->m_error != NULL);
  TEST_S(m->m_error, "invalid domain compression");

  END();
}

/* A name that uses a backward compression pointer decodes to the full name. */
static int test_valid_compression(void)
{
  sres_message_t m[1];
  uint8_t *p;
  unsigned o, name2, len;
  char buf[1026];

  BEGIN();

  memset(m, 0, sizeof m);
  p = m->m_data;

  /* Base name "sip.example.com" at offset 12. */
  o = 12;
  p[o++] = 3; p[o++] = 's'; p[o++] = 'i'; p[o++] = 'p';
  p[o++] = 7; memcpy(p + o, "example", 7); o += 7;
  p[o++] = 3; p[o++] = 'c'; p[o++] = 'o'; p[o++] = 'm';
  p[o++] = 0;

  /* Second name "www" followed by a pointer back to the base name. */
  name2 = o;
  p[o++] = 3; p[o++] = 'w'; p[o++] = 'w'; p[o++] = 'w';
  put_pointer(p, o, 12); o += 2;

  m->m_size = 64;

  memset(buf, 0, sizeof buf);
  len = m_get_domain(buf, sizeof buf, m, (uint16_t)name2);
  TEST_1(m->m_error == NULL);
  TEST_S(buf, "www.sip.example.com.");
  TEST(len, 20);

  END();
}

#if HAVE_ALARM
static void sig_alarm(int s)
{
  fprintf(stderr, "%s: FAIL! test timeout!\n", name);
  exit(1);
}
#endif

int main(int argc, char **argv)
{
  int i;
  int error = 0;
  int o_alarm = 1;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-a") == 0)
      tstflags |= tst_abort;
    else if (strcmp(argv[i], "--no-alarm") == 0)
      o_alarm = 0;
  }

#if HAVE_ALARM
  if (o_alarm) {
    alarm(30);
    signal(SIGALRM, sig_alarm);
  }
#endif

  if (!(tstflags & tst_verbatim))
    su_log_soft_set_level(sresolv_log, 0);

  error |= test_pointer_cycle();
  error |= test_valid_compression();

  return error;
}
