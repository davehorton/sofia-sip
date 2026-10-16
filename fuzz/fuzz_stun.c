/*
 * libFuzzer target: the STUN server built into tport (stun_mini.c).
 *
 * tport enables it by default (TPTAG_STUN_SERVER), so any UDP datagram
 * to a SIP port that starts with 0x00 is handed to stun_mini_request():
 * that is the input here. Responses are sent to a loopback UDP socket
 * owned by the harness, which drains them.
 */
#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <sofia-sip/stun.h>

static stun_mini_t *mini;
static int s = -1;
static struct sockaddr_in self;

static void setup(void)
{
  socklen_t len = sizeof self;

  mini = stun_mini_create();
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (!mini || s < 0)
    abort();

  memset(&self, 0, sizeof self);
  self.sin_family = AF_INET;
  self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&self, sizeof self) < 0 ||
      getsockname(s, (struct sockaddr *)&self, &len) < 0)
    abort();
  fcntl(s, F_SETFL, O_NONBLOCK);

  if (stun_mini_add_socket(mini, s) < 0)
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  uint8_t *msg, sink[2048];

  if (!mini)
    setup();

  /* Exactly-sized heap copy, so ASan sees any read past the datagram */
  msg = malloc(size ? size : 1);
  if (!msg)
    return 0;
  memcpy(msg, data, size);

  stun_mini_request(mini, s, msg, (ssize_t)size,
		    &self, (socklen_t)sizeof self);
  free(msg);

  while (recv(s, sink, sizeof sink, 0) > 0)
    ;				/* drop our own responses */

  return 0;
}
