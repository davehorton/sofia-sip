/*
 * libFuzzer target: WebSocket handshake and frame parsing (tport/ws.c),
 * as tport_type_ws.c drives it for every WS/WSS connection.
 *
 * Byte 0, bit 0 selects what is fuzzed:
 *   0: the whole input is what the peer sends, starting with the HTTP
 *      upgrade request (ws_handshake)
 *   1: a valid upgrade request is sent first, then the input as frames
 *      (ws_read_frame: lengths, masking, fragmentation, control frames)
 *
 * The bytes are written to one end of a socketpair, which is then shut
 * down for writing, so ws.c reads them through its normal recv() path and
 * then sees end of stream.
 */
#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>

#include "ws.h"

static char const upgrade[] =
  "GET /sip HTTP/1.1\r\n"
  "Host: example.com\r\n"
  "Upgrade: websocket\r\n"
  "Connection: Upgrade\r\n"
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
  "Sec-WebSocket-Version: 13\r\n"
  "Sec-WebSocket-Protocol: sip\r\n"
  "\r\n";

static int write_all(int fd, const void *p, size_t n)
{
  const char *c = p;
  while (n) {
    ssize_t w = write(fd, c, n);
    if (w <= 0)
      return -1;
    c += w, n -= (size_t)w;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int initialized;
  int sv[2];
  int bufsize = 1024 * 1024;
  wsh_t wsh[1];
  int i;

  if (!initialized) {
    signal(SIGPIPE, SIG_IGN);	/* ws_close() writes to the socket */
    initialized = 1;
  }

  if (size < 1 || size > 256 * 1024)
    return 0;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return 0;
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof bufsize);
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof bufsize);

  memset(wsh, 0, sizeof wsh);

  if (data[0] & 1) {
    /* Complete a valid handshake first, as a client waits for the 101
     * before sending frames (ws_handshake() consumes all it can read). */
    if (write_all(sv[1], upgrade, sizeof upgrade - 1) < 0)
      goto out;
    if (ws_init(wsh, sv[0], NULL, 0, 0, 0) != 0)
      abort();			/* the fixed handshake must succeed */
    if (write_all(sv[1], data + 1, size - 1) < 0)
      goto destroy;
    shutdown(sv[1], SHUT_WR);
  }
  else {
    if (write_all(sv[1], data + 1, size - 1) < 0)
      goto out;
    shutdown(sv[1], SHUT_WR);
    if (ws_init(wsh, sv[0], NULL, 0, 0, 0) != 0)
      goto destroy;
  }

  {
    for (i = 0; i < 64; i++) {
      ws_opcode_t oc;
      uint8_t *frame = NULL;
      ssize_t r = ws_read_frame(wsh, &oc, &frame);
      if (r <= 0)
	break;
    }
  }
 destroy:
  ws_destroy(wsh);

 out:
  close(sv[0]);
  close(sv[1]);
  return 0;
}
