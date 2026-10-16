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

/**@CFILE check_nta_drachtio.c
 *
 * @brief Scenario tests for nta as drachtio-server drives it.
 *
 * drachtio-server uses nta differently from nua:
 *
 * - the agent is not a UA (NTATAG_UA(0), the default), so nta neither
 *   retransmits 2xx responses to INVITE nor absorbs the ACK to them;
 * - every new request goes to the stateless agent callback first, and
 *   the server transaction is created later with nta_incoming_create()
 *   and NTATAG_TPORT;
 * - 2xx to INVITE is retransmitted by the application with
 *   incoming_retransmit_reply();
 * - the ACK to a 2xx is a separate client transaction the application
 *   builds, re-sent with outgoing_retransmit() when the 2xx is
 *   retransmitted (nta delivers 2xx retransmissions to the terminated
 *   INVITE transaction);
 * - proxying is stateless, with nta_msg_tsend().
 *
 * Each test plays one SIP exchange against the s2sip peer the way
 * drachtio-server does it, and checks what goes on the wire.
 */

#include "config.h"

#include "check_nta.h"
#include "s2base.h"
#include "s2dns.h"

#include <sofia-sip/nta.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/nta_stateless.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-resolv/sres_record.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* s2_nta_wait_for() takes pointer-sized values */
#define W_STATUS(s) wait_for_status, (void *)(intptr_t)(s)
#define W_METHOD(m) wait_for_method, (void *)(intptr_t)(m)

/* The peer's side of the call (s2sip) */
static struct dialog *peer;

/* Legs created by a test, destroyed in teardown */
static nta_leg_t *legs[4];

/* The primary transport the latest stateless request came in on */
static tport_t *delivered_by;

/**
 * The stateless callback. Like drachtio's, it finds the transport the
 * message came in on while nta still knows it, i.e. within the callback.
 */
static int
drachtio_msg_callback(nta_agent_magic_t *magic,
		      nta_agent_t *nta,
		      msg_t *msg,
		      sip_t *sip)
{
  if (sip->sip_request) {
    tport_t *tp = nta_incoming_transport(nta, NULL, msg);
    fail_unless(tp != NULL);
    delivered_by = tport_parent(tp);
    tport_unref(tp);
  }

  return s2_nta_msg_callback(magic, nta, msg, sip);
}

static void
drachtio_setup(void)
{
  sip_contact_t const *m;
  char *url;

  s2_nta_setup("NTA", NULL, TAG_END());
  /* As drachtio-server's DrachtioController::run() creates the agent */
  s2_nta_agent_setup(URL_STRING_MAKE("sip:0.0.0.0:*;transport=udp,tcp"),
		     drachtio_msg_callback, NULL,
		     NTATAG_SERVER_RPORT(2),
		     NTATAG_CLIENT_RPORT(1),
		     NTATAG_PASS_408(1),
		     TPTAG_PONG2PING(1),
		     TAG_END());

  /* Requests from the peer go to the agent over UDP, at the peer's own
     address (s2sip sends its responses there, too) */
  m = nta_agent_contact(s2->nta);
  fail_unless(m != NULL && m->m_url->url_port != NULL);
  fail_unless(s2sip->udp.contact != NULL);
  url = su_sprintf(s2sip->home, "sip:%s:%s",
		   s2sip->udp.contact->m_url->url_host, m->m_url->url_port);
  s2sip->sut.contact = sip_contact_make(s2sip->home, url);
  s2sip->sut.aor = sip_to_make(s2sip->home, "<sip:drachtio@example.net>");
  fail_unless(s2sip->sut.contact && s2sip->sut.aor);

  peer = su_home_new(sizeof *peer);
  fail_unless(peer != NULL);
  delivered_by = NULL;
}

static void
drachtio_teardown(void)
{
  size_t i;

  mark_point();

  for (i = 0; i < (sizeof legs) / (sizeof legs[0]); i++)
    if (legs[i])
      nta_leg_destroy(legs[i]), legs[i] = NULL;

  if (peer) {
    msg_destroy(peer->invite);
    tport_unref(peer->tport);
    su_home_unref(peer->home);
    peer = NULL;
  }

  s2_nta_teardown();
}

/* ---------------------------------------------------------------------- */
/* Helpers */

/** Run the event loop for a while; nothing may happen on either side. */
static void
quiet(void)
{
  int i;

  for (i = 0; i < 20; i++)
    su_root_step(s2->root, 5);

  ck_assert_msg(s2->events == NULL, "unexpected nta callback");
  ck_assert_msg(s2sip->received == NULL, "peer received an unexpected message");
}

/** Wait for the stateless callback to get a request. */
static struct event *
wait_for_stateless(sip_method_t method)
{
  struct event *e = s2_nta_wait_for(wait_for_leg, NULL,
				    wait_for_irq, NULL,
				    wait_for_orq, NULL,
				    W_METHOD(method),
				    0);
  fail_unless(e != NULL && e->msg != NULL && e->leg == NULL);
  return e;
}

/**
 * Create the server transaction for a request the stateless callback got,
 * as DrachtioController::setupLegForIncomingRequest() does: late, outside
 * any nta callback, on the primary transport the request came in on.
 *
 * The transaction takes the event's reference to the message.
 */
static nta_incoming_t *
late_irq(struct event *e)
{
  msg_t *msg = e->msg;
  nta_incoming_t *irq;

  fail_unless(delivered_by != NULL);

  e->msg = NULL;
  irq = nta_incoming_create(s2->nta, NULL, msg, sip_object(msg),
			    NTATAG_TPORT(delivered_by),
			    TAG_END());
  fail_unless(irq != NULL);

  return irq;
}

/** The peer sends its latest INVITE again (a UDP retransmission). */
static void
peer_retransmit_invite(void)
{
  tp_name_t tpn[1];
  url_t const *u = s2sip->sut.contact->m_url;
  msg_t *copy;

  fail_unless(peer->invite != NULL && peer->tport != NULL);

  *tpn = *tport_name(peer->tport);
  tpn->tpn_host = u->url_host;
  tpn->tpn_port = url_port(u);

  copy = msg_copy(peer->invite);
  fail_unless(tport_tsend(peer->tport, copy, tpn, TAG_END()) != NULL);
  msg_destroy(copy);
}

/** A UAC leg, as SipDialogController::doSendRequestOutsideDialog() makes */
static nta_leg_t *
uac_leg(int i)
{
  nta_leg_t *leg;

  leg = nta_leg_tcreate(s2->nta, s2_nta_leg_callback, NULL,
			SIPTAG_FROM_STR("<sip:drachtio@example.net>"),
			SIPTAG_TO_STR("<sip:peer@example.org>"),
			TAG_END());
  fail_unless(leg != NULL);
  nta_leg_tag(leg, NULL);

  return legs[i] = leg;
}

/** The peer's UDP address, as a request target */
static url_string_t const *
peer_url(void)
{
  fail_unless(s2sip->udp.contact != NULL);
  return (url_string_t const *)s2sip->udp.contact->m_url;
}

static int prack_count;

static int
prack_callback(nta_reliable_magic_t *magic,
	       nta_reliable_t *rel,
	       nta_incoming_t *prack,
	       sip_t const *sip)
{
  prack_count++;
  return 200;
}

/* ====================================================================== */
/* 3.0 - UAS: server transactions created late, from the stateless callback */

START_TEST(drachtio_3_0_0)
{
  struct event *e, *e2;
  struct message *m;
  nta_incoming_t *irq;
  msg_t *msg;

  S2_CASE("drachtio-3.0.0", "Late server transaction",
	  "INVITE handled statelessly, then by a server transaction "
	  "created later; app-driven 2xx retransmission; "
	  "ACK goes to the stateless callback");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));

  e = wait_for_stateless(sip_method_invite);
  msg = e->msg;

  /* Stateless 100 Trying, as drachtio sends it while asking the app */
  fail_if(nta_msg_treply(s2->nta, msg_ref_create(msg), SIP_100_TRYING,
			 TAG_END()));
  m = s2_sip_wait_for_response(100, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  /* There is no transaction yet: a retransmission goes to the callback */
  peer_retransmit_invite();
  e2 = wait_for_stateless(sip_method_invite);
  s2_nta_free_event(e2);

  irq = late_irq(e);
  s2_nta_free_event(e);

  fail_if(nta_incoming_treply(irq, SIP_180_RINGING, TAG_END()));
  m = s2_sip_wait_for_response(180, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  /* Now the transaction absorbs retransmissions and resends 180 */
  peer_retransmit_invite();
  m = s2_sip_wait_for_response(180, SIP_METHOD_INVITE);
  s2_sip_free_message(m);
  quiet();

  fail_if(nta_incoming_treply(irq, SIP_200_OK,
			      SIPTAG_CONTACT(s2sip->sut.contact),
			      TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  s2_sip_update_dialog(peer, m);
  s2_sip_free_message(m);

  /* nta is not a UA: it does not retransmit the 2xx by itself */
  s2_fast_forward(1, s2->root);
  quiet();

  /* drachtio's timer G does it, through the terminated transaction */
  incoming_retransmit_reply(irq, NULL);
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  /* The ACK is not absorbed by the INVITE transaction */
  fail_if(s2_sip_request_to(peer, SIP_METHOD_ACK, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_ack);
  s2_nta_free_event(e);

  nta_incoming_destroy(irq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_1)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq, *bye;
  sip_t const *sip;
  nta_leg_t *leg;

  S2_CASE("drachtio-3.0.1", "Late server transaction with a UAS leg",
	  "ACK and BYE are matched to a leg created after the "
	  "server transaction");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  sip = e->sip;

  irq = late_irq(e);

  /* As setupLegForIncomingRequest() and addIncomingInviteTransaction() */
  leg = nta_leg_tcreate(s2->nta, s2_nta_leg_callback, NULL,
			SIPTAG_CALL_ID(sip->sip_call_id),
			SIPTAG_CSEQ(sip->sip_cseq),
			SIPTAG_TO(sip->sip_from),
			SIPTAG_FROM(sip->sip_to),
			TAG_END());
  fail_unless(leg != NULL);
  legs[0] = leg;
  nta_leg_server_route(leg, sip->sip_record_route, sip->sip_contact);
  fail_unless(nta_leg_tag(leg, nta_incoming_tag(irq, NULL)) != NULL);
  s2_nta_free_event(e);

  fail_if(nta_incoming_treply(irq, SIP_200_OK,
			      SIPTAG_CONTACT(s2sip->sut.contact),
			      TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  s2_sip_update_dialog(peer, m);
  s2_sip_free_message(m);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_ACK, NULL, TAG_END()));
  e = s2_nta_wait_for(wait_for_leg, leg,
		      W_METHOD(sip_method_ack),
		      0);
  s2_nta_free_event(e);
  nta_incoming_destroy(irq);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_BYE, NULL, TAG_END()));
  e = s2_nta_wait_for(wait_for_leg, leg,
		      W_METHOD(sip_method_bye),
		      0);
  bye = e->irq;
  fail_if(nta_incoming_treply(bye, SIP_200_OK, TAG_END()));
  nta_incoming_destroy(bye);
  s2_nta_free_event(e);

  m = s2_sip_wait_for_response(200, SIP_METHOD_BYE);
  s2_sip_free_message(m);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_2)
{
  struct event *invite, *cancel;
  struct message *m;

  S2_CASE("drachtio-3.0.2", "CANCEL before the server transaction exists",
	  "Stateless 200 to CANCEL and stateless 487 to a copy of "
	  "the INVITE; the ACK goes to the stateless callback");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));
  invite = wait_for_stateless(sip_method_invite);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_CANCEL, NULL, TAG_END()));
  cancel = wait_for_stateless(sip_method_cancel);

  /* As DrachtioController::processMessageStatelessly() */
  fail_if(nta_msg_treply(s2->nta, cancel->msg, SIP_200_OK, TAG_END()));
  cancel->msg = NULL;
  fail_if(nta_msg_treply(s2->nta, msg_dup(invite->msg),
			 SIP_487_REQUEST_CANCELLED, TAG_END()));

  m = s2_sip_wait_for_response(200, SIP_METHOD_CANCEL);
  s2_sip_free_message(m);
  m = s2_sip_wait_for_response(487, SIP_METHOD_INVITE);
  s2_sip_update_dialog(peer, m);	/* sends ACK */
  s2_sip_free_message(m);

  s2_nta_free_event(wait_for_stateless(sip_method_ack));

  s2_nta_free_event(cancel);
  s2_nta_free_event(invite);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_3)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq;

  S2_CASE("drachtio-3.0.3", "CANCEL to a server transaction",
	  "nta answers the CANCEL, calls the bound callback "
	  "and sends 487; the ACK to 487 is absorbed");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  irq = late_irq(e);
  s2_nta_free_event(e);

  nta_incoming_bind(irq, s2_nta_irq_callback, NULL);

  fail_if(nta_incoming_treply(irq, SIP_180_RINGING, TAG_END()));
  m = s2_sip_wait_for_response(180, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_CANCEL, NULL, TAG_END()));

  e = s2_nta_wait_for(wait_for_irq, irq,
		      W_METHOD(sip_method_cancel),
		      0);
  s2_nta_free_event(e);

  m = s2_sip_wait_for_response(200, SIP_METHOD_CANCEL);
  s2_sip_free_message(m);
  m = s2_sip_wait_for_response(487, SIP_METHOD_INVITE);
  s2_sip_update_dialog(peer, m);	/* sends ACK */
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_irq, irq,
		      W_METHOD(sip_method_ack),
		      0);
  s2_nta_free_event(e);

  nta_incoming_destroy(irq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_4)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq;

  S2_CASE("drachtio-3.0.4", "CANCEL after 200",
	  "nta answers a CANCEL that arrives after the 2xx with 481");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  irq = late_irq(e);
  s2_nta_free_event(e);
  nta_incoming_bind(irq, s2_nta_irq_callback, NULL);

  fail_if(nta_incoming_treply(irq, SIP_200_OK,
			      SIPTAG_CONTACT(s2sip->sut.contact),
			      TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_CANCEL, NULL, TAG_END()));
  m = s2_sip_wait_for_response(481, SIP_METHOD_CANCEL);
  s2_sip_free_message(m);
  quiet();

  nta_incoming_destroy(irq);
}
END_TEST

START_TEST(drachtio_3_0_5)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq;
  int i;

  S2_CASE("drachtio-3.0.5", "Error response is never ACKed",
	  "nta retransmits 486 over UDP until timer H, "
	  "then calls the bound callback without a message");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  irq = late_irq(e);
  s2_nta_free_event(e);
  nta_incoming_bind(irq, s2_nta_irq_callback, NULL);

  fail_if(nta_incoming_treply(irq, SIP_486_BUSY_HERE, TAG_END()));
  m = s2_sip_wait_for_response(486, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  /* Timer G: retransmissions at T1, 2*T1, ... capped at T2 */
  s2_fast_forward(1, s2->root);
  m = s2_sip_wait_for_response(486, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  /* Timer H = 64*T1 */
  for (i = 0; i < 40; i++)
    s2_fast_forward(1, s2->root);

  e = s2_nta_wait_for(wait_for_irq, irq, 0);
  fail_unless(e->msg == NULL);
  s2_nta_free_event(e);

  s2_sip_flush_messages();
  nta_incoming_destroy(irq);
}
END_TEST

START_TEST(drachtio_3_0_6)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq;
  nta_reliable_t *rel;
  char rack[64];

  S2_CASE("drachtio-3.0.6", "Reliable provisional response",
	  "183 sent with 100rel; PRACK reaches the reliable callback "
	  "on a non-UA agent");

  prack_count = 0;

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, NULL,
			    SIPTAG_SUPPORTED_STR("100rel"),
			    TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  irq = late_irq(e);
  s2_nta_free_event(e);

  rel = nta_reliable_treply(irq, prack_callback, NULL,
			    SIP_183_SESSION_PROGRESS,
			    SIPTAG_CONTACT(s2sip->sut.contact),
			    TAG_END());
  fail_unless(rel != NULL);

  m = s2_sip_wait_for_response(183, SIP_METHOD_INVITE);
  fail_unless(m->sip->sip_rseq != NULL);
  fail_unless(sip_has_feature(m->sip->sip_require, "100rel"));
  snprintf(rack, sizeof rack, "%lu %lu INVITE",
	   (unsigned long)m->sip->sip_rseq->rs_response,
	   (unsigned long)m->sip->sip_cseq->cs_seq);
  s2_sip_update_dialog(peer, m);
  s2_sip_free_message(m);

  fail_if(s2_sip_request_to(peer, SIP_METHOD_PRACK, NULL,
			    SIPTAG_RACK_STR(rack),
			    TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_PRACK);
  s2_sip_free_message(m);
  /* nta answered the PRACK with the status the callback returned */
  fail_unless(prack_count == 1);

  fail_if(nta_incoming_treply(irq, SIP_200_OK,
			      SIPTAG_CONTACT(s2sip->sut.contact),
			      TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  s2_sip_free_message(m);

  nta_incoming_destroy(irq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_7)
{
  struct event *e;
  struct message *m;
  nta_incoming_t *irq;

  S2_CASE("drachtio-3.0.7", "Late server transaction over TCP",
	  "drachtio passes the primary transport, not the connection, "
	  "to nta_incoming_create(); the response must still go back "
	  "on the connection the request came in on");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, s2sip->tcp.tport,
			    TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  fail_unless(tport_is_primary(delivered_by) && tport_is_tcp(delivered_by));
  irq = late_irq(e);
  s2_nta_free_event(e);

  fail_if(nta_incoming_treply(irq, SIP_200_OK,
			      SIPTAG_CONTACT(s2sip->sut.contact),
			      TAG_END()));
  m = s2_sip_wait_for_response(200, SIP_METHOD_INVITE);
  fail_unless(m->tport == peer->tport);
  s2_sip_free_message(m);

  nta_incoming_destroy(irq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_0_8)
{
  struct event *e;
  nta_incoming_t *irq;
  int i;

  S2_CASE("drachtio-3.0.8", "TCP connection closed before the answer",
	  "The peer closes the connection while the application is "
	  "still deciding; answering and destroying the transaction "
	  "afterwards must be safe");

  fail_if(s2_sip_request_to(peer, SIP_METHOD_INVITE, s2sip->tcp.tport,
			    TAG_END()));
  e = wait_for_stateless(sip_method_invite);
  irq = late_irq(e);
  s2_nta_free_event(e);

  tport_shutdown(peer->tport, 2);
  for (i = 0; i < 20; i++)
    su_root_step(s2->root, 5);

  nta_incoming_treply(irq, SIP_180_RINGING, TAG_END());
  nta_incoming_treply(irq, SIP_200_OK,
		      SIPTAG_CONTACT(s2sip->sut.contact),
		      TAG_END());
  for (i = 0; i < 20; i++)
    su_root_step(s2->root, 5);
  nta_incoming_destroy(irq);

  /* Timers run to the end on a transaction with a dead connection */
  for (i = 0; i < 40; i++)
    s2_fast_forward(1, s2->root);

  s2_sip_flush_messages();
  s2_nta_flush_events();
}
END_TEST

TCase *check_nta_drachtio_3_0(void)
{
  TCase *tc = tcase_create("NTA 3.0 - drachtio UAS");

  tcase_add_checked_fixture(tc, drachtio_setup, drachtio_teardown);
  tcase_set_timeout(tc, 10);

  tcase_add_test(tc, drachtio_3_0_0);
  tcase_add_test(tc, drachtio_3_0_1);
  tcase_add_test(tc, drachtio_3_0_2);
  tcase_add_test(tc, drachtio_3_0_3);
  tcase_add_test(tc, drachtio_3_0_4);
  tcase_add_test(tc, drachtio_3_0_5);
  tcase_add_test(tc, drachtio_3_0_6);
  tcase_add_test(tc, drachtio_3_0_7);
  tcase_add_test(tc, drachtio_3_0_8);

  return tc;
}

/* ====================================================================== */
/* 3.1 - UAC */

/** Send an INVITE from a new UAC leg and receive it at the peer */
static nta_outgoing_t *
uac_invite(nta_leg_t *leg, struct message **request)
{
  nta_outgoing_t *orq;

  orq = nta_outgoing_tcreate(leg, s2_nta_orq_callback, NULL, NULL,
			     SIP_METHOD_INVITE, peer_url(),
			     SIPTAG_CONTACT(s2sip->sut.contact),
			     TAG_END());
  fail_unless(orq != NULL);

  if (request) {
    *request = s2_sip_wait_for_request(SIP_METHOD_INVITE);
    fail_unless(*request != NULL);
  }

  return orq;
}

/** The ACK to a 2xx, as SipDialogController builds it */
static nta_outgoing_t *
uac_ack(nta_leg_t *leg, nta_outgoing_t *invite)
{
  char cseq[32];

  snprintf(cseq, sizeof cseq, "%lu ACK",
	   (unsigned long)nta_outgoing_cseq(invite));

  return nta_outgoing_tcreate(leg, NULL, NULL, NULL,
			      SIP_METHOD_ACK, peer_url(),
			      SIPTAG_CSEQ_STR(cseq),
			      TAG_END());
}

START_TEST(drachtio_3_1_0)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq, *ack;
  struct message *invite, *m;
  struct event *e;
  char const *branch;

  S2_CASE("drachtio-3.1.0", "App-built ACK, re-sent on 2xx retransmission",
	  "A retransmitted 2xx reaches the INVITE transaction again; "
	  "outgoing_retransmit() re-sends the same ACK");

  orq = uac_invite(leg, &invite);

  s2_sip_respond_to(invite, peer, SIP_200_OK,
		    SIPTAG_CONTACT(s2sip->contact), TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(200), 0);
  nta_leg_rtag(leg, e->sip->sip_to->a_tag);
  s2_nta_free_event(e);

  ack = uac_ack(leg, orq);
  fail_unless(ack != NULL);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  branch = su_strdup(peer->home, m->sip->sip_via->v_branch);
  s2_sip_free_message(m);

  /* The peer did not get the ACK and retransmits the 200 */
  s2_sip_respond_to(invite, peer, SIP_200_OK,
		    SIPTAG_CONTACT(s2sip->contact), TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(200), 0);
  s2_nta_free_event(e);

  /* As TimerDHandler::resendIfNeeded() */
  outgoing_retransmit(ack);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  fail_unless(su_strmatch(branch, m->sip->sip_via->v_branch));
  s2_sip_free_message(m);

  s2_sip_free_message(invite);
  nta_outgoing_destroy(ack);
  nta_outgoing_destroy(orq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_1_1)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq, *cancel;
  struct message *invite, *m;
  struct event *e;

  S2_CASE("drachtio-3.1.1", "CANCEL before any provisional response",
	  "The CANCEL is held until 100 Trying arrives; the 487 is "
	  "ACKed by nta");

  orq = uac_invite(leg, &invite);

  cancel = nta_outgoing_tcancel(orq, s2_nta_orq_callback, NULL, TAG_END());
  fail_unless(cancel != NULL);
  quiet();			/* not sent yet */

  s2_sip_respond_to(invite, peer, SIP_100_TRYING, TAG_END());
  m = s2_sip_wait_for_request(SIP_METHOD_CANCEL);
  s2_sip_respond_to(m, NULL, SIP_200_OK, TAG_END());
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_orq, cancel, W_STATUS(200), 0);
  s2_nta_free_event(e);

  s2_sip_respond_to(invite, peer, SIP_487_REQUEST_CANCELLED, TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(487), 0);
  s2_nta_free_event(e);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  s2_sip_free_message(m);

  s2_sip_free_message(invite);
  nta_outgoing_destroy(cancel);
  nta_outgoing_destroy(orq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_1_2)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq, *cancel;
  struct message *invite, *m;
  struct event *e;

  S2_CASE("drachtio-3.1.2", "CANCEL held, first provisional is 180",
	  "The held CANCEL goes out on 180; the 180 still reaches "
	  "the application");

  orq = uac_invite(leg, &invite);

  cancel = nta_outgoing_tcancel(orq, s2_nta_orq_callback, NULL, TAG_END());
  fail_unless(cancel != NULL);

  s2_sip_respond_to(invite, peer, SIP_180_RINGING, TAG_END());
  m = s2_sip_wait_for_request(SIP_METHOD_CANCEL);
  s2_sip_respond_to(m, NULL, SIP_200_OK, TAG_END());
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(180), 0);
  s2_nta_free_event(e);
  e = s2_nta_wait_for(wait_for_orq, cancel, W_STATUS(200), 0);
  s2_nta_free_event(e);

  s2_sip_respond_to(invite, peer, SIP_487_REQUEST_CANCELLED, TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(487), 0);
  s2_nta_free_event(e);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  s2_sip_free_message(m);

  s2_sip_free_message(invite);
  nta_outgoing_destroy(cancel);
  nta_outgoing_destroy(orq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_1_3)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq, *cancel, *ack;
  struct message *invite, *m;
  struct event *e;

  S2_CASE("drachtio-3.1.3", "CANCEL crosses 200",
	  "The 2xx still reaches the application, which ACKs it");

  orq = uac_invite(leg, &invite);
  s2_sip_respond_to(invite, peer, SIP_180_RINGING, TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(180), 0);
  s2_nta_free_event(e);

  cancel = nta_outgoing_tcancel(orq, s2_nta_orq_callback, NULL, TAG_END());
  fail_unless(cancel != NULL);
  m = s2_sip_wait_for_request(SIP_METHOD_CANCEL);

  /* The peer answered before it saw the CANCEL */
  s2_sip_respond_to(invite, peer, SIP_200_OK,
		    SIPTAG_CONTACT(s2sip->contact), TAG_END());
  s2_sip_respond_to(m, NULL, SIP_481_NO_TRANSACTION, TAG_END());
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(200), 0);
  nta_leg_rtag(leg, e->sip->sip_to->a_tag);
  s2_nta_free_event(e);
  e = s2_nta_wait_for(wait_for_orq, cancel, W_STATUS(481), 0);
  s2_nta_free_event(e);

  ack = uac_ack(leg, orq);
  fail_unless(ack != NULL);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  s2_sip_free_message(m);

  s2_sip_free_message(invite);
  nta_outgoing_destroy(ack);
  nta_outgoing_destroy(cancel);
  nta_outgoing_destroy(orq);
  quiet();
}
END_TEST

START_TEST(drachtio_3_1_4)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq;
  struct event *e;
  int i;

  S2_CASE("drachtio-3.1.4", "INVITE timeout",
	  "No answer: the application gets an internal 408 (timer B)");

  orq = uac_invite(leg, NULL);

  for (i = 0; i < 40; i++)
    s2_fast_forward(1, s2->root);

  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(408), 0);
  fail_unless(e->sip != NULL);
  fail_unless(nta_sip_is_internal(e->sip));
  s2_nta_free_event(e);

  s2_sip_flush_messages();
  nta_outgoing_destroy(orq);
}
END_TEST

START_TEST(drachtio_3_1_5)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq;
  struct message *invite;
  struct event *e;

  S2_CASE("drachtio-3.1.5", "INVITE transaction destroyed early",
	  "A 2xx arriving after the application destroyed the INVITE "
	  "transaction goes to the stateless callback");

  orq = uac_invite(leg, &invite);
  s2_sip_respond_to(invite, peer, SIP_180_RINGING, TAG_END());
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(180), 0);
  s2_nta_free_event(e);

  nta_outgoing_destroy(orq);

  s2_sip_respond_to(invite, peer, SIP_200_OK,
		    SIPTAG_CONTACT(s2sip->contact), TAG_END());
  e = s2_nta_wait_for(wait_for_orq, NULL, W_STATUS(200), 0);
  fail_unless(e->orq == NULL);
  s2_nta_free_event(e);

  s2_sip_free_message(invite);
  quiet();
}
END_TEST

START_TEST(drachtio_3_1_6)
{
  nta_leg_t *leg;
  nta_outgoing_t *orq;
  struct message *m;
  struct event *e;

  S2_CASE("drachtio-3.1.6", "REGISTER with Contact: *",
	  "Removing all bindings; nta must not touch the wildcard "
	  "Contact when it fixes up the Contact for the transport");

  leg = nta_leg_tcreate(s2->nta, s2_nta_leg_callback, NULL,
			SIPTAG_FROM_STR("<sip:drachtio@example.net>"),
			SIPTAG_TO_STR("<sip:drachtio@example.net>"),
			NTATAG_NO_DIALOG(1),
			TAG_END());
  fail_unless(leg != NULL);
  legs[0] = leg;

  orq = nta_outgoing_tcreate(leg, s2_nta_orq_callback, NULL, NULL,
			     SIP_METHOD_REGISTER, peer_url(),
			     SIPTAG_CONTACT_STR("*"),
			     SIPTAG_EXPIRES_STR("0"),
			     TAG_END());
  fail_unless(orq != NULL);

  m = s2_sip_wait_for_request(SIP_METHOD_REGISTER);
  fail_unless(m->sip->sip_contact != NULL);
  fail_unless(m->sip->sip_contact->m_url->url_type == url_any);
  s2_sip_respond_to(m, NULL, SIP_200_OK, TAG_END());
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(200), 0);
  s2_nta_free_event(e);
  nta_outgoing_destroy(orq);
}
END_TEST

START_TEST(drachtio_3_1_7)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq;
  struct message *m;
  struct event *e;
  char contact[512];
  char const *uri_params =
    ";pn-provider=apns.voip"
    ";pn-prid=00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0"
    ":voip.00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0"
    ";pn-param=ABCD1234.com.example.voip";
  char const *params =
    ";+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000a95a0e128>\"";

  S2_CASE("drachtio-3.1.7", "Long Contact rewritten for the transport",
	  "nta replaces the Contact host and port with the transport's; "
	  "a Contact longer than 255 bytes must survive intact");

  /* An address the agent does not have, so nta rewrites it */
  snprintf(contact, sizeof contact, "<sip:drachtio@10.255.255.1:5999%s>%s",
	   uri_params, params);
  fail_unless(strlen(contact) > 255);

  orq = nta_outgoing_tcreate(leg, s2_nta_orq_callback, NULL, NULL,
			     SIP_METHOD_INVITE, peer_url(),
			     SIPTAG_CONTACT_STR(contact),
			     TAG_END());
  fail_unless(orq != NULL);

  m = s2_sip_wait_for_request(SIP_METHOD_INVITE);
  fail_unless(m->sip->sip_contact != NULL);
  fail_if(su_strmatch(m->sip->sip_contact->m_url->url_host, "10.255.255.1"));
  fail_if(su_strmatch(m->sip->sip_contact->m_url->url_port, "5999"));
  fail_unless(url_has_param(m->sip->sip_contact->m_url, "pn-param"));
  fail_unless(m->sip->sip_contact->m_params != NULL);
  fail_unless(su_strmatch(m->sip->sip_contact->m_params[0],
			  "+sip.instance=\"<urn:uuid:00000000-0000-1000-"
			  "8000-000a95a0e128>\""));

  s2_sip_respond_to(m, peer, SIP_486_BUSY_HERE, TAG_END());
  s2_sip_free_message(m);
  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(486), 0);
  s2_nta_free_event(e);
  m = s2_sip_wait_for_request(SIP_METHOD_ACK);
  s2_sip_free_message(m);
  nta_outgoing_destroy(orq);
}
END_TEST

START_TEST(drachtio_3_1_8)
{
  nta_leg_t *leg = uac_leg(0);
  nta_outgoing_t *orq;
  struct message *m;
  struct event *e;
  char const *host = s2sip->udp.contact->m_url->url_host;
  unsigned port = strtoul(url_port(s2sip->udp.contact->m_url), NULL, 10);
  char const *branch;

  S2_CASE("drachtio-3.1.8", "SRV failover on 503",
	  "The first SRV target answers 503; nta retries the request "
	  "at the next one");

  s2_dns_record("_sip._udp.failover.example.org.", sres_type_srv,
		"", sres_type_srv, 1, 0, port, "a.failover.example.org.",
		"", sres_type_srv, 2, 0, port, "b.failover.example.org.",
		NULL);
  s2_dns_record("a.failover.example.org.", sres_type_a,
		"", sres_type_a, host,
		NULL);
  s2_dns_record("b.failover.example.org.", sres_type_a,
		"", sres_type_a, host,
		NULL);

  orq = nta_outgoing_tcreate(leg, s2_nta_orq_callback, NULL, NULL,
			     SIP_METHOD_OPTIONS,
			     URL_STRING_MAKE("sip:failover.example.org"
					     ";transport=udp"),
			     TAG_END());
  fail_unless(orq != NULL);

  m = s2_sip_wait_for_request(SIP_METHOD_OPTIONS);
  branch = su_strdup(peer->home, m->sip->sip_via->v_branch);
  s2_sip_respond_to(m, NULL, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
  s2_sip_free_message(m);

  m = s2_sip_wait_for_request(SIP_METHOD_OPTIONS);
  fail_if(su_strmatch(branch, m->sip->sip_via->v_branch));
  s2_sip_respond_to(m, NULL, SIP_200_OK, TAG_END());
  s2_sip_free_message(m);

  e = s2_nta_wait_for(wait_for_orq, orq, W_STATUS(200), 0);
  s2_nta_free_event(e);
  nta_outgoing_destroy(orq);
  quiet();
}
END_TEST

TCase *check_nta_drachtio_3_1(void)
{
  TCase *tc = tcase_create("NTA 3.1 - drachtio UAC");

  tcase_add_checked_fixture(tc, drachtio_setup, drachtio_teardown);
  tcase_set_timeout(tc, 10);

  tcase_add_test(tc, drachtio_3_1_0);
  tcase_add_test(tc, drachtio_3_1_1);
  tcase_add_test(tc, drachtio_3_1_2);
  tcase_add_test(tc, drachtio_3_1_3);
  tcase_add_test(tc, drachtio_3_1_4);
  tcase_add_test(tc, drachtio_3_1_5);
  tcase_add_test(tc, drachtio_3_1_6);
  tcase_add_test(tc, drachtio_3_1_7);
  tcase_add_test(tc, drachtio_3_1_8);

  return tc;
}

/* ====================================================================== */
/* 3.2 - Stateless proxy */

START_TEST(drachtio_3_2_0)
{
  struct event *e;
  struct message *m;
  msg_t *msg;
  sip_t *sip;

  S2_CASE("drachtio-3.2.0", "Stateless proxy",
	  "Request forwarded with nta_msg_tsend(); the response comes "
	  "back to the stateless callback and is forwarded upstream");

  /* The peer is both the caller and the callee */
  fail_if(s2_sip_request_to(peer, SIP_METHOD_OPTIONS, NULL, TAG_END()));
  e = wait_for_stateless(sip_method_options);
  msg = e->msg, e->msg = NULL;
  s2_nta_free_event(e);

  fail_if(nta_msg_tsend(s2->nta, msg, peer_url(),
			NTATAG_BRANCH_KEY("z9hG4bK.drachtio.3.2.0"),
			TAG_END()));

  m = s2_sip_wait_for_request(SIP_METHOD_OPTIONS);
  fail_unless(m->sip->sip_via && m->sip->sip_via->v_next);
  s2_sip_respond_to(m, NULL, SIP_200_OK, TAG_END());
  s2_sip_free_message(m);

  /* No client transaction: the response goes to the stateless callback */
  e = s2_nta_wait_for(wait_for_orq, NULL, W_STATUS(200), 0);
  msg = e->msg, e->msg = NULL;
  sip = sip_object(msg);
  fail_unless(sip->sip_via && sip->sip_via->v_next);
  s2_nta_free_event(e);

  /* nta strips our Via and sends the response to the next one */
  fail_if(nta_msg_tsend(s2->nta, msg, NULL, TAG_END()));

  m = s2_sip_wait_for_response(200, SIP_METHOD_OPTIONS);
  fail_unless(m->sip->sip_via && !m->sip->sip_via->v_next);
  s2_sip_free_message(m);
  quiet();
}
END_TEST

TCase *check_nta_drachtio_3_2(void)
{
  TCase *tc = tcase_create("NTA 3.2 - drachtio proxy");

  tcase_add_checked_fixture(tc, drachtio_setup, drachtio_teardown);
  tcase_set_timeout(tc, 10);

  tcase_add_test(tc, drachtio_3_2_0);

  return tc;
}
