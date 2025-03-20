/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2008,2010,2014
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart, James
 * Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 *
 * Dec 2014 garmitage@swin.edu.au
 * Borrowed code fragments from cc_cdg.c to add modifiable beta
 * via sysctls.
 *
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/vnet.h>

#include <net/route.h>
#include <net/route/nhop.h>

#include <netinet/in_pcb.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_log_buf.h>
#include <netinet/tcp_hpts.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_module.h>
#include <netinet/cc/cc_newreno.h>

#include <sys/syslog.h>

// #define SEARCH_LOG_ENABLED

static void	newreno_cb_destroy(struct cc_var *ccv);
static void	newreno_ack_received(struct cc_var *ccv, ccsignal_t type);
static void	newreno_after_idle(struct cc_var *ccv);
static void	newreno_cong_signal(struct cc_var *ccv, ccsignal_t type);
static int newreno_ctl_output(struct cc_var *ccv, struct sockopt *sopt, void *buf);
static void	newreno_newround(struct cc_var *ccv, uint32_t round_cnt);
static void	newreno_rttsample(struct cc_var *ccv, uint32_t usec_rtt, uint32_t rxtcnt, uint32_t fas);
static 	int	newreno_cb_init(struct cc_var *ccv, void *);
static size_t	newreno_data_sz(void);


VNET_DECLARE(uint32_t, newreno_beta);
#define V_newreno_beta VNET(newreno_beta)
VNET_DECLARE(uint32_t, newreno_beta_ecn);
#define V_newreno_beta_ecn VNET(newreno_beta_ecn)

struct cc_algo newreno_cc_algo = {
	.name = "newreno",
	.cb_destroy = newreno_cb_destroy,
	.ack_received = newreno_ack_received,
	.after_idle = newreno_after_idle,
	.cong_signal = newreno_cong_signal,
	.post_recovery = newreno_cc_post_recovery,
	.ctl_output = newreno_ctl_output,
	.newround = newreno_newround,
	.rttsample = newreno_rttsample,
	.cb_init = newreno_cb_init,
	.cc_data_sz = newreno_data_sz,
};

static void
newreno_log_hystart_event(struct cc_var *ccv, struct newreno *nreno, uint8_t mod, uint32_t flex1)
{
	/*
	 * Types of logs (mod value)
	 * 1 - rtt_thresh in flex1, checking to see if RTT is to great.
	 * 2 - rtt is too great, rtt_thresh in flex1.
	 * 3 - CSS is active incr in flex1
	 * 4 - A new round is beginning flex1 is round count
	 * 5 - A new RTT measurement flex1 is the new measurement.
	 * 6 - We enter CA ssthresh is also in flex1.
	 * 7 - Socket option to change hystart executed opt.val in flex1.
	 * 8 - Back out of CSS into SS, flex1 is the css_baseline_minrtt
	 * 9 - We enter CA, via an ECN mark.
	 * 10 - We enter CA, via a loss.
	 * 11 - We have slipped out of SS into CA via cwnd growth.
	 * 12 - After idle has re-enabled hystart++
	 */
	struct tcpcb *tp;

	
	log(LOG_INFO, "<%p> hs Event Logging [mod %hhu] [flex1 %u]\n", ccv, mod, flex1);

	if (hystart_bblogs == 0)
		return;
	tp = ccv->tp;
	if (tcp_bblogging_on(tp)) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = flex1;
		log.u_bbr.flex2 = nreno->css_current_round_minrtt;
		log.u_bbr.flex3 = nreno->css_lastround_minrtt;
		log.u_bbr.flex4 = nreno->css_rttsample_count;
		log.u_bbr.flex5 = nreno->css_entered_at_round;
		log.u_bbr.flex6 = nreno->css_baseline_minrtt;
		/* We only need bottom 16 bits of flags */
		log.u_bbr.flex7 = nreno->newreno_flags & 0x0000ffff;
		log.u_bbr.flex8 = mod;
		log.u_bbr.epoch = nreno->css_current_round;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.lt_epoch = nreno->css_fas_at_css_entry;
		log.u_bbr.pkts_out = nreno->css_last_fas;
		log.u_bbr.delivered = nreno->css_lowrtt_fas;
		log.u_bbr.pkt_epoch = ccv->flags;
		TCP_LOG_EVENTP(tp, NULL,
		    &tptosocket(tp)->so_rcv,
		    &tptosocket(tp)->so_snd,
		    TCP_HYSTART, 0,
		    0, &log, false, &tv);
	}
}

static size_t
newreno_data_sz(void)
{
	return (sizeof(struct newreno));
}

static uint64_t get_now_us(void) {
	static struct timeval tv;
	microtime(&tv);
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

static int
newreno_cb_init(struct cc_var *ccv, void *ptr)
{
	uint64_t now_us = get_now_us();
	log(LOG_NOTICE, "<%p> [now %lu] Init CB\n", ccv, now_us);
	struct newreno *nreno;

	INP_WLOCK_ASSERT(tptoinpcb(ccv->tp));
	if (ptr == NULL) {
		ccv->cc_data = malloc(sizeof(struct newreno), M_CC_MEM, M_NOWAIT);
		if (ccv->cc_data == NULL)
			return (ENOMEM);
	} else
		ccv->cc_data = ptr;
	nreno = (struct newreno *)ccv->cc_data;
	/* NB: nreno is not zeroed, so initialise all fields. */
	nreno->beta = V_newreno_beta;
	nreno->beta_ecn = V_newreno_beta_ecn;
	/*
	 * We set the enabled flag so that if
	 * the socket option gets strobed and
	 * we have not hit a loss
	 */
	nreno->newreno_flags = CC_NEWRENO_HYSTART_ENABLED;
	/* At init set both to infinity */
	nreno->css_lastround_minrtt = 0xffffffff;
	nreno->css_current_round_minrtt = 0xffffffff;
	nreno->css_current_round = 0;
	nreno->css_baseline_minrtt = 0xffffffff;
	nreno->css_rttsample_count = 0;
	nreno->css_entered_at_round = 0;
	nreno->css_fas_at_css_entry = 0;
	nreno->css_lowrtt_fas = 0;
	nreno->css_last_fas = 0;
	return (0);
}

static void
newreno_cb_destroy(struct cc_var *ccv)
{
	free(ccv->cc_data, M_CC_MEM);
}

static uint64_t get_rtt_us(struct cc_var* ccv) {
	return ((uint64_t)CCV(ccv, t_srtt) * tick) >> TCP_RTT_SHIFT;
}

static void
newreno_ack_received(struct cc_var *ccv, ccsignal_t type)
{
	struct newreno *nreno;

	nreno = ccv->cc_data;
	
#ifdef SEARCH_LOG_ENABLED
	uint64_t rtt_us = get_rtt_us(ccv);
	log(LOG_INFO, "<%p> ACK: [now %lu] [srtt %lu] [curack %u] [cwnd %u] [ssthresh %u]\n", 
		ccv, 
		get_now_us(), 
		rtt_us,
		ccv->curack,
		CCV(ccv, snd_cwnd),
		CCV(ccv, snd_ssthresh)
	);
#endif

	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
	        log(LOG_INFO, "<%p> ACK; !recovery; cwnd_limited\n", ccv);
		u_int cw = CCV(ccv, snd_cwnd);
		u_int incr = CCV(ccv, t_maxseg);

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_l_var * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > CCV(ccv, snd_ssthresh)) {
		        log(LOG_INFO, "<%p> cwnd>ssthresh\n", ccv);
			if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
				/*
				 * We have slipped into CA with
				 * CSS active. Deactivate all.
				 */
				log(LOG_INFO, "<%p> [now %lu] Exiting hs CSS\n", ccv, get_now_us());
				/* Turn off the CSS flag */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
				/* Disable use of CSS in the future except long idle  */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
				newreno_log_hystart_event(ccv, nreno, 11, CCV(ccv, snd_ssthresh));
			}
			if (V_tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else {
				incr = max((incr * incr / cw), 1);
			}
			log(LOG_INFO, "<%p> CA incr %u\n", ccv, incr);
		} else if (V_tcp_do_rfc3465) {
		        log(LOG_INFO, "<%p> do rfc3465\n", ccv);
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_l_var > 1 if slow starting after
			 * an RTO. On RTO, snd_nxt = snd_una, so the
			 * snd_nxt == snd_max check is sufficient to
			 * handle this).
			 *
			 * XXXLAS: Find a way to signal SS after RTO that
			 * doesn't rely on tcpcb vars.
			 */
			uint16_t abc_val;

			if (ccv->flags & CCF_USE_LOCAL_ABC)
				abc_val = ccv->labc;
			else
				abc_val = V_tcp_abc_l_var;
			log(LOG_INFO, "<%p> Allowed? %u; Enabled? %u; !HyStartInCSS? %u\n", ccv, (ccv->flags & CCF_HYSTART_ALLOWED) != 0, (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) != 0, (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) == 0);
			if ((ccv->flags & CCF_HYSTART_ALLOWED) &&
			    (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) &&
			    ((nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) == 0)) {
			        log(LOG_INFO, "<%p> CCF HS OK; NR HS EN; !NR HS IN CSS\n", ccv);
				/*
				 * Hystart is allowed and still enabled and we are not yet
				 * in CSS. Lets check to see if we can make a decision on
				 * if we need to go into CSS.
				 */
				if ((nreno->css_rttsample_count >= hystart_n_rttsamples) &&
				    (nreno->css_current_round_minrtt != 0xffffffff) &&
				    (nreno->css_lastround_minrtt != 0xffffffff)) {
					uint32_t rtt_thresh;

					/* Clamp (minrtt_thresh, lastround/8, maxrtt_thresh) */
					rtt_thresh = (nreno->css_lastround_minrtt >> 3);
					if (rtt_thresh < hystart_minrtt_thresh)
						rtt_thresh = hystart_minrtt_thresh;
					if (rtt_thresh > hystart_maxrtt_thresh)
						rtt_thresh = hystart_maxrtt_thresh;
					newreno_log_hystart_event(ccv, nreno, 1, rtt_thresh);
					log(LOG_INFO, "<%p> Checking HS RTT rounds\n", ccv);
					if (nreno->css_current_round_minrtt >= (nreno->css_lastround_minrtt + rtt_thresh)) {
						/* Enter CSS */
						nreno->newreno_flags |= CC_NEWRENO_HYSTART_IN_CSS;
						nreno->css_fas_at_css_entry = nreno->css_lowrtt_fas;
						log(LOG_INFO, "<%p> [now %lu] hs Entering CSS\n", ccv, get_now_us());
						/*
						 * The draft (v4) calls for us to set baseline to css_current_round_min
						 * but that can cause an oscillation. We probably shoudl be using
						 * css_lastround_minrtt, but the authors insist that will cause
						 * issues on exiting early. We will leave the draft version for now
						 * but I suspect this is incorrect.
						 */
						nreno->css_baseline_minrtt = nreno->css_current_round_minrtt;
						nreno->css_entered_at_round = nreno->css_current_round;
						newreno_log_hystart_event(ccv, nreno, 2, rtt_thresh);
					}
				}
			}
			if (CCV(ccv, snd_nxt) == CCV(ccv, snd_max))
				incr = min(ccv->bytes_this_ack,
				    ccv->nsegs * abc_val *
				    CCV(ccv, t_maxseg));
			else
				incr = min(ccv->bytes_this_ack, CCV(ccv, t_maxseg));
			log(LOG_INFO, "<%p> SS incr %u\n", ccv, incr);

			/* Only if Hystart is enabled will the flag get set */
			if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
				incr /= hystart_css_growth_div;
				log(LOG_INFO, "<%p> [now %lu] [incr %u] hs growing cwnd\n", ccv, get_now_us(), incr);
				newreno_log_hystart_event(ccv, nreno, 3, incr);
			}
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0) {
			CCV(ccv, snd_cwnd) = min(cw + incr,
			    TCP_MAXWIN << CCV(ccv, snd_scale));
			log(LOG_INFO, "<%p>new cwnd %u\n", ccv, CCV(ccv, snd_cwnd));
		}
	}
	log(LOG_INFO, "<%p> ack_received done\n", ccv);
}

static void
newreno_after_idle(struct cc_var *ccv)
{
	uint64_t now_us = get_now_us();
	log(LOG_NOTICE, "<%p> [now %lu] After idle\n", ccv, now_us);
	struct newreno *nreno;

	nreno = ccv->cc_data;
	newreno_cc_after_idle(ccv);
	if ((nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) == 0) {
		/*
		 * Re-enable hystart if we have been idle.
		 */
		nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
		nreno->newreno_flags |= CC_NEWRENO_HYSTART_ENABLED;
		newreno_log_hystart_event(ccv, nreno, 12, CCV(ccv, snd_ssthresh));
		log(LOG_INFO, "<%p> [now %lu] Re-enabling hs after idle\n", ccv, now_us);
	}
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
newreno_cong_signal(struct cc_var *ccv, ccsignal_t type)
{
	struct newreno *nreno;
	uint32_t beta, beta_ecn, cwin, factor, mss, pipe;

	uint64_t now_us = get_now_us();

	cwin = CCV(ccv, snd_cwnd);
	mss = tcp_fixed_maxseg(ccv->tp);
	nreno = ccv->cc_data;
	beta = (nreno == NULL) ? V_newreno_beta : nreno->beta;;
	beta_ecn = (nreno == NULL) ? V_newreno_beta_ecn : nreno->beta_ecn;
	/*
	 * Note that we only change the backoff for ECN if the
	 * global sysctl V_cc_do_abe is set <or> the stack itself
	 * has set a flag in our newreno_flags (due to pacing) telling
	 * us to use the lower valued back-off.
	 */
	if ((type == CC_ECN) &&
	    (V_cc_do_abe ||
	    ((nreno != NULL) && (nreno->newreno_flags & CC_NEWRENO_BETA_ECN_ENABLED))))
		factor = beta_ecn;
	else
		factor = beta;

	/* Catch algos which mistakenly leak private signal types. */
	KASSERT((type & CC_SIGPRIVMASK) == 0,
	    ("%s: congestion signal type 0x%08x is private\n", __func__, type));

	cwin = max(((uint64_t)cwin * (uint64_t)factor) / (100ULL * (uint64_t)mss),
	    2) * mss;

	switch (type) {
	case CC_NDUPACK:
		if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) {
			log(LOG_INFO, "<%p> [now %lu] Disabling hs at loss\n", ccv, now_us);
			/* Make sure the flags are all off we had a loss */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			newreno_log_hystart_event(ccv, nreno, 10, CCV(ccv, snd_ssthresh));
		}
		if (!IN_FASTRECOVERY(CCV(ccv, t_flags))) {
			if (IN_CONGRECOVERY(CCV(ccv, t_flags) &&
			    V_cc_do_abe && V_cc_abe_frlossreduce)) {
				log(LOG_INFO, "<%p> [now %lu] NewReno Cong signal: dup ack in cong recovery. setting ssthresh\n", ccv, now_us);
				CCV(ccv, snd_ssthresh) =
				    ((uint64_t)CCV(ccv, snd_ssthresh) *
				     (uint64_t)beta) / (uint64_t)beta_ecn; // SET SSTHRESH
			}
			if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
				log(LOG_INFO, "<%p> [now %lu] NewReno Cong signal: dup ack not in cong recovery. setting ssthresh\n", ccv, now_us);
				CCV(ccv, snd_ssthresh) = cwin; // SET SSTHRESH
			}
			log(LOG_INFO, "<%p> [now %lu] Entering recovery, dup ack threshold reached\n", ccv, now_us);
			ENTER_RECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_ECN:
		if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) {
			/* Make sure the flags are all off we had a loss */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			newreno_log_hystart_event(ccv, nreno, 9, CCV(ccv, snd_ssthresh));
		}
		if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
			log(LOG_INFO, "NewReno Cong signal: ECN. setting ssthresh\n");
			CCV(ccv, snd_ssthresh) = cwin; // SET SSTHRESH
			log(LOG_INFO, "cwnd: cong sig ECN: setting to cwin");
			CCV(ccv, snd_cwnd) = cwin;
			log(LOG_INFO, "Entering recovery, ECN received\n");
			ENTER_CONGRECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_RTO:
		if (CCV(ccv, t_rxtshift) == 1) {
			if (V_tcp_do_newsack) {
				pipe = tcp_compute_pipe(ccv->tp);
			} else {
				pipe = CCV(ccv, snd_max) -
					CCV(ccv, snd_fack) +
					CCV(ccv, sackhint.sack_bytes_rexmit);
			}
			log(LOG_NOTICE, "<%p> [now %lu] NewReno Cong signal: RTO. setting ssthresh\n", ccv, now_us);
			CCV(ccv, snd_ssthresh) = max(2,
				((uint64_t)min(CCV(ccv, snd_wnd), pipe) *
				    (uint64_t)factor) /
				    (100ULL * (uint64_t)mss)) * mss; // SET SSTHRESH
		}
		log(LOG_NOTICE, "<%p> [now %lu] cwnd: cong sig RTO - setting to MSS", ccv, now_us);
		CCV(ccv, snd_cwnd) = mss;
		break;
	default:
		break;
	}
}

static int
newreno_ctl_output(struct cc_var *ccv, struct sockopt *sopt, void *buf)
{
	struct newreno *nreno;
	struct cc_newreno_opts *opt;

	if (sopt->sopt_valsize != sizeof(struct cc_newreno_opts))
		return (EMSGSIZE);

	if (CC_ALGO(ccv->tp) != &newreno_cc_algo)
		return (ENOPROTOOPT);

	nreno = (struct newreno *)ccv->cc_data;
	opt = buf;
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (opt->name) {
		case CC_NEWRENO_BETA:
			nreno->beta = opt->val;
			break;
		case CC_NEWRENO_BETA_ECN:
			nreno->beta_ecn = opt->val;
			nreno->newreno_flags |= CC_NEWRENO_BETA_ECN_ENABLED;
			break;
		default:
			return (ENOPROTOOPT);
		}
		break;
	case SOPT_GET:
		switch (opt->name) {
		case CC_NEWRENO_BETA:
			opt->val =  nreno->beta;
			break;
		case CC_NEWRENO_BETA_ECN:
			opt->val = nreno->beta_ecn;
			break;
		default:
			return (ENOPROTOOPT);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
newreno_beta_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	uint32_t new;

	new = *(uint32_t *)arg1;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr != NULL ) {
		if (arg1 == &VNET_NAME(newreno_beta_ecn) && !V_cc_do_abe)
			error = EACCES;
		else if (new == 0 || new > 100)
			error = EINVAL;
		else
			*(uint32_t *)arg1 = new;
	}

	return (error);
}

static void
newreno_newround(struct cc_var *ccv, uint32_t round_cnt)
{
	struct newreno *nreno;
	uint64_t now_us = get_now_us();

	nreno = (struct newreno *)ccv->cc_data;
	/* We have entered a new round */
	nreno->css_lastround_minrtt = nreno->css_current_round_minrtt;
	nreno->css_current_round_minrtt = 0xffffffff;
	nreno->css_rttsample_count = 0;
	nreno->css_current_round = round_cnt;
	if ((nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) &&
	    ((round_cnt - nreno->css_entered_at_round) >= hystart_css_rounds)) {
		/* Enter CA */
		if (ccv->flags & CCF_HYSTART_CAN_SH_CWND) {
			/*
			 * We engage more than snd_ssthresh, engage
			 * the brakes!! Though we will stay in SS to
			 * creep back up again, so lets leave CSS active
			 * and give us hystart_css_rounds more rounds.
			 */
			if (ccv->flags & CCF_HYSTART_CONS_SSTH) {
				log(LOG_NOTICE, "<%p> [now %lu] NewReno hs: SS->CSS (CA). Setting ssthresh (true)\n", ccv, now_us);
				CCV(ccv, snd_ssthresh) = ((nreno->css_lowrtt_fas + nreno->css_fas_at_css_entry) / 2); // SET SSTHRESH
			} else {
				log(LOG_NOTICE, "<%p> [now %lu] NewReno hs: SS->CSS (CA). Setting ssthresh (false)\n", ccv, now_us);
				CCV(ccv, snd_ssthresh) = nreno->css_lowrtt_fas; // SET SSTHRESH
			}
			log(LOG_NOTICE, "<%p> [now %lu] cwnd: newreno setting in css", ccv, now_us);
			CCV(ccv, snd_cwnd) = nreno->css_fas_at_css_entry;
			nreno->css_entered_at_round = round_cnt;
		} else {
			log(LOG_NOTICE, "<%p> [now %lu] NewReno hs: SS->CA. Setting ssthresh to cwnd\n", ccv, now_us);
			CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd); // SET SSTHRESH
			/* Turn off the CSS flag */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			/* Disable use of CSS in the future except long idle  */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
		}
		newreno_log_hystart_event(ccv, nreno, 6, CCV(ccv, snd_ssthresh));
	}
	if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED)
		newreno_log_hystart_event(ccv, nreno, 4, round_cnt);
}

static void
newreno_rttsample(struct cc_var *ccv, uint32_t usec_rtt, uint32_t rxtcnt, uint32_t fas)
{
	struct newreno *nreno;

	nreno = (struct newreno *)ccv->cc_data;
	if (rxtcnt > 1) {
		/*
		 * Only look at RTT's that are non-ambiguous.
		 */
		return;
	}
	nreno->css_rttsample_count++;
	nreno->css_last_fas = fas;
	if (nreno->css_current_round_minrtt > usec_rtt) {
		nreno->css_current_round_minrtt = usec_rtt;
		nreno->css_lowrtt_fas = nreno->css_last_fas;
	}
	if ((nreno->css_rttsample_count >= hystart_n_rttsamples) &&
	    (nreno->css_current_round_minrtt != 0xffffffff) &&
	    (nreno->css_current_round_minrtt < nreno->css_baseline_minrtt) &&
	    (nreno->css_lastround_minrtt != 0xffffffff)) {
		/*
		 * We were in CSS and the RTT is now less, we
		 * entered CSS erroneously.
		 */
		log(LOG_NOTICE, "<%p> NewReno hs: CSS->SS (erroneous CSS)\n", ccv);
		nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
		newreno_log_hystart_event(ccv, nreno, 8, nreno->css_baseline_minrtt);
		nreno->css_baseline_minrtt = 0xffffffff;
	}
	if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED)
		newreno_log_hystart_event(ccv, nreno, 5, usec_rtt);
}

SYSCTL_DECL(_net_inet_tcp_cc_newreno);
SYSCTL_NODE(_net_inet_tcp_cc, OID_AUTO, newreno,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "New Reno related settings");

SYSCTL_PROC(_net_inet_tcp_cc_newreno, OID_AUTO, beta,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &VNET_NAME(newreno_beta), 3, &newreno_beta_handler, "IU",
    "New Reno beta, specified as number between 1 and 100");

SYSCTL_PROC(_net_inet_tcp_cc_newreno, OID_AUTO, beta_ecn,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &VNET_NAME(newreno_beta_ecn), 3, &newreno_beta_handler, "IU",
    "New Reno beta ecn, specified as number between 1 and 100");

DECLARE_CC_MODULE(newreno, &newreno_cc_algo);
MODULE_VERSION(newreno, 2);
