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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/khelp.h>
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
#include <netinet/khelp/h_ertt.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_log_buf.h>
#include <netinet/tcp_hpts.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_module.h>
#include <netinet/cc/cc_newreno_search.h>
#include <netinet/cc/cc_search_common.h>
// #include "sys/time.h"

#include <sys/syslog.h>

#define SEARCH_LOG_ENABLED

static int newreno_search_mod_init(void);
static void	newreno_cb_destroy(struct cc_var *ccv);
static void	newreno_ack_received(struct cc_var *ccv, uint16_t type);
static void	newreno_after_idle(struct cc_var *ccv);
static void	newreno_cong_signal(struct cc_var *ccv, uint32_t type);
static int newreno_ctl_output(struct cc_var *ccv, struct sockopt *sopt, void *buf);
static void	newreno_newround(struct cc_var *ccv, uint32_t round_cnt);
static void	newreno_rttsample(struct cc_var *ccv, uint32_t usec_rtt, uint32_t rxtcnt, uint32_t fas);
static 	int	newreno_cb_init(struct cc_var *ccv, void *);
static size_t	newreno_data_sz(void);


VNET_DECLARE(uint32_t, newreno_beta);
#define V_newreno_beta VNET(newreno_beta)
VNET_DECLARE(uint32_t, newreno_beta_ecn);
#define V_newreno_beta_ecn VNET(newreno_beta_ecn)

struct cc_algo newreno_search_cc_algo = {
	.name = "newreno_search",
	.mod_init = newreno_search_mod_init,
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

static int ertt_id;

static int newreno_search_mod_init(void) {
	ertt_id = khelp_get_id("ertt");
	if (ertt_id <= 0) {
		printf("%s: h_ertt module not found\n", __func__);
		return (ENOENT);
	}
	return (0);
}

// <<<<<SEARCH IMPL>>>>> note: no conn_init defined
// <<<<<SEARCH IMPL>>>>> note: no ssthresh_update or related (ssthresh is updated in 7 placed in this file)

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

	if (hystart_bblogs == 0)
		return;
	tp = ccv->ccvc.tcp;
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

// <<<<<SEARCH IMPL>>>>> Reset search

static void search_reset(struct newreno* nreno) {
	memset(nreno->search_bin, 0, sizeof(nreno->search_bin));
	nreno->search_bin_duration_us = 0;
	nreno->search_curr_idx = -1;
	nreno->search_bin_end_us = 0;
	nreno->search_scale_factor = 0;
	nreno->search_bytes_this_bin = 0;
}

static int
newreno_cb_init(struct cc_var *ccv, void *ptr)
{
	log(LOG_NOTICE, "<%p> Init CB\n", ccv);
	struct newreno *nreno;

	INP_WLOCK_ASSERT(tptoinpcb(ccv->ccvc.tcp));
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
	nreno->search_exited = 0;

	// <<<<<SEARCH IMPL>>>>> Initialize variables here
	search_reset(nreno);

	return (0);
}

static void
newreno_cb_destroy(struct cc_var *ccv)
{
	log(LOG_NOTICE, "Destroy CB\n");
	free(ccv->cc_data, M_CC_MEM);
}

static uint64_t get_now_us(void) {
	static struct timeval tv;
	microtime(&tv);
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

static uint64_t get_rtt_us(struct cc_var* ccv) {
	// return ((uint64_t)CCV(ccv, t_srtt) * tick) >> TCP_RTT_SHIFT;
	return ((struct newreno *)ccv->cc_data)->last_rtt_us;
}

/*
 * Scale bin value to fit bin size, rescale previous bins.
 * Return amount scaled.
 * In Linux implementation, this is named search_bit_shifting
 */
static void search_rescale_bins(struct cc_var* ccv, uint64_t* bin_value) {
	struct newreno* nreno = ccv->cc_data;

	uint8_t num_shift = 0;	// Keep track of how many bits it's been shifted by
	
	// Adjust bin value if it's greater than MAX_SEARCH_BIN_VALUE
	while (*bin_value > MAX_SEARCH_BIN_VALUE) {
		num_shift++;
		*bin_value >>= 1;	// Divide by two
	}

	// Adjust all previous bins according to the new shift amount
	for (uint8_t i = 0; i < SEARCH_TOTAL_BINS; i++) {
		SEARCH_BIN(ccv, i) >>= num_shift;
	}

	// Update the saved scale factor
	nreno->search_scale_factor += num_shift;
}

static void search_init_bins(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {
	struct newreno* nreno = ccv->cc_data;

	search_reset(nreno);

	nreno->search_bin_duration_us = SEARCH_BIN_DURATION_US(rtt_us);
	// nreno->search_bin_duration_us = SEARCH_WINDOW_SIZE(rtt_us) / SEARCH_BINS;
	nreno->search_bin_end_us = now_us + nreno->search_bin_duration_us;
	nreno->search_curr_idx = -1;
#ifdef SEARCH_LOG_ENABLED
	log(LOG_NOTICE, "<%p> INIT bins [now_us %lu] [rtt_us %lu] [duration %d] [end %ld]\n",
		ccv,
		now_us,
		rtt_us,
		nreno->search_bin_duration_us,
		nreno->search_bin_end_us);
#endif
}

static int search_update_bins(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {
	struct newreno* nreno = ccv->cc_data;

	// passed_bins > 1 means we missed some bins
	uint32_t passed_bins = ((now_us - nreno->search_bin_end_us) / nreno->search_bin_duration_us) + 1;

	/* If we passed more than SEARCH_MISSED_BIN_RESET_THRESHOLD bins, need to reset SEARCH, and initialize bins*/
	if (passed_bins > SEARCH_MISSED_BIN_RESET_THRESHOLD) {
		log(LOG_NOTICE, "<%p> SEARCH RESET! Passed %u bins!\n", ccv, passed_bins);
		search_reset(nreno);
		search_init_bins(ccv, now_us, rtt_us);
		return 1;
	} else if (passed_bins > 1) {
		log(LOG_NOTICE, "<%p> SEARCH passed %u bins! Filling missing data\n", ccv, passed_bins);
		if (nreno->search_curr_idx < 0) {
			passed_bins += nreno->search_curr_idx;
			nreno->search_curr_idx = 0;
			log(LOG_NOTICE, "<%p> search_curr_idx < 0, setting passed_bins to %u\n", ccv, passed_bins);
		}
		for (uint32_t i = nreno->search_curr_idx + 1; i < nreno->search_curr_idx + passed_bins; i++) {
			SEARCH_BIN(ccv, i) = SEARCH_BIN(ccv, nreno->search_curr_idx);
		}
	}

	nreno->search_curr_idx += passed_bins;
	nreno->search_bin_end_us += passed_bins * nreno->search_bin_duration_us;

#ifdef SEARCH_LOG_ENABLED
	log(LOG_INFO, "<%p> SEARCH update bins: [now %lu] [curr_idx %d] [bin_end_us %lu]\n",
		ccv,
		now_us,
		nreno->search_curr_idx,
		nreno->search_bin_end_us
	);
#endif

	// Calculate bin_value by dividing bytes_acked by 2^scale_factor
	uint64_t bin_value = (nreno->search_bytes_this_bin >> nreno->search_scale_factor);
	if (nreno->search_curr_idx > 0) 
		bin_value += SEARCH_BIN(ccv, nreno->search_curr_idx - 1);
	nreno->search_bytes_this_bin = 0;

	if (bin_value > MAX_SEARCH_BIN_VALUE) {
		log(LOG_INFO, "<%p> SEARCH Rescaling bins\n", ccv);
		search_rescale_bins(ccv, &bin_value);
	}
	
	// Assign bin value to current bin
	SEARCH_BIN(ccv, nreno->search_curr_idx) = (search_bin_t)bin_value;

#ifdef SEARCH_LOG_ENABLED
	log(LOG_INFO, "<%p> SEARCH BINS: ", ccv);
	for (int i = 0; i < SEARCH_TOTAL_BINS; i++) {
		log(LOG_INFO, "| %u ", nreno->search_bin[i]);
	}
	log(LOG_INFO, "|\n");
#endif

	return 0;
}

/**
 * Calculates the bytes delivered when we want to look at some time boundaries in the middle of bins
 */
static uint64_t search_compute_delivered_window(struct cc_var* ccv, int32_t index1, int32_t index2, uint32_t fraction) {
	// TODO: Does this need 64 bits?
	// How many bytes were delivered between these bins
	uint64_t delivered = SEARCH_BIN(ccv, index2 - 1) - SEARCH_BIN(ccv, index1);

	// Take some fraction% data from the bin before index 1
	if (index1 == 0) { // We are interpolating using the very first bin: the "previous" bin value is 0
		delivered += SEARCH_BIN(ccv, index1) * fraction / 100;
	} else {
		delivered += (SEARCH_BIN(ccv, index1) - SEARCH_BIN(ccv, index1 - 1)) * fraction / 100;
	}

	delivered += (SEARCH_BIN(ccv, index2) - SEARCH_BIN(ccv, index2 - 1)) * (100 - fraction) / 100;

	return delivered;
}

static void search_exit_slow_start(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {
	struct newreno* nreno = ccv->cc_data;

	int32_t cong_idx = 0;
	uint32_t initial_rtt = 0;
	uint64_t overshoot_bytes = 0;
	uint32_t overshoot_cwnd = 0;

	/*
	 * If cwnd rollback is enabled, the code calculates the initial round-trip time (RTT)
	 * and determines the congestion index (`cong_idx`) from which to compute the overshoot.
	 * The overshoot represents the excess bytes delivered beyond the estimated target,
	 * which is calculated over a window defined by the current and the rollback indices.
	 * 
	 * The rollback logic adjusts the congestion window (`snd_cwnd`) based on the overshoot:
	 * 1. It first computes the overshoot congestion window (`overshoot_cwnd`), derived by
	 *    dividing the overshoot bytes by the maximum segment size (MSS).
	 * 2. It reduces `snd_cwnd` by the calculated overshoot while ensuring it does not fall
	 *    below the initial congestion window (`TCP_INIT_CWND`), which acts as a safety guard.
	 * 3. If the overshoot exceeds the current congestion window, it resets `snd_cwnd` to the 
	 *    initial value, providing a safeguard to avoid a drastic drop in case of miscalculations
	 *    or unusual network conditions (e.g., TCP reset).
	 * 
	 * After adjusting the congestion window, the slow start threshold (`snd_ssthresh`) is set 
	 * to the updated congestion window to finalize the rollback.
	 */

	 if (SEARCH_ROLLBACK) {
		initial_rtt = nreno->search_bin_duration_us * SEARCH_BINS * 10 / SEARCH_WINDOW_SIZE_FACTOR;
		cong_idx = nreno->search_curr_idx - ((2 * initial_rtt) / nreno->search_bin_duration_us);

		// Calculate the overshoot based on the delivered bytes between cong_idx and the current index
		overshoot_bytes = search_compute_delivered_window(ccv, cong_idx, nreno->search_curr_idx, 0);

		// Calculate the rollback congestion window based on overshoot divided by MSS
		overshoot_cwnd = overshoot_bytes / CCV(ccv, t_maxseg);	// TODO: Correct MSS?

		/*
		 * Reduce the current congestion window,
		 * but guard so it doesn't drop below the initial cwnd
		 * or is not larger than the current cwnd (in case of TCP reset)
		 */
		if (overshoot_cwnd < CCV(ccv, snd_cwnd)) {
			log(LOG_NOTICE, "cwnd: setting for search rollback\n");
			CCV(ccv, snd_cwnd) = max(CCV(ccv, snd_cwnd) - overshoot_cwnd, V_tcp_initcwnd_segments);
		} else {
			log(LOG_NOTICE, "cwnd: search rollback resetting to initial\n");
			CCV(ccv, snd_cwnd) = V_tcp_initcwnd_segments;
		}
	 }

	log(LOG_INFO, "<%p> [now %lu] SEARCH: Exit slow start with ssthresh = %u\n", ccv, now_us, CCV(ccv, snd_cwnd));
	nreno->search_exited = 1;
	// CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd);
}

// <<<<<SEARCH IMPL>>>>> SEARCH update
static void search_update(struct cc_var* ccv) {
	// log(LOG_NOTICE, "SEARCH update\n");
	struct newreno* nreno = ccv->cc_data;

	uint64_t now_us = get_now_us();
	uint64_t rtt_us = get_rtt_us(ccv);

	int32_t prev_idx = 0;
	int64_t curr_delv_bytes = 0;	// Bytes delivered in the current rolling RTT
	int64_t prev_delv_bytes = 0;	// Bytes delivered in the previous rolling RTT
	int32_t norm_diff = 0; 			// Ratio of expected/actual delivered bytes in the current rolling RTT
	uint32_t fraction = 0; // Interpolate sliding bin values that might not exactly line up with bins

	nreno->search_bytes_this_bin += ccv->bytes_this_ack;

	// On first ack, initialize bin duration and bin end time
	if (nreno->search_bin_duration_us == 0) {
		search_init_bins(ccv, now_us, rtt_us);
		return;
	}

	// If we have reached the bin boundary,
	if (now_us > nreno->search_bin_end_us) {
		// log(LOG_NOTICE, "<%p> SEARCH bin boundary\n", ccv);
		if (search_update_bins(ccv, now_us, rtt_us)) {
			// Missed > SEARCH_MISSED_BIN_RESET_THRESHOLD bins
			return;
		}

		// Are there enough bins to compute previous window?
		prev_idx = nreno->search_curr_idx - (rtt_us / nreno->search_bin_duration_us);
#ifdef SEARCH_LOG_ENABLED
		log(LOG_INFO, "<%p> SEARCH Compute windows: [now %lu] [prev_idx %d]", ccv, now_us, prev_idx);
#endif
		if (prev_idx >= SEARCH_BINS && (nreno->search_curr_idx - prev_idx) < SEARCH_EXTRA_BINS - 1) { // Add back -1?
			// Calculate delivered bytes for the current and previous windows
			curr_delv_bytes = search_compute_delivered_window(ccv, nreno->search_curr_idx - SEARCH_BINS, nreno->search_curr_idx, 0);
			fraction = ((rtt_us % nreno->search_bin_duration_us) * 100 / nreno -> search_bin_duration_us);
			prev_delv_bytes = search_compute_delivered_window(ccv, prev_idx - SEARCH_BINS, prev_idx, fraction);
#ifdef SEARCH_LOG_ENABLED
			log(LOG_INFO, " [curr_delv_bytes %ld] [fraction %d] [prev_delv_bytes %ld]", curr_delv_bytes, fraction, prev_delv_bytes);
#endif
			if (prev_delv_bytes > 0) {
				norm_diff = ((2 * prev_delv_bytes) - curr_delv_bytes) * 100 / (2 * prev_delv_bytes);
#ifdef SEARCH_LOG_ENABLED
				log(LOG_INFO, "[norm_diff %d]", norm_diff);
#endif
				// exit condition
				if ((2 * prev_delv_bytes) >= curr_delv_bytes && norm_diff >= SEARCH_THRESH) {
#ifdef SEARCH_LOG_ENABLED
					log(LOG_INFO, "\n");
#endif
					search_exit_slow_start(ccv, now_us, rtt_us);
				}
			}
		}
#ifdef SEARCH_LOG_ENABLED
		log(LOG_INFO, "\n");
#endif
	}
}

static void
newreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	struct newreno *nreno;

	nreno = ccv->cc_data;
	uint64_t rtt_us = get_rtt_us(ccv);
	

#ifdef SEARCH_LOG_ENABLED
	log(LOG_INFO, "<%p> ACK: [now %lu] [srtt %lu] [cur_bytes %u] [curack %u] [cwnd %u] [ssthresh %u]\n", 
		ccv, 
		get_now_us(), 
		rtt_us,
		nreno->search_bytes_this_bin,
		ccv->curack,
		CCV(ccv, snd_cwnd),
		CCV(ccv, snd_ssthresh)
	);
#endif

	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
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
			if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
				/*
				 * We have slipped into CA with
				 * CSS active. Deactivate all.
				 */
				log(LOG_INFO, "<%p> Exiting Hystart++ CSS, cwnd > ssthresh\n", ccv);
				/* Turn off the CSS flag */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
				/* Disable use of CSS in the future except long idle  */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
				newreno_log_hystart_event(ccv, nreno, 11, CCV(ccv, snd_ssthresh));
			}
			// (else?) if doing search
			// then stop search
			if (V_tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = max((incr * incr / cw), 1);
		} else {
			if (V_tcp_do_rfc3465) {
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
				if (////(ccv->flags & CCF_HYSTART_ALLOWED) &&
				    (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) &&
				    ((nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) == 0)) {
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
						if (nreno->css_current_round_minrtt >= (nreno->css_lastround_minrtt + rtt_thresh)) {
							/* Enter CSS */
							nreno->newreno_flags |= CC_NEWRENO_HYSTART_IN_CSS;
							nreno->css_fas_at_css_entry = nreno->css_lowrtt_fas;
							log(LOG_INFO, "<%p> [now %lu] Hystart++ Entering CSS\n", ccv, get_now_us());
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

				/* Only if Hystart is enabled will the flag get set */
				if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
					//// incr /= hystart_css_growth_div;
					newreno_log_hystart_event(ccv, nreno, 3, incr);
				}
			}
			// if doing search and not stopped
			// update search
			// if (!nreno->search_exited)
				search_update(ccv);
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0) {
			// log(LOG_NOTICE, "<%p> cwnd: increasing in cwnd_limited (slow start)\n", ccv);
			CCV(ccv, snd_cwnd) = min(cw + incr,
			    TCP_MAXWIN << CCV(ccv, snd_scale));
		}

	}
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
		log(LOG_INFO, "<%p> [now %lu] Re-enabling Hystart++ after idle\n", ccv, now_us);
	} // else if doing search
	// then unstop search
	search_reset(nreno);
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
newreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	struct newreno *nreno;
	uint32_t beta, beta_ecn, cwin, factor;
	u_int mss;

	uint64_t now_us = get_now_us();

	cwin = CCV(ccv, snd_cwnd);
	mss = tcp_fixed_maxseg(ccv->ccvc.tcp);
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
			log(LOG_INFO, "<%p> [now %lu] Disabling Hystart++ at loss\n", ccv, now_us);
			/* Make sure the flags are all off we had a loss */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			newreno_log_hystart_event(ccv, nreno, 10, CCV(ccv, snd_ssthresh));
		}
		// TODO: search_reset?
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
			// log(LOG_INFO, "<%p> [now %lu] Entering recovery, dup ack threshold reached\n", ccv, now_us);
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
		// TODO: search_reset?
		if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
			// log(LOG_INFO, "NewReno Cong signal: ECN. setting ssthresh\n");
			CCV(ccv, snd_ssthresh) = cwin; // SET SSTHRESH
			// log(LOG_INFO, "cwnd: cong sig ECN: setting to cwin");
			CCV(ccv, snd_cwnd) = cwin;
			log(LOG_INFO, "Entering recovery, ECN received\n");
			ENTER_CONGRECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_RTO:
		log(LOG_NOTICE, "<%p> [now %lu] NewReno Cong signal: RTO. setting ssthresh\n", ccv, now_us);
		CCV(ccv, snd_ssthresh) = max(min(CCV(ccv, snd_wnd),
						 CCV(ccv, snd_cwnd)) / 2 / mss,
					     2) * mss; // SET SSTHRESH
		log(LOG_NOTICE, "<%p> [now %lu] cwnd: cong sig RTO - setting to MSS", ccv, now_us);
		CCV(ccv, snd_cwnd) = mss;
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

	if (CC_ALGO(ccv->ccvc.tcp) != &newreno_search_cc_algo)
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
				log(LOG_NOTICE, "<%p> [now %lu] NewReno Hystart++: SS->CSS (CA). Slamming cwnd\n", ccv, now_us);
				//// CCV(ccv, snd_ssthresh) = ((nreno->css_lowrtt_fas + nreno->css_fas_at_css_entry) / 2); // SET SSTHRESH
			} else {
				log(LOG_NOTICE, "<%p> [now %lu] NewReno Hystart++: SS->CSS (CA). Setting ssthresh\n", ccv, now_us);
				//// CCV(ccv, snd_ssthresh) = nreno->css_lowrtt_fas; // SET SSTHRESH
			}
			// log(LOG_NOTICE, "<%p> [now %lu] cwnd: newreno setting in css", ccv, now_us);
			//// CCV(ccv, snd_cwnd) = nreno->css_fas_at_css_entry;
			nreno->css_entered_at_round = round_cnt;
		} else {
			log(LOG_NOTICE, "<%p> [now %lu] Hystart++ Exiting\n", ccv, now_us);
			//// CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd); // SET SSTHRESH
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
	nreno->last_rtt_us = usec_rtt;
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
		log(LOG_NOTICE, "<%p> NewReno Hystart++: CSS->SS (erroneous CSS)\n", ccv);
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

DECLARE_CC_MODULE(newreno, &newreno_search_cc_algo);
MODULE_VERSION(newreno, 0);
