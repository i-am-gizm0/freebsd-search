/*-
 * Copyright (c) 2017 Tom Jones <tj@enoti.me>
 * All rights reserved.
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

 #ifndef _CC_NEWRENO_H
 #define _CC_NEWRENO_H
 
 #include "cc_search_common.h"
 #define CCALGONAME_NEWRENO "newreno_search"
 
 struct newreno {
     uint32_t beta;
     uint32_t beta_ecn;
     uint32_t newreno_flags;
     // TODO: Extract HyStart and SEARCH parameters into a union once they are guaranteed mutually exclusive
     // union {
     // struct {
     uint32_t css_baseline_minrtt;
     uint32_t css_current_round_minrtt;
     uint32_t css_lastround_minrtt;
     uint32_t css_rttsample_count;
     uint32_t css_entered_at_round;
     uint32_t css_current_round;
     uint32_t css_fas_at_css_entry;
     uint32_t css_lowrtt_fas;
     uint32_t css_last_fas;
     // } hystart;
 
     // struct {
     // <<<<<SEARCH>>>>>
     uint32_t last_rtt_us;
     uint32_t search_bin_duration_us;		// Duration of each bin in microseconds
     int32_t  search_curr_idx;				// Total number of bins
     uint64_t search_bin_end_us;				// End time of the latest bin in microseconds
     search_bin_t search_bin[SEARCH_TOTAL_BINS];	// Array to keep bytes for bins
     // uint8_t search_unused;
     uint8_t search_scale_factor;					// Scale factor to fit value within bin size
 
     uint32_t search_bytes_this_bin;
     uint8_t search_exited;
     // } search;
     // };
 };
 
 struct cc_newreno_opts {
     int		name;
     uint32_t	val;
 };
 
 #define CC_NEWRENO_BETA			1	/* Beta for normal DUP-ACK/Sack recovery */
 #define CC_NEWRENO_BETA_ECN		2	/* ECN Beta for Abe */
 
 /* Flags values */
 #define CC_NEWRENO_HYSTART_ENABLED	0x0002	/* We can do hystart, a loss removes this flag */
 #define CC_NEWRENO_HYSTART_IN_CSS	0x0004	/* If we enter hystart CSS this flag is set */
 #define CC_NEWRENO_BETA_ECN_ENABLED	0x0020
 #endif /* _CC_NEWRENO_H */
