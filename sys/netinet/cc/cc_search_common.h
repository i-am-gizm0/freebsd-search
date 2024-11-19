#ifndef _CC_SEARCH_COMMON_H
#define _CC_SEARCH_COMMON_H

#define MAX_SEARCH_BIN_VALUE 0xFFFF

/**
 * Window size, in tenths of an RTT (35 = 3.5*InitRTT)
 */
#define SEARCH_WINDOW_SIZE_TIME 35
#define SEARCH_BINS 10
#define SEARCH_EXTRA_BINS 15
#define SEARCH_TOTAL_BINS SEARCH_BINS + SEARCH_EXTRA_BINS
/**
 * Slow start exit threshold, in percent
 */
#define SEARCH_THRESH 35
/**
 * Enable cwnd rollback (on exit, reduce cwnd to its value 2 InitRTT ago, to avoid congestion)
 */
#define SEARCH_ROLLBACK 1

#define SEARCH_WINDOW_SIZE(initial_rtt) initial_rtt * SEARCH_WINDOW_SIZE_TIME
#define SEARCH_BIN_DURATION(initial_rtt) SEARCH_WINDOW_SIZE(initial_rtt) / SEARCH_BINS

#define SEARCH_BIN(ccv, index) ((struct newreno*)(ccv)->cc_data)->search_bin[(index) % SEARCH_TOTAL_BINS]

#endif