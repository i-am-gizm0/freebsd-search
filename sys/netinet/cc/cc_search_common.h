#ifndef _CC_SEARCH_COMMON_H
#define _CC_SEARCH_COMMON_H

#define MAX_SEARCH_BIN_VALUE 0xFFFF

typedef uint16_t search_bin_t;

/* "WINDOW_SIZE" */
#define SEARCH_WINDOW_SIZE_FACTOR 3.5
/* "W" */
#define SEARCH_BINS 10
#define SEARCH_EXTRA_BINS 15
#define SEARCH_TOTAL_BINS (SEARCH_BINS + SEARCH_EXTRA_BINS)
/**
 * Slow start exit threshold, in percent
 */
#define SEARCH_THRESH 35
/** How many bits to shift each iteration trying to fit sequence number in a bin */
#define SEARCH_SCALE_SHIFT_STEP 1
/** Force a reset after missing this number of bins */
#define SEARCH_MISSED_BIN_RESET_THRESHOLD 2
/**
 * Enable cwnd rollback (on exit, reduce cwnd to its value 2 InitRTT ago, to avoid congestion)
 */
#define SEARCH_ROLLBACK 1

#define SEARCH_WINDOW_SIZE(initial_rtt) initial_rtt * SEARCH_WINDOW_SIZE_FACTOR
#define SEARCH_BIN_DURATION(initial_rtt) SEARCH_WINDOW_SIZE(initial_rtt) / SEARCH_BINS

#define SEARCH_BIN(ccv, index) ((struct newreno*)(ccv)->cc_data)->search_bin[(index) % SEARCH_TOTAL_BINS]

#endif