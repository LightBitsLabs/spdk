#ifndef STATS_STATS_H_
#define STATS_STATS_H_

#include <pthread.h>
#include <rte_lcore.h>
#include "procstat.h"

struct procstat_context *stats_create(const char* stats_mountpoint);
void stats_destroy(struct procstat_context *procstat_ctx);

#endif
