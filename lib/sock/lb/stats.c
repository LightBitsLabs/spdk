#include "stats.h"
#include "lb/log.h"

#define RTE_LOGTYPE_STATS	RTE_LOGTYPE_USER2

static void *stats_loop(void *context)
{
	struct procstat_context *procstat_ctx = (struct procstat_context*)context;

	procstat_loop(procstat_ctx);
	return 0;
}

struct procstat_context *stats_create(const char* stats_mountpoint)
{
	struct procstat_context *procstat_ctx = NULL;
	pthread_t stats_tid;
	cpu_set_t cpuset;
	int ret = 0;

	procstat_ctx = procstat_create(stats_mountpoint);
	if (!procstat_ctx) {
		trace_error(STATS, "Failed to create procstat context");
		goto exit;
	}

	ret = pthread_create(&stats_tid, NULL, stats_loop, procstat_ctx);
	if (ret != 0) {
		trace_error(STATS, "Failed to create stats thread");
		goto error;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(rte_lcore_id(), &cpuset);
	ret = pthread_setaffinity_np(stats_tid, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		trace_error(STATS, "Failed to set affinity for the stats thread");
		goto error;
	}
	pthread_setname_np(stats_tid, "stats");

	return procstat_ctx;

error:
	procstat_destroy(procstat_ctx);
exit:
	return NULL;
}

void stats_destroy(struct procstat_context *procstat_ctx)
{
	procstat_destroy(procstat_ctx);
}


