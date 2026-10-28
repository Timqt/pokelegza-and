#include "mach/mach_time.h"
#include "mach/mach.h"
#include <time.h>
#include <errno.h>

uint64_t mach_absolute_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

kern_return_t mach_timebase_info(mach_timebase_info_data_t *info)
{
    if (info) { info->numer = 1; info->denom = 1; }
    return KERN_SUCCESS;
}

uint64_t clock_gettime_nsec_np(int clock_id)
{
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// 等到 deadline（我们的时基就是纳秒）。async-signal-safe。
void mach_wait_until(uint64_t deadline)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(deadline / 1000000000ull);
    ts.tv_nsec = (long)(deadline % 1000000000ull);
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) { }
}

// libSystem 私有接口；安卓上给零，调用方看到的是「读不到」。
int thread_selfcounts(int type, void *buf, size_t nbytes)
{
    (void)type; (void)buf; (void)nbytes;
    return -1;
}
