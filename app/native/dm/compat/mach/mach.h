// Android 垫片：参考实现的 hle_nvn.c 用 Mach 接口做**只读诊断**
// （线程 QoS、进程内存足迹、每线程指令/周期计数）。安卓没有这些；
// 这里给出足以编译的类型与函数，全部返回失败/零，调用点自然走「读不到」分支。
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "mach_time.h"

typedef unsigned int mach_port_t;
typedef unsigned int mach_msg_type_number_t;
typedef int *task_info_t;
typedef int *thread_info_t;
typedef int *thread_policy_t;
typedef int kern_return_t;

#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define MACH_PORT_NULL 0u

typedef struct { uint64_t phys_footprint; } task_vm_info_data_t;
#define TASK_VM_INFO 22
#define TASK_VM_INFO_COUNT ((mach_msg_type_number_t)(sizeof(task_vm_info_data_t) / sizeof(int)))

typedef struct { int32_t seconds, microseconds; } dm_time_value_t;
typedef struct {
    dm_time_value_t user_time, system_time;
    int32_t run_state, flags;
} thread_basic_info_data_t;
#define THREAD_BASIC_INFO 4
#define THREAD_BASIC_INFO_COUNT ((mach_msg_type_number_t)(sizeof(thread_basic_info_data_t) / sizeof(int)))

typedef struct {
    uint64_t pth_user_time, pth_system_time;
    uint32_t pth_curpri, pth_priority, pth_maxpriority;
} thread_extended_info_data_t;
#define THREAD_EXTENDED_INFO 7
#define THREAD_EXTENDED_INFO_COUNT ((mach_msg_type_number_t)(sizeof(thread_extended_info_data_t) / sizeof(int)))

typedef struct {
    uint32_t period, computation, constraint, preemptible;
} thread_time_constraint_policy_data_t;
#define THREAD_TIME_CONSTRAINT_POLICY 2
#define THREAD_TIME_CONSTRAINT_POLICY_COUNT \
    ((mach_msg_type_number_t)(sizeof(thread_time_constraint_policy_data_t) / sizeof(int)))

static inline mach_port_t mach_task_self(void) { return 0u; }
static inline mach_port_t mach_thread_self(void) { return 0u; }
static inline kern_return_t mach_port_deallocate(mach_port_t task, mach_port_t name)
{ (void)task; (void)name; return KERN_SUCCESS; }
static inline mach_port_t pthread_mach_thread_np(pthread_t t) { (void)t; return 0u; }

static inline kern_return_t task_info(mach_port_t task, int flavor, task_info_t out,
                                      mach_msg_type_number_t *cnt)
{ (void)task; (void)flavor; (void)out; (void)cnt; return KERN_FAILURE; }
static inline kern_return_t thread_info(mach_port_t thr, int flavor, thread_info_t out,
                                        mach_msg_type_number_t *cnt)
{ (void)thr; (void)flavor; (void)out; (void)cnt; return KERN_FAILURE; }
static inline kern_return_t thread_policy_get(mach_port_t thr, int flavor, thread_policy_t p,
                                              mach_msg_type_number_t *cnt, int *get)
{ (void)thr; (void)flavor; (void)p; (void)cnt; if (get) *get = 0; return KERN_FAILURE; }
static inline kern_return_t thread_policy_set(mach_port_t thr, int flavor, const thread_policy_t p,
                                              mach_msg_type_number_t cnt)
{ (void)thr; (void)flavor; (void)p; (void)cnt; return KERN_FAILURE; }
