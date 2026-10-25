// nn::os 宿主实现的接口（app/native/za_os.c）与宿主符号表用。
#ifndef ZA_OS_H
#define ZA_OS_H

#include <stdint.h>

// 每个客机线程都要装一次「影子 TLS 描述符」（见 za_guest.c 里的说明）。
void za_os_install_tls_descriptor(void);

// 当前线程对应的「客机 ThreadType 对象」—— GetCurrentThread 要返回非空合法指针。
void *za_os_current_thread_obj(void);

unsigned long long za_os_get_system_tick(void);
unsigned long long za_os_get_system_tick_frequency(void);
void za_os_sleep_thread(long long ns);
void za_os_yield_thread(void);

unsigned int za_os_create_thread(void *thread_obj, void (*fn)(void *), void *arg,
                                 void *stack_obj, int priority, int core_mask);
unsigned int za_os_start_thread(void *thread_obj);
unsigned int za_os_destroy_thread(void *thread_obj);
void *za_os_get_current_thread(void);
unsigned long long za_os_get_thread_id(const void *thread_obj);

unsigned int za_os_initialize_mutex(void *mutex_obj, int recursive, int priority);
void za_os_lock_mutex(void *mutex_obj);
void za_os_unlock_mutex(void *mutex_obj);

unsigned int za_os_initialize_semaphore(void *sem_obj, int count, int max_count);
void za_os_acquire_semaphore(void *sem_obj);
int za_os_try_acquire_semaphore(void *sem_obj);
void za_os_release_semaphore(void *sem_obj, int count);

unsigned int za_os_initialize_event(void *event_obj, int auto_reset, int clear_mode);
void za_os_wait_event(void *event_obj);
int za_os_try_wait_event(void *event_obj);
void za_os_signal_event(void *event_obj);
void za_os_clear_event(void *event_obj);
unsigned int za_os_initialize_light_event(void *event_obj, int auto_reset, int clear_mode);
void za_os_signal_light_event(void *event_obj);
void za_os_wait_light_event(void *event_obj);

// errno / musl
void *za_os_errno_location(void);
unsigned int za_os_nnmusl_init_dso(void);

// Switch OS 注入给 SDK 的「线程局部内存分配器」
// （注册进 SDK .bss 的 0xb9b008 / 0xb9b010 两个槽）
void *za_os_alloc_thread_local(unsigned long size, unsigned long align);
void za_os_free_thread_local(void *p, unsigned long size);
// 客机用的 aligned_alloc（宽松版，绝不因对齐要求返回 NULL）
void *za_os_aligned_alloc(unsigned long alignment, unsigned long size);

unsigned int za_os_get_host_argc(void);
const char **za_os_get_host_argv(void);

unsigned int za_os_allocate_tls_slot(void *slot_obj, void *destructor);
void za_os_set_tls_value(unsigned long long slot, unsigned long long value);
unsigned long long za_os_get_tls_value(unsigned long long slot);
void za_os_free_tls_slot(unsigned long long slot);

#endif
