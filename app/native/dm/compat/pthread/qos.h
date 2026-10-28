// Android 垫片：参考实现用 QoS 类做线程优先级诊断/设置。安卓没有这套，
// 全部退化为「未指定」，设置调用是空操作（不影响功能）。
#pragma once
#include <pthread.h>
typedef enum {
    QOS_CLASS_USER_INTERACTIVE = 0x21,
    QOS_CLASS_USER_INITIATED   = 0x19,
    QOS_CLASS_DEFAULT          = 0x15,
    QOS_CLASS_UTILITY          = 0x11,
    QOS_CLASS_BACKGROUND       = 0x09,
    QOS_CLASS_UNSPECIFIED      = 0x00,
} qos_class_t;

static inline int pthread_set_qos_class_self_np(qos_class_t c, int rel)
{ (void)c; (void)rel; return 0; }
static inline int pthread_attr_set_qos_class_np(pthread_attr_t *a, qos_class_t c, int rel)
{ (void)a; (void)c; (void)rel; return 0; }
static inline int pthread_get_qos_class_np(pthread_t t, qos_class_t *c, int *rel)
{ (void)t; if (c) *c = QOS_CLASS_UNSPECIFIED; if (rel) *rel = 0; return 0; }
