// 客机（main NSO）装载器：映像映射、基址重定位、导入解析、TLS 改写、启动。
//
// ⚠ 本文件于 2026-10-25 被一次错误的批量替换（re.sub 跨行匹配）清空，现按以下依据重建：
//   · work/recover/libzaandroid-1403.so 的 DWARF 行号表（原文件 2,743 行、117 个代码段）
//   · app/native/za_guest_api.h（对外接口定义，完好）
//   · 现存头文件 za_guest_info.h / za_imports.h / za_relocs.h / za_tls_patch.h /
//     za_tls_mrs.h / za_tlsro_patch.h / za_svc_patch.h
//   · 借鉴清单.md 里记录的全部逆向结论
// 重建原则：**接口与行为按文档实证的来，注释里逐条标注依据**。
//
// 客机是 Switch 原生 ARM64，安卓也是 ARM64 ⇒ 直接跑、不翻译。
// 需要解决的是「导入怎么解析」「TLS 怎么给」「OS 服务谁提供」。

// process_vm_readv 要 _GNU_SOURCE（bionic 的 <sys/uio.h> 才声明它）
// ⚠ 必须在任何系统头文件之前定义
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <android/log.h>

#include "za_common.h"
#include "za_guest_info.h"
#include "za_imports.h"
#include "za_relocs.h"
#include "za_stub.h"
#include "za_tls_patch.h"
#include "za_tlsbase_patch.h"
#include "za_tlsro_patch.h"
#include "za_tls_mrs.h"
#include "za_tls_mrs_blob.h"
#include "za_mod.h"
#include "za_sdk.h"
#include "za_guest_api.h"
#include "za_os.h"

// ── 客机映像布局（来自 za_guest_info.h，实测值）────────────────────────
//   text   0x0000000 .. 0x2fc7250
//   rodata 0x2fc8000 .. 0x39e1000
//   data   0x39e1000 .. 0x3d7f1c0
//   bss    +0x21fae40        ⇒ 映像总计 0x5f7a000
#define ZA_GUEST_BASE_ADDR 0x100000000ul   // 客机代码里硬编码的基址，必须映射到这里

// 客机全局状态（其它 .c 通过 extern 访问）
unsigned char *za_guest_base = NULL;
volatile unsigned long za_sdk_base = 0;
volatile unsigned long za_sdk_size = 0;

// 崩溃/诊断用的线程身份
volatile long za_render_tid = 0;
volatile long za_guest_tid = 0;
volatile long za_render_entry = 0;
volatile int za_render_crashes = 0;
volatile unsigned long za_so_base = 0;
char za_last_sym[256];

// svc 轨迹（崩溃时倒出来，直接看「最后一步调了什么」）
unsigned long za_svc_trace_nr[32];
unsigned long za_svc_trace_pc[32];
unsigned long za_svc_trace_pos;

// ── 小工具（信号处理器里也只能用这些，不能碰 libc）──────────────────
static char *za_put_str(char *p, const char *s)
{
    while (*s) *p++ = *s++;
    return p;
}

static char *za_put_hex(char *p, unsigned long long v)
{
    static const char dig[] = "0123456789abcdef";
    *p++ = '0';
    *p++ = 'x';
    if (!v) { *p++ = '0'; return p; }
    char tmp[16];
    int n = 0;
    while (v) { tmp[n++] = dig[v & 0xF]; v >>= 4; }
    while (n) *p++ = tmp[--n];
    return p;
}

// 把地址换算成「模块名+偏移」，光看绝对地址没法反查汇编
static char *za_put_addr(char *p, unsigned long a)
{
    if (za_guest_base && a >= (unsigned long)za_guest_base &&
        a < (unsigned long)za_guest_base + ZA_IMAGE_SIZE)
    {
        p = za_put_str(p, "main+");
        p = za_put_hex(p, a - (unsigned long)za_guest_base);
        return p;
    }
    if (za_sdk_base && a >= za_sdk_base && a < za_sdk_base + za_sdk_size)
    {
        p = za_put_str(p, "sdk+");
        p = za_put_hex(p, a - za_sdk_base);
        return p;
    }
    return za_put_hex(p, a);
}
