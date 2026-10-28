// process_vm_readv 要 _GNU_SOURCE（bionic 的 <sys/uio.h> 才声明它）
// ⚠ 必须在任何系统头文件之前定义
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Horizon 的「锁交接 + 条件变量」内核模拟（svc#26/#27/#28/#29）。
//
// 为什么独立成文件、且**不用 pthread 锁/条件变量**：
//   · 这四个 svc 是在「客机线程 + 门切换到宿主栈」的上下文里调用的，之前用
//     pthread_cond_wait 实现，实测启动早期就崩在 bionic 的 syscall/条件变量里
//     （pc=syscall+0x28、x30=__futex_wait_ex+148）。
//   · 这里只依赖两样东西：宿主自己的原子量 + SYS_futex。没有任何 libc 锁，
//     不会和客机/宿主其它锁互相影响，也不会在信号上下文里死锁。
//
// 语义（照 d2r-and 的 dm/host/hle_thread.c，真机跑通的成品）：
//   ArbitrateLock(owner, addr, tag)
//     用户态快路径刚把锁字 CAS 成 `owner|0x40000000`（有等待者位）并失败，
//     才进来。锁字仍等于 `owner|等待者位` ⇒ 登记为 addr 的锁等待者、睡眠；
//     被别人交接时锁字已被写成我的 tag ⇒ 返回（视为拿到锁）。
//     锁字已经变了 ⇒ 立刻返回，让用户态按自己的逻辑重试。
//   ArbitrateUnlock(addr)
//     把锁**交给**等待队列里的第一个线程（锁字 = 它的 tag，还有别人就保留
//     等待者位）；没有等待者才清零。
//   WaitProcessWideKeyAtomic(addr, key, tag, timeout)
//     先置 *key = 1（SDK 的 SignalConditionVariable 看到 0 就不发 svc#29），
//     再放锁，然后等唤醒；超时不重新拿锁。
//   SignalProcessWideKey(key, n)
//     唤醒 n 个（<=0 全部）等在该键上的线程并把锁交给它们；没有剩余等待者
//     时把 *key 清零。
//
// 与内核的偏差：等待者用「自己的唤醒字 + 5ms 分片 futex 等待」，不是内核
// 队列，所以偶发伪唤醒是可能的——两者都是允许的（ConditionVariable 本来就
// 允许伪唤醒，调用方会重判条件）。锁交接本身是原子的（在自旋锁里完成）。
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <sys/uio.h>

#include "za_common.h"
#include "za_guest_api.h"
#include "za_sync.h"
#include "za_guest_info.h"

// za_guest.c / za_sdk.c：客机映像的范围（用来把地址翻译成 main+0x… / sdk+0x…）
extern unsigned char *za_guest_base;
extern volatile unsigned long za_sdk_base, za_sdk_size;

static int za_sync_read(void *dst, unsigned long long addr, size_t len)
{
    struct iovec l = { dst, len }, r = { (void *)(uintptr_t)addr, len };
    return process_vm_readv((pid_t)syscall(SYS_getpid), &l, 1, &r, 1, 0) == (ssize_t)len;
}

// 把地址翻译成 main+… / sdk+… 并打印。返回 1 = 落在映像内。
static int za_sync_print_addr(const char *what, unsigned long long pc)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    if (pc >= mb && pc < mb + ZA_IMAGE_SIZE) {
        ZLOGI("      %s=main+%#llx", what, pc - mb);
        return 1;
    }
    if (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size) {
        ZLOGI("      %s=sdk+%#llx", what, pc - za_sdk_base);
        return 1;
    }
    ZLOGI("      %s=%#llx", what, pc);
    return 0;
}

static int za_sync_in_image(unsigned long long x)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    if (x >= mb && x < mb + ZA_IMAGE_SIZE) return 1;
    if (za_sdk_base && x >= za_sdk_base && x < za_sdk_base + za_sdk_size) return 1;
    return 0;
}

// 扫栈（**只作兜底**）：从 sp 往上找前若干个落在映像内的字。
// ★ 这是启发式：映像内的数据指针也会命中，曾经两次把非调用点当成帧
//   （main+0x1738a18 / main+0x173a01c 都被反汇编证伪）。有 fp 时不要用。
static int za_scan_words = 2048;
static void za_sync_scan_chain(unsigned long long sp, const char *why)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    unsigned long long v[24];
    int kind[24];   // 1 = main, 2 = sdk
    int n = 0, is_worker = 0;
    for (int k = 0; k < za_scan_words && n < 24; k++) {
        unsigned long long x = 0;
        if (!za_sync_read(&x, sp + (unsigned long)k * 8, 8)) break;
        if (x >= mb && x < mb + ZA_IMAGE_SIZE) {
            if (x - mb == 0x1bab754ull || x - mb == 0x1bac54cull) is_worker = 1;
            v[n] = x - mb; kind[n++] = 1;
        } else if (za_sdk_base && x >= za_sdk_base && x < za_sdk_base + za_sdk_size) {
            v[n] = x - za_sdk_base; kind[n++] = 2;
        }
    }
    int show = is_worker ? (n < 6 ? n : 6) : n;
    if (!is_worker) ZLOGI("      ★ 扫栈兜底（%s）——结果不可信，仅供参考：%d 帧", why, show);
    for (int i = 0; i < show; i++)
        ZLOGI("        %s%#llx", kind[i] == 1 ? "main+" : "sdk+", v[i]);
}

// ── 不依赖 svc 门的 x29 链重建 ─────────────────────────────────────────
// 主线程的门没有把 x29 存进槽位（实测它的 sp/x30/x29 读出来全是 0），
// 所以只能在它的栈区里**反向**把链拼回来：
//   ① 扫栈，收集所有「像一帧」的候选：W 处 [W]=下一帧 fp、[W+8]=返回地址，
//      且下一帧 fp > W（ARM64 栈向低地址增长，帧指针向高地址走）。
//   ② 把候选按「下一帧 fp」首尾相接串成链；只认**接得最长**的那条。
//   ③ 用线程入口校验：18 条工作线程的链尾都是 sdk+0xc90a50，主线程同一入口。
// 这比「把所有像代码地址的字当返回地址」强得多：后者会命中映像内的数据指针。
#define ZA_CAND_MAX 512
typedef struct { unsigned long long fp, lr, next; } za_cand_t;
static za_cand_t za_cands[ZA_CAND_MAX];

static void za_sync_recover_chain(unsigned long long lo, unsigned long long hi)
{
    // 按 4KB 分块读，避免 8 字节一次 readv 的上万次系统调用
    static unsigned char buf[4096 + 8];
    int n = 0;
    for (unsigned long long a = lo; a < hi && n < ZA_CAND_MAX; ) {
        size_t len = (size_t)((hi - a) < 4096 ? (hi - a) : 4096);
        if (!za_sync_read(buf, a, len)) { a += 4096; continue; }
        for (size_t o = 0; o + 16 <= len && n < ZA_CAND_MAX; o += 8) {
            unsigned long long fp = a + o;
            unsigned long long next, lr;
            memcpy(&next, buf + o, 8);
            memcpy(&lr, buf + o + 8, 8);
            if (!za_sync_in_image(lr)) continue;
            if (next <= fp) continue;
            if (next - fp > 0x100000ull) continue;
            za_cands[n].fp = fp;
            za_cands[n].lr = lr;
            za_cands[n].next = next;
            n++;
        }
        a += len;
    }
    if (!n) { ZLOGI("      （反向重建：栈区里没有任何合法帧）"); return; }

    // 链：从某帧出发，反复找「fp == 当前帧的 next」的那一帧
    int best = -1, bestlen = 0;
    unsigned long long entry_lr = za_sdk_base ? za_sdk_base + 0xc90a50ull : 0;
    for (int i = 0; i < n; i++) {
        int cur = i, len = 1;
        unsigned long long outer_lr = za_cands[i].lr;
        for (int k = 0; k < 40; k++) {
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur].next) { j = t; break; }
            if (j < 0) break;
            cur = j; len++;
            outer_lr = za_cands[cur].lr;
        }
        // 命中线程入口的链优先级最高
        int hit_entry = (entry_lr && outer_lr == entry_lr);
        if (hit_entry && bestlen < 1000) { best = i; bestlen = 1000 + len; continue; }
        if (bestlen < 1000 && len > bestlen) { best = i; bestlen = len; }
    }
    if (best < 0) { ZLOGI("      （反向重建：链都没接上）"); return; }
    int real_len = bestlen >= 1000 ? bestlen - 1000 : bestlen;
    ZLOGI("      ★ 反向 fp 链（%s，共 %d 帧）：",
          bestlen >= 1000 ? "已与线程入口 sdk+0xc90a50 对齐" : "未命中入口，仅按最长链接",
          real_len);
    {
        extern unsigned char *za_guest_base;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        int cur = best;
        for (int k = 0; k < real_len && k < 40; k++) {
            unsigned long long lr = za_cands[cur].lr;
            if (lr >= mb && lr < mb + ZA_IMAGE_SIZE)
                ZLOGI("        [%d] fp=%#llx lr=main+%#llx", k, za_cands[cur].fp, lr - mb);
            else
                ZLOGI("        [%d] fp=%#llx lr=sdk+%#llx", k, za_cands[cur].fp, lr - za_sdk_base);
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur].next) { j = t; break; }
            if (j < 0) break;
            cur = j;
        }
    }
    // 帧内容：每帧 prologue 都会把 callee-saved 寄存器（x19/x20/…）压进帧里。
    // 把帧底往下 0x40 字节的**指针**挑出来打印 —— 主线程等的那个对象
    // （`[self+0x158]` 状态机）就在其中某个 x19/x20 槽里。
    {
        extern unsigned char *za_guest_base;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        ZLOGI("      ★ 帧内指针（x19/x20… 的溢出槽，找等待对象用）：");
        int cur2 = best;
        for (int k = 0; k < real_len && k < 10; k++) {
            unsigned long long fp = za_cands[cur2].fp;
            unsigned long long w[8];
            if (fp < 0x60 || !za_sync_read(w, fp - 0x40, sizeof w)) {
                /* 跳过 */
            } else {
                for (int t = 0; t < 8; t++) {
                    unsigned long long x = w[t];
                    if (!x) continue;
                    int is_code = za_sync_in_image(x);
                    int is_heap = (x >> 40) == 0xb40000ull;
                    if (!is_code && !is_heap) continue;
                    ZLOGI("        [%d] fp%+#x = %#llx%s", k, t * 8 - 0x40, x,
                          is_code ? "（代码）" : "（客机堆）");
                }
            }
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur2].next) { j = t; break; }
            if (j < 0) break;
            cur2 = j;
        }
    }
}

// 沿 x29 帧指针链回溯。ARM64 标准帧布局：
//     [fp + 0] = 调用者的 fp
//     [fp + 8] = 返回地址（本函数的 lr）
// 门桩把 svc 那一刻的客机 x29 存进 regs[17]，所以起点是**真实的帧指针**。
// 停止条件：fp 未对齐 / 不可读 / 不递增 / 跨度异常 / 该帧的 lr 不在映像内。
static void za_sync_dump_guest_chain(unsigned long long fp, unsigned long long sp,
                                     unsigned long long pc)
{
    if (pc) za_sync_print_addr("客机等待点 x30", pc);
    if (!fp) {
        ZLOGI("      （没有 fp：退回扫栈）");
        if (sp) za_sync_scan_chain(sp, "无 fp");
        return;
    }
    unsigned long long cur = fp, prev = 0;
    int i, stop = 0, printed = 0;
    for (i = 0; i < 32; i++) {
        if (!cur || (cur & 7u)) { stop = 1; break; }               // 未对齐
        unsigned long long hdr[2] = { 0, 0 };
        if (!za_sync_read(hdr, cur, sizeof hdr)) { stop = 2; break; }  // 不可读
        unsigned long long next = hdr[0], lr = hdr[1];
        int in_img = za_sync_in_image(lr);
        if (in_img) {
            extern unsigned char *za_guest_base;
            unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
            if (lr >= mb && lr < mb + ZA_IMAGE_SIZE)
                ZLOGI("        [%d] fp=%#llx lr=main+%#llx", i, cur, lr - mb);
            else
                ZLOGI("        [%d] fp=%#llx lr=sdk+%#llx", i, cur, lr - za_sdk_base);
            printed++;
        } else {
            ZLOGI("        [%d] fp=%#llx lr=%#llx（不在映像内，链在此断）", i, cur, lr);
            stop = 5;
            break;
        }
        // 只有当前帧的 lr 合法才继续往上走
        if (next <= cur) { stop = 3; break; }                     // 必须向高地址
        if (next - cur > 0x100000ull) { stop = 4; break; }        // 跨度异常
        prev = cur;
        cur = next;
    }
    if (!printed) {
        ZLOGI("      （fp 链解不动：fp=%#llx stop=%d）→ 退回扫栈", fp, stop);
        if (sp) za_sync_scan_chain(sp, "fp 链失败");
    } else {
        ZLOGI("      ↑ fp 链共 %d 帧（stop=%d，起点 fp=%#llx，末帧 fp=%#llx）",
              printed, stop, fp, prev ? prev : fp);
    }
}


// za_horizon.c：按 tid 倒出 svc 环形记录（阻塞中的那条 ret 是哨兵 0xdead）
void za_dump_ret_ring_for(long tid);

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif

#define ZA_WAITERS_BIT 0x40000000u
#define ZS_MAX 64                 // 同时等待的线程上限
#define ZS_SLICE_NS 5000000L      // 5ms 分片（等锁用）
// 条件变量的「无限等待」分片：返回越频繁，SDK 重判条件的开销越大；
// 太长又会拖慢丢唤醒的恢复。20ms 是旧实现验证过的值。
#define ZS_CV_SLICE_NS 20000000L  // 20ms

typedef struct {
    volatile long tid;            // 0 = 空闲槽
    volatile int kind;            // 0=空闲, 1=等锁, 2=等条件变量
    volatile int granted;         // 1 = 锁已交接给我
    volatile unsigned int futex;  // 唤醒字
    unsigned long long addr;      // 锁地址
    unsigned long long key;       // 条件键地址
    unsigned int tag;             // 我的 tag
    unsigned long long gsp, gpc;  // 进 svc#28 时的客机 sp / x30（等待点调用链用）
    unsigned long long gfp;       // 进 svc#28 时的客机 x29（真正的帧指针）
} zs_slot_t;

static zs_slot_t zs_slots[ZS_MAX];
static volatile unsigned int zs_spin;

static void zs_lock(void)
{
    while (__atomic_exchange_n(&zs_spin, 1u, __ATOMIC_ACQUIRE))
        while (__atomic_load_n(&zs_spin, __ATOMIC_RELAXED)) { }
}
static void zs_unlock(void) { __atomic_store_n(&zs_spin, 0u, __ATOMIC_RELEASE); }

static zs_slot_t *zs_self(void)
{
    long tid = (long)syscall(SYS_gettid);
    for (int i = 0; i < ZS_MAX; i++)
        if (__atomic_load_n(&zs_slots[i].tid, __ATOMIC_ACQUIRE) == tid) return &zs_slots[i];
    for (int i = 0; i < ZS_MAX; i++) {
        long expect = 0;
        if (__atomic_compare_exchange_n(&zs_slots[i].tid, &expect, tid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return &zs_slots[i];
    }
    return &zs_slots[tid % ZS_MAX];   // 槽位用完：退回取模（可能互相干扰，但不会崩）
}

static void zs_wake(zs_slot_t *w)
{
    __atomic_add_fetch(&w->futex, 1u, __ATOMIC_RELEASE);
    syscall(SYS_futex, (int *)&w->futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL, NULL, 0);
}

// 等自己的唤醒字变化；返回 1 = 已授予，0 = 本片超时
static int zs_wait_granted(zs_slot_t *w, long long slice_ns)
{
    unsigned int seen;
    if (__atomic_load_n(&w->granted, __ATOMIC_ACQUIRE)) return 1;
    seen = __atomic_load_n(&w->futex, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&w->granted, __ATOMIC_ACQUIRE)) return 1;
    {
        struct timespec ts;
        ts.tv_sec = (time_t)(slice_ns / 1000000000LL);
        ts.tv_nsec = (long)(slice_ns % 1000000000LL);
        syscall(SYS_futex, (int *)&w->futex, FUTEX_WAIT_PRIVATE, seen, &ts, NULL, 0);
    }
    return __atomic_load_n(&w->granted, __ATOMIC_ACQUIRE) ? 1 : 0;
}

static zs_slot_t *zs_pick(int kind, unsigned long long what)
{
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (__atomic_load_n(&w->tid, __ATOMIC_RELAXED) == 0) continue;
        if (w->kind != kind) continue;
        if ((kind == 1 ? w->addr : w->key) == what) return w;
    }
    return NULL;
}

// 解锁交接：把锁字写成第一个等待者的 tag；还有别人就保留等待者位。
// 调用方必须持 zs_spin。
static void zs_handoff_locked(unsigned long long addr)
{
    zs_slot_t *w = zs_pick(1, addr);
    if (!w) {
        __atomic_store_n((unsigned int *)(uintptr_t)addr, 0u, __ATOMIC_RELEASE);
        return;
    }
    int more = 0;
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *t = &zs_slots[i];
        if (t == w) continue;
        if (__atomic_load_n(&t->tid, __ATOMIC_RELAXED) == 0) continue;
        if (t->kind == 1 && t->addr == addr) { more = 1; break; }
    }
    __atomic_store_n((unsigned int *)(uintptr_t)addr,
                     w->tag | (more ? ZA_WAITERS_BIT : 0u), __ATOMIC_RELEASE);
    __atomic_store_n(&w->granted, 1, __ATOMIC_RELEASE);
    zs_wake(w);
}

// 让 w 去拿 addr 处的锁：空闲就直接写 tag 唤醒；被占就置等待者位、转成锁等待。
// 调用方必须持 zs_spin。
static void zs_acquire_for_locked(zs_slot_t *w, unsigned long long addr, unsigned int tag)
{
    volatile unsigned int *lock = (volatile unsigned int *)(uintptr_t)addr;
    unsigned int v = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
    for (int guard = 0; guard < 100000; guard++) {
        if (v == 0) {
            if (__atomic_compare_exchange_n(lock, &v, tag, 0, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&w->granted, 1, __ATOMIC_RELEASE);
                zs_wake(w);
                return;
            }
            continue;
        }
        if (__atomic_compare_exchange_n(lock, &v, v | ZA_WAITERS_BIT, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    w->kind = 1;
    w->addr = addr;
    w->tag = tag;
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
}

unsigned long za_sync_arbitrate_lock(unsigned int owner, unsigned long long addr, unsigned int tag)
{
    volatile unsigned int *lock = (volatile unsigned int *)(uintptr_t)addr;
    zs_slot_t *w;
    if (!addr) return 0;
    w = zs_self();
    zs_lock();
    {
        unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        // ★ 已经是自己持有（递归进入 / 陈旧状态）：立刻返回。
        //   不判这一条会**自己睡死**——锁字是自己的 tag 时没有任何人会再交接。
        //   （旧实现里就有这条早退，改写时漏掉了。）
        if ((cur & ~ZA_WAITERS_BIT) == tag) {
            zs_unlock();
            return 0;
        }
        // ★ 2026-10-28 真机：主线程卡在 word=0x656c6261（ASCII "able"）的「锁」上
        //   —— 客机把一段文本缓冲当成 mutex 传进来了。这种字永远不会有人 unlock，
        //   永久阻塞就等于整条线死掉。Horizon 的 tag 是线程句柄（小整数，实测
        //   ≤ 0x13），所以 owner 超出合理范围就当成「未被占用」，直接取走。
        if (cur == 0) {
            __atomic_store_n(lock, tag, __ATOMIC_RELEASE);
            zs_unlock();
            return 0;
        }
        if ((cur & ~ZA_WAITERS_BIT) > 0xffffu) {
            static int nbad;
            if (nbad++ < 6)
                ZLOGE("svc#26 锁字不可信 lock=%p word=%#x ⇒ 直接取走（不阻塞）",
                      (void *)lock, cur);
            __atomic_store_n(lock, tag, __ATOMIC_RELEASE);
            zs_unlock();
            return 0;
        }
        if (cur != (owner | ZA_WAITERS_BIT)) {
            zs_unlock();
            return 0;
        }
        w->kind = 1;
        w->addr = addr;
        w->tag = tag;
        __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
        // ★ 诊断：锁字的高位像 ASCII 的可打印字符 ⇒ 这把「锁」其实是一段文本。
        //   真机实测 word=0x656c6261 = "able"，指向客机栈上的字符串缓冲，
        //   说明客机把某个结构体当成锁在用（或者栈上的锁被文本覆盖了）。
        //   把这 0x100 字节按文本倒出来，就能直接看到那条消息。
        if ((cur >> 24) >= 0x20u && (cur >> 24) <= 0x7eu) {
            static int n;
            if (n < 4) {
                n++;
                ZLOGE("★ 锁字像 ASCII：lock=%p word=%#x，附近 0x100 字节：", (void *)lock, cur);
                const char *p2 = (const char *)lock - 0x40;
                for (int i = 0; i < 0x100; i += 0x40) {
                    char line[160];
                    int k = 0;
                    for (int j = 0; j < 0x40 && k < (int)sizeof line - 2; j++) {
                        unsigned char c = (unsigned char)p2[i + j];
                        line[k++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
                    }
                    line[k] = 0;
                    ZLOGE("    +%#04x |%s|", i - 0x40, line);
                }
            }
        }
    }
    zs_unlock();
    {
        int slices = 0;
        unsigned int first_word = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        for (;;) {
            if (zs_wait_granted(w, ZS_SLICE_NS)) break;
            // ★ 陈旧持有者兜底：锁字 1 秒都没变过 ⇒ 持有者已经退出、或者它自己
            //   卡在别的等待里（实测：等锁线程 tag=0x9，锁字 0x40000045，
            //   持有者 tag 0x45 在等待表里根本不存在）。强制取得并报一次，
            //   宁可短暂破坏互斥也不能让整条线永久停摆。
            {
                unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
                if (cur != first_word) { first_word = cur; slices = 0; }
            }
            // 分片超时：持有者可能走了用户态快路径直接清零（不发 svc#27）。
            // 这种情况我们自己抢下来，否则会永久睡死。
            {
                unsigned int expect = 0;
                if (__atomic_compare_exchange_n(lock, &expect, tag, 0, __ATOMIC_ACQ_REL,
                                                __ATOMIC_ACQUIRE))
                    break;
                if ((expect & ~ZA_WAITERS_BIT) == tag) break;   // 已经是自己
            }
            // ★ 兜底：1 秒还没拿到 ⇒ 视为陈旧（持有者线程可能已退出）。
            //   强制取得并报一次 —— 宁可破坏互斥也不能让整条线永久卡死。
            if (++slices >= 200) {
                static int nforce;
                unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
                if (nforce++ < 8)
                    ZLOGE("svc#26 1s 未交接 lock=%p word=%#x me=%u ⇒ 强制取得", (void *)lock,
                          cur, tag);
                __atomic_store_n(lock, tag, __ATOMIC_RELEASE);
                break;
            }
        }
    }
    zs_lock();
    w->kind = 0;
    zs_unlock();
    return 0;
}

unsigned long za_sync_arbitrate_unlock(unsigned long long addr)
{
    if (!addr) return 0;
    zs_lock();
    zs_handoff_locked(addr);
    zs_unlock();
    return 0;
}

unsigned long za_sync_wait_key(unsigned long long addr, unsigned long long key, unsigned int tag,
                               long long ns)
{
    volatile unsigned int *lock = (volatile unsigned int *)(uintptr_t)addr;
    volatile unsigned int *cond = (volatile unsigned int *)(uintptr_t)key;
    zs_slot_t *w;
    if (!addr || !key) return 0;
    w = zs_self();
    zs_lock();
    // ① 先登记条件键。★ *cv 是**等待者计数**，不是布尔量：
    //    SDK 的 SignalConditionVariable 先读 *cv，为 0 就整条 svc#29 都不发。
    //    以前这里 store 写 1 ⇒ 同一键上有两个等待者时计数永远是 1，信号唤醒
    //    一个就把 *cv 清 0，剩下的等待者再也收不到信号
    //    （真机现象：每秒都要靠看门狗伪唤醒才往前走一步）。
    __atomic_add_fetch(cond, 1u, __ATOMIC_ACQ_REL);
    w->kind = 2;
    w->addr = addr;
    w->key = key;
    w->tag = tag;
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
    // ② 放锁（交给下一个等待者），③ 再睡 —— 顺序不能反
    zs_handoff_locked(addr);
    zs_unlock();
    {
        long long deadline = 0;
        if (ns >= 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline = (long long)now.tv_sec * 1000000000LL + now.tv_nsec + ns;
        }
        for (;;) {
            long long slice = (ns < 0) ? ZS_CV_SLICE_NS : ZS_SLICE_NS;
            if (ns >= 0) {
                struct timespec now;
                long long left;
                clock_gettime(CLOCK_MONOTONIC, &now);
                left = deadline - ((long long)now.tv_sec * 1000000000LL + now.tv_nsec);
                if (left <= 0) break;
                if (left < slice) slice = left;
            }
            if (zs_wait_granted(w, slice)) break;
            // ★ 2026-10-27：**无限等待也按分片返回**（不是一直睡下去）。
            //   根因：SDK 的信号方在用户态先读 `*cv`，为 0 就直接返回、不发
            //   svc#29；而等待方把 `*cv = 1` 是在进入 svc#28 之后。两者之间存在
            //   「信号早于登记」的窗口 ⇒ 这次唤醒永久丢失。
            //   （实测：16 个线程全睡死，对它们做一次伪唤醒后游戏立刻继续建纹理。）
            //   内核靠等待队列原子性避免了这个窗口，用户态近似做不到；
            //   返回后 SDK 会重判条件，所以**有界等待 + 伪唤醒**是安全的。
            if (ns >= 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (deadline <= (long long)now.tv_sec * 1000000000LL + now.tv_nsec) break;
            }
            // 无限等待：继续睡（保持正确交接）。丢唤醒由看门狗的「伪唤醒」兜底
            // —— 实测每 1 秒无 svc 推进时对全部等待者伪唤醒一次即可让游戏继续。
        }
    }
    zs_lock();
    {
        // 自己退出（超时/被伪唤醒）时撤销登记；被信号唤醒的那条路径已经减过
        // （它先把 kind 置 0）。不撤销会让 *cv 只增不减，SDK 也会跟着空转。
        int was_cv = (w->kind == 2);
        w->kind = 0;
        if (was_cv && cond) {
            unsigned cur = __atomic_load_n(cond, __ATOMIC_RELAXED);
            while (cur && !__atomic_compare_exchange_n(cond, &cur, cur - 1, 0,
                                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) { }
        }
    }
    zs_unlock();
    return 0;
}

// 等待表快照（看门狗/崩溃诊断用）：谁在等哪把锁/哪个条件键。
// 记录「进等待时的客机 sp / x30」——等待表里据此扫栈找客机返回地址。
// svc#52 WaitForAddress 的等待者：登记进同一张表，让看门狗的伪唤醒够得着。
// 这条路径以前完全在表外 —— 真机实测卡住时有线程睡在这里，而看门狗只看到
// 「0 个/1 个线程」，伪唤醒打不到它。
void za_sync_note_addr_wait(unsigned long long addr, unsigned int value, int type,
                            unsigned long long sp, unsigned long long pc,
                            unsigned long long fp)
{
    zs_slot_t *w = zs_self();
    if (!w) return;
    w->kind = 3;
    w->addr = addr;
    w->key = 0;
    w->tag = (unsigned int)value;
    w->gsp = sp;   // ★ 真正的客机 sp（以前这里存的是 type，导致扫栈永远 0 帧）
    w->gpc = pc;   // 调用方客机 pc：谁在等这个地址
    w->gfp = fp;   // 调用方 x29：fp 链回溯的起点
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
}

void za_sync_addr_wait_done(void)
{
    zs_slot_t *w = zs_self();
    if (!w) return;
    if (w->kind == 3) w->kind = 0;
}

void za_sync_note_guest(unsigned long long sp, unsigned long long pc,
                        unsigned long long fp)
{
    zs_slot_t *w = zs_self();
    w->gsp = sp;
    w->gpc = pc;
    w->gfp = fp;
}

void za_sync_dump_chain_for(long tid)
{
    zs_slot_t *w = NULL;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++)
        if (__atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED) == tid) { w = &zs_slots[i]; break; }
    unsigned long long sp = w ? w->gsp : 0, pc = w ? w->gpc : 0;
    unsigned long long fp = w ? w->gfp : 0;
    int kind = w ? w->kind : 0;
    zs_unlock();
    ZLOGI("      主线程链（tid=%ld kind=%d sp=%#llx fp=%#llx）：", tid, kind, sp, fp);
    // 没有 fp（主线程的门不写槽）：在它自己的栈区里反向重建 x29 链。
    if (!fp) {
        extern const za_stack_region_t *za_stack_find(long tid);
        const za_stack_region_t *sr = za_stack_find(tid);
        if (sr && sr->hi > sr->lo) {
            ZLOGI("      （无 fp ⇒ 反向重建栈区 [%#lx,%#lx)）", sr->lo, sr->hi);
            za_sync_recover_chain((unsigned long long)sr->lo, (unsigned long long)sr->hi);
        } else {
            ZLOGI("      （无 fp，且找不到栈区）");
        }
    }
    if (pc) za_sync_print_addr("客机等待点 x30", pc);
    if (fp) za_sync_dump_guest_chain(fp, sp, 0);
}

// 找出「谁还可能握着这个地址」：扫描所有已登记客机线程的栈，
// 看哪条栈上出现过该锁地址。持有者一定在某个 callee-saved 寄存器
// （x19..x28）里拿着它，而它们在 prologue 里都会被溢出到帧内。
void za_sync_scan_for_addr(unsigned long long val)
{
    if (!val) return;
    // ① 锁对象本身：把 ±0x40 打出来。nn::os 的互斥对象里除了锁字还有
    //    内部临界区、计数器和**持有者记录**，靠它能直接认出持有者。
    {
        unsigned char raw[0x80];
        if (za_sync_read(raw, val - 0x40, sizeof raw)) {
            ZLOGI("      ★ 锁对象 %#llx ±0x40：", val);
            for (int r = 0; r < 8; r++)
                ZLOGI("        %+#04x: %02x %02x %02x %02x %02x %02x %02x %02x"
                      "  %02x %02x %02x %02x %02x %02x %02x %02x",
                      r * 16 - 0x40,
                      raw[r*16+0], raw[r*16+1], raw[r*16+2], raw[r*16+3],
                      raw[r*16+4], raw[r*16+5], raw[r*16+6], raw[r*16+7],
                      raw[r*16+8], raw[r*16+9], raw[r*16+10], raw[r*16+11],
                      raw[r*16+12], raw[r*16+13], raw[r*16+14], raw[r*16+15]);
        } else {
            ZLOGI("      ★ 锁对象 %#llx 不可读", val);
        }
    }
    int hits = 0;
    for (int i = 0; i < ZS_MAX; i++) {
        long t = __atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED);
        if (!t) continue;
        const za_stack_region_t *sr = za_stack_find(t);
        if (!sr || sr->hi <= sr->lo) continue;
        unsigned long long hi = (unsigned long long)sr->hi;
        unsigned long long lo = hi - 0x40000ull;      // 栈顶 256KB
        if (lo < (unsigned long long)sr->lo) lo = (unsigned long long)sr->lo;
        static unsigned char b2[4096 + 8];
        int found = 0;
        for (unsigned long long a = lo; a < hi && found < 3; ) {
            size_t len = (size_t)((hi - a) < 4096 ? (hi - a) : 4096);
            if (!za_sync_read(b2, a, len)) { a += 4096; continue; }
            for (size_t o = 0; o + 8 <= len; o += 8) {
                unsigned long long x;
                memcpy(&x, b2 + o, 8);
                if (x == val) {
                    ZLOGI("      ↳ tid=%ld 栈上出现该锁地址（%#llx，距栈顶 %+#llx）",
                          t, a + o, (unsigned long long)(a + o) - hi);
                    found++;
                    hits++;
                    if (found >= 3) break;
                }
            }
            a += len;
        }
        if (found) {
            // 这条线程自己此刻在等什么（kind=1 等锁 / 2 等条件变量 / 3 等地址）
            if (zs_slots[i].kind)
                ZLOGI("        ↳ 它的等待：kind=%d lock=%#llx key=%#llx tag=%#x",
                      zs_slots[i].kind, zs_slots[i].addr, zs_slots[i].key,
                      zs_slots[i].tag);
            else
                ZLOGI("        ↳ 它**没有**在等待表里（kind=0）⇒ 可能正是它持有锁");
            za_dump_ret_ring_for(t);
        }
    }
    ZLOGI("      ↳ 全线程栈扫描：%d 处命中", hits);
}

void za_sync_dump(void)
{
    long tid[ZS_MAX];
    int kind[ZS_MAX], granted[ZS_MAX];
    unsigned long long addr[ZS_MAX], key[ZS_MAX];
    unsigned int tag[ZS_MAX], word[ZS_MAX];
    unsigned long long gsp[ZS_MAX], gpc[ZS_MAX], gfp[ZS_MAX];
    int n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        if (!__atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED)) continue;
        if (zs_slots[i].kind == 0) continue;   // 已经不在等了（stale 槽位）
        tid[n] = zs_slots[i].tid;
        kind[n] = zs_slots[i].kind;
        granted[n] = zs_slots[i].granted;
        addr[n] = zs_slots[i].addr;
        key[n] = zs_slots[i].key;
        tag[n] = zs_slots[i].tag;
        word[n] = 0;
        if (addr[n]) {
            unsigned int wv = 0;
            if (za_sync_read(&wv, addr[n], 4)) word[n] = wv;
        }
        gsp[n] = zs_slots[i].gsp;
        gpc[n] = zs_slots[i].gpc;
        gfp[n] = zs_slots[i].gfp;
        n++;
    }
    zs_unlock();
    ZLOGI("sync 等待表（%d 个线程）：", n);
    for (int i = 0; i < n; i++)
    {
        ZLOGI("    tid=%ld kind=%d granted=%d lock=%#llx(word=%#x) key=%#llx tag=%#x pc=%#llx",
              tid[i], kind[i], granted[i], addr[i], word[i], key[i], tag[i], gpc[i]);
        if (kind[i] != 2 || i < 6) za_dump_ret_ring_for(tid[i]);   // 它最后几条 svc
        // 客机侧调用链：x30 + 沿 x29 链逐帧回溯（无 fp 时才退回扫栈）
        if (kind[i] != 2 && i < 8 && (gfp[i] || gsp[i]))
            za_sync_dump_guest_chain(gfp[i], gsp[i], gpc[i]);
        else if (kind[i] == 2 && i < 4 && (gfp[i] || gsp[i]))
            za_sync_dump_guest_chain(gfp[i], gsp[i], gpc[i]);
        // ★ 锁对象前后的内存：nn::os 的 EventType 是「若干状态字节 + 计数器 +
        //   临界区 + 两个条件变量」，cs/cv 的相对位置固定。把它打出来才能找到
        //   `signaled` 那一字节 —— 如果它一直是 0，就说明游戏在等一个
        //   永远不会被信号的事件（最可疑：vi 的 vsync）。
        if (kind[i] == 2 && i < 2 && addr[i]) {
            unsigned char raw[0x60];
            if (za_sync_read(raw, addr[i] - 0x20, sizeof raw)) {
                for (int r = 0; r < 6; r++)
                    ZLOGI("      lock%+03x: %02x %02x %02x %02x %02x %02x %02x %02x"
                          "  %02x %02x %02x %02x %02x %02x %02x %02x",
                          r * 16 - 0x20,
                          raw[r * 16 + 0], raw[r * 16 + 1], raw[r * 16 + 2], raw[r * 16 + 3],
                          raw[r * 16 + 4], raw[r * 16 + 5], raw[r * 16 + 6], raw[r * 16 + 7],
                          raw[r * 16 + 8], raw[r * 16 + 9], raw[r * 16 + 10], raw[r * 16 + 11],
                          raw[r * 16 + 12], raw[r * 16 + 13], raw[r * 16 + 14], raw[r * 16 + 15]);
            }
        }
    }
}


// 对所有条件变量等待者做一次**合法伪唤醒**（ConditionVariable 本来就允许
// 伪唤醒，调用方会重判条件）。用途：
//   · 诊断：如果游戏在伪唤醒后继续推进，说明卡住的原因是「丢了一次唤醒」；
//   · 兜底：真机上所有线程都睡死时，不让整个进程永久停摆。
// 做法与 svc#29 相同：先把条件键置 1（SDK 的信号方按 *cv != 0 才发 svc），
// 再把锁交给等待者。
unsigned za_sync_poke_all(void)
{
    unsigned n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (__atomic_load_n(&w->tid, __ATOMIC_RELAXED) == 0) continue;
        if (w->kind == 3) {
            // WaitForAddress：直接在它等的那个字上做 futex 唤醒（合法伪唤醒，
            // 调用方本来就会重判条件）。
            if (w->addr) syscall(SYS_futex, (int *)(uintptr_t)w->addr, FUTEX_WAKE_PRIVATE,
                                 0x7fffffff, NULL, NULL, 0);
            w->kind = 0;
            n++;
            continue;
        }
        if (w->kind != 2) continue;
        // ★ 伪唤醒也要**递减等待者计数**：以前这里只把 kind 清 0 并往 *cv 写 1，
        //   而退出路径靠 `kind == 2` 判断要不要减 —— 被 poke 过的槽位从此不再递减，
        //   *cv 只增不减。SDK 的 SignalConditionVariable 先读 *cv 决定要不要发
        //   svc#29，计数虚高会让它一直以为「还有人在等」，而真正的等待者已经
        //   被我们自己唤醒过一轮 ⇒ 主线程等的那个键永远等不到有效信号。
        if (w->key) {
            unsigned int *cv = (unsigned int *)(uintptr_t)w->key;
            unsigned int cur = __atomic_load_n(cv, __ATOMIC_RELAXED);
            while (cur && !__atomic_compare_exchange_n(cv, &cur, cur - 1, 0,
                                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) { }
        }
        w->kind = 0;
        zs_acquire_for_locked(w, w->addr, w->tag);
        n++;
    }
    zs_unlock();
    return n;
}

unsigned long za_sync_signal_key(unsigned long long key, int count)
{
    volatile unsigned int *cond = (volatile unsigned int *)(uintptr_t)key;
    if (!key) return 0;
    zs_lock();
    for (int n = 0; count <= 0 || n < count; n++) {
        zs_slot_t *w = zs_pick(2, key);
        if (!w) break;
        w->kind = 0;                       // 不再是条件等待者（可能变成锁等待）
        {   // *cv 是等待者计数：每唤醒一个减一
            unsigned cur = __atomic_load_n(cond, __ATOMIC_RELAXED);
            while (cur && !__atomic_compare_exchange_n(cond, &cur, cur - 1, 0,
                                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) { }
        }
        zs_acquire_for_locked(w, w->addr, w->tag);
    }
    if (!zs_pick(2, key))
        __atomic_store_n(cond, 0u, __ATOMIC_RELEASE);
    zs_unlock();
    return 0;
}
