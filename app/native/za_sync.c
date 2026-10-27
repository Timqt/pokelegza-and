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

#include "za_common.h"
#include "za_sync.h"

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
        if (cur != (owner | ZA_WAITERS_BIT)) {
            zs_unlock();
            return 0;
        }
        w->kind = 1;
        w->addr = addr;
        w->tag = tag;
        __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
    }
    zs_unlock();
    {
        int slices = 0;
        for (;;) {
            if (zs_wait_granted(w, ZS_SLICE_NS)) break;
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
void za_sync_dump(void)
{
    long tid[ZS_MAX];
    int kind[ZS_MAX], granted[ZS_MAX];
    unsigned long long addr[ZS_MAX], key[ZS_MAX];
    unsigned int tag[ZS_MAX], word[ZS_MAX];
    int n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        if (!__atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED)) continue;
        tid[n] = zs_slots[i].tid;
        kind[n] = zs_slots[i].kind;
        granted[n] = zs_slots[i].granted;
        addr[n] = zs_slots[i].addr;
        key[n] = zs_slots[i].key;
        tag[n] = zs_slots[i].tag;
        word[n] = addr[n] ? __atomic_load_n((unsigned int *)(uintptr_t)addr[n], __ATOMIC_RELAXED) : 0;
        n++;
    }
    zs_unlock();
    ZLOGI("sync 等待表（%d 个线程）：", n);
    for (int i = 0; i < n; i++)
    {
        ZLOGI("    tid=%ld kind=%d granted=%d lock=%#llx(word=%#x) key=%#llx tag=%#x",
              tid[i], kind[i], granted[i], addr[i], word[i], key[i], tag[i]);
        if (kind[i] == 2) za_dump_ret_ring_for(tid[i]);   // 它最后几条 svc
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
        if (w->kind != 2) continue;
        if (w->key) __atomic_store_n((unsigned int *)(uintptr_t)w->key, 1u, __ATOMIC_RELEASE);
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
