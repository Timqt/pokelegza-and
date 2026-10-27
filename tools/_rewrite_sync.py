#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 za_horizon.c 的 svc#26..#29 换成「真正的等待队列 + 锁交接」实现。

一次性脚本（做完即弃）。做法：
  1) 在 za_horizon_svc_impl 声明之前插入等待队列基础设施；
  2) 用新的 case 26..29 替换原来的 1313..1516 行。
两处都用「锚点行号 + 断言原文」校验，改完再打印边界供人工确认。
"""
import io
import sys

PATH = "app/native/za_horizon.c"

INFRA = r'''
// ── 锁 / 条件变量的等待队列（Horizon 内核语义）─────────────────────────
// 为什么必须是真队列：svc#26/#27/#28/#29 不是四个独立的 futex 操作，而是一套
// 「锁交接 + 条件键」协议 —— 解锁/唤醒的一方必须把锁**交给**下一个等待者，
// 而不是清个标志让所有人去抢。用轮询近似会破坏 SDK 的 owner 记账：
// 32 位实现在 WaitConditionVariable 里断言 `mutex->owner == [tpidrro+0x1f8]`，
// 对不上就 nn::diag::Abort（真机实测 reason=0，进程随后被带走）。
// 语义照 d2r-and 的 dm/host/hle_thread.c（那边已在真机跑通）。
#define ZA_WAITERS_BIT 0x40000000u
typedef struct za_wait {
    struct za_wait *next;
    unsigned long long addr;   /* kind1: 锁地址；kind2: 等条件变量时也要记锁地址 */
    unsigned long long key;    /* kind2: 条件键地址 */
    unsigned int tag;          /* 本线程的锁 tag */
    int kind;                  /* 0 = 空闲, 1 = 等锁, 2 = 等条件变量 */
    int granted;               /* 1 = 已拿到锁（或已交付唤醒） */
    pthread_cond_t cv;
} za_wait_t;

static pthread_mutex_t za_sync_mtx = PTHREAD_MUTEX_INITIALIZER;
static za_wait_t *za_wait_head;

static za_wait_t *za_wait_self(void)
{
    static __thread za_wait_t *mine;
    if (!mine) {
        mine = (za_wait_t *)calloc(1, sizeof *mine);
        if (mine) pthread_cond_init(&mine->cv, NULL);
    }
    return mine;
}
static void za_wait_link(za_wait_t *w) { w->next = za_wait_head; za_wait_head = w; }
static void za_wait_unlink(za_wait_t *w)
{
    for (za_wait_t **p = &za_wait_head; *p; p = &(*p)->next)
        if (*p == w) { *p = w->next; w->next = NULL; return; }
}
static za_wait_t *za_wait_pick(int kind, unsigned long long what)
{
    for (za_wait_t *w = za_wait_head; w; w = w->next)
        if (w->kind == kind && (kind == 1 ? w->addr : w->key) == what) return w;
    return NULL;
}
/* 解锁交接：把锁字写成第一个等待者的 tag；还有别的等待者就保留等待者位。
 * 没有等待者就清零（与用户态快路径的最终状态一致）。调用方必须持 za_sync_mtx。 */
static void za_lock_handoff(unsigned long long addr)
{
    za_wait_t *w = za_wait_pick(1, addr);
    if (!w) {
        __atomic_store_n((unsigned int *)(uintptr_t)addr, 0u, __ATOMIC_RELEASE);
        return;
    }
    int more = 0;
    for (za_wait_t *t = za_wait_head; t; t = t->next)
        if (t != w && t->kind == 1 && t->addr == addr) { more = 1; break; }
    __atomic_store_n((unsigned int *)(uintptr_t)addr,
                     w->tag | (more ? ZA_WAITERS_BIT : 0u), __ATOMIC_RELEASE);
    w->granted = 1;
    pthread_cond_broadcast(&w->cv);
}
/* 让 w 去拿 addr 处的锁：空闲就直接写 tag 并唤醒；被占就置等待者位、转成锁等待。
 * 调用方必须持 za_sync_mtx。 */
static void za_lock_acquire_for(za_wait_t *w, unsigned long long addr, unsigned int tag)
{
    unsigned int v = __atomic_load_n((unsigned int *)(uintptr_t)addr, __ATOMIC_ACQUIRE);
    for (;;) {
        if (v == 0) {
            if (__atomic_compare_exchange_n((unsigned int *)(uintptr_t)addr, &v, tag, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                w->granted = 1;
                pthread_cond_broadcast(&w->cv);
                return;
            }
            continue;
        }
        if (__atomic_compare_exchange_n((unsigned int *)(uintptr_t)addr, &v,
                                        v | ZA_WAITERS_BIT, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    w->kind = 1;
    w->addr = addr;
    w->tag = tag;
    w->granted = 0;
}
'''

NEW_CASES = r'''    case 26: // ArbitrateLock(old_owner=x0, lockaddr=x1, my_tag=w2)
    {
        // 用户态快路径刚用 CAS 把锁字改成 `old_owner|等待者位`，失败了才进这里。
        // 内核只做两件事：锁字确实还是 `old_owner|等待者位` ⇒ 睡眠等交接；
        // 否则状态已经变了 ⇒ 立刻返回，让用户态自己重试。
        // ⚠ 以前这里做「阻塞 CAS + 陈旧锁强制夺取」：锁字被我们改掉、SDK 的
        //   owner 记账没跟上 ⇒ WaitConditionVariable 断言 `mutex->owner ==
        //   [tpidrro+0x1f8]` 失败 ⇒ 客机 Panic（真机实测 reason=0）。
        if (!a1) return 0;
        {
            unsigned int owner = (unsigned int)a0;
            unsigned int *lock = (unsigned int *)(uintptr_t)a1;
            za_wait_t *w = za_wait_self();
            if (!w) return 0;
            pthread_mutex_lock(&za_sync_mtx);
            if (__atomic_load_n(lock, __ATOMIC_ACQUIRE) == (owner | ZA_WAITERS_BIT))
            {
                w->kind = 1;
                w->addr = (unsigned long long)a1;
                w->tag = (unsigned int)a2;
                w->granted = 0;
                za_wait_link(w);
                while (!w->granted) pthread_cond_wait(&w->cv, &za_sync_mtx);
                za_wait_unlink(w);
                w->kind = 0;
            }
            pthread_mutex_unlock(&za_sync_mtx);
        }
        return 0;
    }
    case 27: // ArbitrateUnlock(lockaddr=x0)
        // 把锁**交给**等待队列里的第一个线程（锁字写成它的 tag；还有别人就保留
        // 等待者位），没有等待者才清零。用户态的解锁快路径只在「没有等待者位」
        // 时才走，所以走到这里的一定需要真交接。
        if (a0)
        {
            pthread_mutex_lock(&za_sync_mtx);
            za_lock_handoff((unsigned long long)a0);
            pthread_mutex_unlock(&za_sync_mtx);
        }
        return 0;
    case 28: // WaitProcessWideKeyAtomic(lockaddr=x0, condkey=x1, tag=w2, timeout=x3)
    {
        // ★ 顺序（d2r 踩过同样的坑）：**先**把条件键置 1，**再**放锁。
        //   SDK 的 SignalConditionVariable 是 `ldr w8,[cv] ; cbz w8, ret` ——
        //   *cv == 0 就根本不发 svc#29。若先放锁后置键，别的线程能在窗口里
        //   读到键为 0、改完条件、不发唤醒，本线程随后才挂上去 ⇒ 永久睡眠。
        // 超时后**不重新拿锁**（用户态自己拿）。
        if (!a0 || !a1) return 0;
        {
            unsigned int *key = (unsigned int *)(uintptr_t)a1;
            long long ns = (long long)a3;
            za_wait_t *w = za_wait_self();
            if (!w) return 0;
            pthread_mutex_lock(&za_sync_mtx);
            __atomic_store_n(key, 1u, __ATOMIC_RELEASE);
            w->kind = 2;
            w->key = (unsigned long long)a1;
            w->addr = (unsigned long long)a0;
            w->tag = (unsigned int)a2;
            w->granted = 0;
            za_wait_link(w);
            za_lock_handoff((unsigned long long)a0);
            if (ns < 0)
            {
                while (!w->granted) pthread_cond_wait(&w->cv, &za_sync_mtx);
            }
            else
            {
                struct timespec dl;
                clock_gettime(CLOCK_REALTIME, &dl);
                dl.tv_sec += (time_t)(ns / 1000000000LL);
                dl.tv_nsec += (long)(ns % 1000000000LL);
                if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
                while (!w->granted)
                    if (pthread_cond_timedwait(&w->cv, &za_sync_mtx, &dl) != 0) break;
            }
            za_wait_unlink(w);
            w->kind = 0;
            pthread_mutex_unlock(&za_sync_mtx);
        }
        return 0;
    }
    case 29: // SignalProcessWideKey(condkey=x0, count=w1)
    {
        // 唤醒 count 个（<=0 = 全部）等在这个键上的线程，并把锁交给它们：
        // 锁空闲就写 tag 唤醒，被占就转成锁等待。没有剩下的等待者时把键清零，
        // 让 SDK 的 `*cv == 0` 判断回到「没人等」。
        if (a0)
        {
            unsigned int *key = (unsigned int *)(uintptr_t)a0;
            int cnt = (int)a1, n = 0;
            pthread_mutex_lock(&za_sync_mtx);
            for (;;)
            {
                za_wait_t *w;
                if (cnt > 0 && n >= cnt) break;
                w = za_wait_pick(2, (unsigned long long)a0);
                if (!w) break;
                w->kind = 0;                    // 不再是条件等待者（可能变成锁等待）
                za_lock_acquire_for(w, w->addr, w->tag);
                n++;
            }
            if (!za_wait_pick(2, (unsigned long long)a0))
                __atomic_store_n(key, 0u, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&za_sync_mtx);
        }
        return 0;
    }
'''

src = io.open(PATH, encoding="utf-8").read().split("\n")

# ── 1) 插入基础设施：锚点 = za_horizon_svc_impl 的声明前 ──────────────
anchor = "static long za_horizon_dispatch(long a0, long a1, long a2, long a3,"
idx = [i for i, l in enumerate(src) if l.startswith(anchor)]
assert len(idx) >= 1, idx
idx = [idx[0]]        # 只取声明处（第一处），定义处不插
src.insert(idx[0], INFRA)

# ── 2) 替换 case 26..29 ────────────────────────────────────────────────
start = [i for i, l in enumerate(src) if l.lstrip().startswith("case 26: // ArbitrateLock")]
assert len(start) == 1, start
s = start[0]
assert "ArbitrateLock" in src[s], src[s]
e = [i for i in range(s, s + 400) if src[i].strip().startswith("case 29:")]
assert len(e) == 1, e
e = e[0]
# case 29 的结束：从 case 29 往后找到第一个只含 "    }" 的行（case 块闭合）
end = None
for i in range(e, e + 200):
    if src[i] == "    }":
        end = i
        break
assert end is not None, "找不到 case 29 的结尾"
assert src[end + 2].strip().startswith("// ── 地址等待"), src[end + 2]
new = NEW_CASES.rstrip("\n").split("\n")
src[s:end + 1] = new

io.open(PATH, "w", encoding="utf-8", newline="\n").write("\n".join(src))
print("patched %s: infra at line %d, cases %d..%d -> %d lines" %
      (PATH, idx[0] + 1, s + 1, end + 1, len(new)))
