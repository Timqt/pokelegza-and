// Horizon 锁 / 条件变量的内核模拟（见 za_sync.c 顶部注释）。
// 四个入口都返回 0（SDK 对非 0 返回值会直接 throw/abort）。
#ifndef ZA_SYNC_H
#define ZA_SYNC_H

// svc#26 ArbitrateLock(owner, addr, tag)
unsigned long za_sync_arbitrate_lock(unsigned int owner, unsigned long long addr,
                                     unsigned int tag);
// svc#27 ArbitrateUnlock(addr)
unsigned long za_sync_arbitrate_unlock(unsigned long long addr);
// svc#28 WaitProcessWideKeyAtomic(addr, key, tag, timeout_ns)
unsigned long za_sync_wait_key(unsigned long long addr, unsigned long long key,
                               unsigned int tag, long long ns);
// svc#29 SignalProcessWideKey(key, count)
unsigned long za_sync_signal_key(unsigned long long key, int count);

// 对所有条件变量等待者做一次合法伪唤醒；返回被唤醒的线程数。
unsigned za_sync_poke_all(void);

// 记录进 svc#28 时的客机 sp / x30（等待点调用链用）
void za_sync_note_guest(unsigned long long sp, unsigned long long pc);
void za_sync_note_addr_wait(unsigned long long addr, unsigned int value, int type,
                            unsigned long long pc);
void za_sync_addr_wait_done(void);

// 打印等待表快照（诊断用）
void za_sync_dump(void);

#endif
