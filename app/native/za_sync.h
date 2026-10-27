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

// 打印等待表快照（诊断用）
void za_sync_dump(void);

#endif
