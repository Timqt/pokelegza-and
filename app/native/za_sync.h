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
// svc#52 WaitForAddress(addr, type, value, timeout_ns)
// type: 2 = 值等于 value 才等；0/1 = 值小于 value 才等；1 = 先减一再等。
unsigned long za_sync_wait_addr(unsigned long long addr, int type, int val, long long ns);
// svc#53 SignalToAddress(addr, type, value, count)
// type: 0 = 只唤醒；1 = 等于 value 则 +1 并唤醒；2 = 按等待者数量改值再唤醒。
unsigned long za_sync_signal_addr(unsigned long long addr, int type, int val, int count);

// 对所有条件变量等待者做一次合法伪唤醒；返回被唤醒的线程数。
unsigned za_sync_poke_all(void);

// 记录进 svc#28 时的客机 sp / x30 / x29（等待点调用链用）
// fp = 客机 x29，门桩 `str x29,[x16,#136]`（regs[17]）。调用链靠它逐帧回溯，
// 不再扫栈（扫栈会把映像内的数据指针误认成返回地址，已两次被反汇编证伪）。
void za_sync_note_guest(unsigned long long sp, unsigned long long pc,
                        unsigned long long fp);
void za_sync_note_addr_wait(unsigned long long addr, unsigned int value, int type,
                            unsigned long long sp, unsigned long long pc,
                            unsigned long long fp);
void za_sync_addr_wait_done(void);

// 打印等待表快照（诊断用）
void za_sync_dump(void);
void za_sync_dump_chain_for(long tid);
// 在所有客机线程栈里搜某个地址（找锁持有者用）
void za_sync_scan_for_addr(unsigned long long val);

#endif
