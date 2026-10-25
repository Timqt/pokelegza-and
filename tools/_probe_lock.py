# -*- coding: utf-8 -*-
"""给 ArbitrateLock(svc#26) / ArbitrateUnlock(svc#27) 加探针。

为什么：Break 现场实测
    cs: self=0xb400006fdb0ec078 owner_id=1  lockword(Break.x0)=0  match=NO
而客机在 sdk+0x1445f0 把 [x21] 的值（实测 1）写进线程对象 +0x1b0，
所以 za_current_owner_id() 应读回 1。
锁字却是 0 ⇒ 要么 ArbitrateLock 的 ptr(x1) 不是那个锁字，
要么它压根没被调用过（客户机走的是 SDK 内联快路径）。

本探针把两次调用的 (lock 指针, 锁字前后值, owner) 都记下来。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = "            unsigned int owner = za_current_owner_id();"
new = """            unsigned int owner = za_current_owner_id();
            {
                static int n26;
                if (n26 < 12)
                {
                    n26++;
                    ZLOGI("svc#26 ArbitrateLock lock=%p before=%#x owner=%u host_tid=%u",
                          (void *)lock, *lock, owner, (unsigned)syscall(SYS_gettid));
                }
            }"""
assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)

old27 = "            if (a0) __atomic_store_n((unsigned int *)(uintptr_t)a0, 0u, __ATOMIC_RELEASE);"
new27 = """            {
                static int n27;
                if (n27 < 12)
                {
                    n27++;
                    unsigned int cur = a0 ? *(unsigned int *)(uintptr_t)a0 : 0;
                    ZLOGI("svc#27 ArbitrateUnlock lock=%p before=%#x owner=%u",
                          (void *)(uintptr_t)a0, cur, za_current_owner_id());
                }
            }
            if (a0) __atomic_store_n((unsigned int *)(uintptr_t)a0, 0u, __ATOMIC_RELEASE);"""
assert s.count(old27) == 1, s.count(old27)
s = s.replace(old27, new27)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('lock probes added')
