# -*- coding: utf-8 -*-
"""修 cs 探针的错标：Break 的 a0 是 reason（实测恒为 0），不是锁字。

上一版把 lockword 标成 Break.x0，输出恒为 0 且带「match=NO」，
纯属误导 —— 自己给自己造了一个假结论。

改为只报告能确证的事实：
  · self（读 [ro+0x1f8]）—— 实测是客机自己的线程对象（堆地址）
  · owner_id（读 [self+0x1b0]）—— 实测 1
  · za_current_owner_id() 的返回值（ArbitrateLock 用的就是这个）
  · 本线程真实 tid（svc#37 GetThreadId 返回的就是它）
三者是否一致，直接决定 Unlock 会不会 abort。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """        // ③ 临界区实况：self / owner_id / 锁字（Unlock 判定的三个输入）
        {
            unsigned long ro = (unsigned long)za_ro_tls_page;
            unsigned long self = 0;
            if (ro)
                memcpy(&self, (void *)(uintptr_t)(ro + 0x1f8), 8);
            unsigned int oid = 0, lock = 0;
            if (self)
            {
                memcpy(&oid, (void *)(uintptr_t)(self + 0x1b0), 4);
                // 锁字：Break 的 x0/a0 可能就是那个临界区对象
                if (a0)
                    memcpy(&lock, (void *)(uintptr_t)a0, 4);
            }
            ZLOGI("  cs: ro=%p self=%p owner_id=%u  lockword(Break.x0)=%#x  "
                  "match=%s  self.tid=%u",
                  (void *)(uintptr_t)ro, (void *)(uintptr_t)self, oid, lock,
                  ((lock & 0xbfffffff) == oid) ? "YES" : "NO",
                  (unsigned)syscall(SYS_gettid));
        }"""

new = """        // ③ 临界区实况：self / owner_id / 本线程 tid
        //   ⚠ 不要读 Break 的 a0 当锁字 —— a0 是 reason（恒为 0），
        //     上一版据此报「lockword=0 match=NO」是自己造的假结论。
        {
            unsigned long ro = (unsigned long)za_ro_tls_page;
            unsigned long self = 0;
            if (ro)
                memcpy(&self, (void *)(uintptr_t)(ro + 0x1f8), 8);
            unsigned int oid = 0;
            if (self)
                memcpy(&oid, (void *)(uintptr_t)(self + 0x1b0), 4);
            unsigned int mine = za_current_owner_id();
            unsigned int tid = (unsigned)syscall(SYS_gettid);
            ZLOGI("  cs: ro=%p self=%p [self+0x1b0]=%u cur_owner_id=%u host_tid=%u "
                  "consistent=%s",
                  (void *)(uintptr_t)ro, (void *)(uintptr_t)self, oid, mine, tid,
                  (oid && oid == tid) ? "YES" : "NO(以 [self+0x1b0] 为准)");
        }"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('cs probe corrected')
