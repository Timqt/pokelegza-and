# -*- coding: utf-8 -*-
"""在 Break 时把「临界区锁字 vs owner_id」的实况打出来，一次定案。

判据（反汇编实测）
------------------
Lock 入口 sdk+0x13c610：`bl 0x636760(=0x14603c IsLockedByCurrentThread)` ;
    `tbnz w0,#0, abort` —— **已持有** 才不 abort（注意方向，见下）
Unlock 入口 sdk+0x13c668：`bl 0x636760` ; `tbz w0,#0, abort` —— **未持有** 才 abort

IsLockedByCurrentThread（sdk+0x14603c）：
    mrs  x8,TPIDRRO_EL0 ; ldr x8,[x8,#0x1f8]  ; self
    ldr  w9,[x0]                              ; 锁字
    and  w9,w9,#0xbfffffff
    ldr  w8,[x8,#0x1b0]                       ; owner_id
    cmp  w9,w8 ; cset w0,eq

⇒ 只要锁字里的值 != owner_id，Unlock 就 abort。
   所以 Break 时把 self / owner_id / 锁字 全打出来，就能确定是谁没对上。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """        // ② GetInfo 关键 id 的当前值：0x148f80 的 bics 掩码校验依赖它
        {
            extern unsigned long long za_mem_getinfo(long id);
            ZLOGI("  GetInfo: id0(CpuMask)=%#llx id23(IsApplication)=%#llx",
                  za_mem_getinfo(0), za_mem_getinfo(23));
        }"""

new = """        // ② GetInfo 关键 id 的当前值：0x148f80 的 bics 掩码校验依赖它
        {
            extern unsigned long long za_mem_getinfo(long id);
            ZLOGI("  GetInfo: id0(CpuMask)=%#llx id23(IsApplication)=%#llx",
                  za_mem_getinfo(0), za_mem_getinfo(23));
        }
        // ③ 临界区实况：self / owner_id / 锁字（Unlock 判定的三个输入）
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

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('cs probe added')
