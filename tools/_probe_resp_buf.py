# -*- coding: utf-8 -*-
"""实现 svc#33 的 sm 应答：往客机的应答缓冲区写 "SFCO" 头。

依据（反汇编定案）
------------------
sdk+0x14eb48..0x14eb94（nn::fs 的 IPC 应答校验）：
```
14eb48  mov  w10,#0x4653
14eb4c  movk w10,#0x4f43,lsl #16   ; 0x4F434653 = "SFCO" (小端)
14eb60  ldr  w9,[x8]               ; x8 = [sp+0x90] + 索引*4，指向应答缓冲区
14eb64  cmp  w9,w10
14eb68  b.ne 0x14eb90              ; 不等
14eb90  mov  w0,#0xa80a
14eb94  movk w0,#0x1,lsl #16       ; => 0x1a80a
```
⇒ 只要应答缓冲区首字是 "SFCO"，这个校验就过。

缓冲区在哪里？
--------------
`[sp+0x90]` 在 sdk+0x14e92c 被清零，随后由 sdk+0x14ea44 `bl 0xc43f0`
（IPC 封包/解析器）填充 —— 也就是说缓冲区是**客机自己栈上的结构**，
我们拿不到指针。

所以正确做法不是猜指针，而是：**在 svc#33 时扫客机栈附近，找到那个
被 memset 成 0 的 0x120 字节请求结构并写入 SFCO**？——不可靠。

改用最稳的一步：把 svc#33 的**应答语义**补齐得太早会盲猜。
先把「客机在 svc#33 前后，栈上哪块内存是应答缓冲区」用探针确认，
再决定写哪里。本脚本只加探针，不改行为。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """        ZLOGI("svc#33 SendSyncRequest session=%#llx  ro=%p [ro+0]=%#x [ro+8] %#x->%#x  "
              "sm.cnt=%u sm.sess=%u",
              (unsigned long long)(unsigned int)a0, (void *)(uintptr_t)ro,
              pre0, pre8, post8, sm_cnt, sm_sess);"""

new = """        ZLOGI("svc#33 SendSyncRequest session=%#llx  ro=%p [ro+0]=%#x [ro+8] %#x->%#x  "
              "sm.cnt=%u sm.sess=%u",
              (unsigned long long)(unsigned int)a0, (void *)(uintptr_t)ro,
              pre0, pre8, post8, sm_cnt, sm_sess);
        // ★ 应答缓冲区定位探针
        //   sdk+0x14eb60 用 `ldr w9,[x8]` 读应答首字并与 "SFCO"(0x4F434653) 比。
        //   x8 = [sp+0x90] + idx*4，而 [sp+0x90] 在 sdk+0x14e92c 被 stp xzr,xzr 清零。
        //   我们要写的就是那块。它落在客机栈上 —— 从 svc 时的 sp 往上/下扫，
        //   找 0x120 字节全 0 的区域并打印候选，先看清楚再动手。
        {
            unsigned long gsp = za_horizon_guest_sp();
            static int n33;
            if (n33 < 6 && gsp)
            {
                n33++;
                ZLOGI("  resp-scan: guest sp=%p  head=%016llx %016llx %016llx %016llx",
                      (void *)(uintptr_t)gsp,
                      *(unsigned long long *)(uintptr_t)(gsp + 0x40),
                      *(unsigned long long *)(uintptr_t)(gsp + 0x90),
                      *(unsigned long long *)(uintptr_t)(gsp + 0xe0),
                      *(unsigned long long *)(uintptr_t)(gsp + 0x130));
            }
        }"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('resp-buffer probe added')
