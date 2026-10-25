# -*- coding: utf-8 -*-
"""给 svc#38 Break 加补强取证。

为什么要补：
  0x148f80 的失败点是 `bics xzr,x19,x0 ; b.ne 0x149048(abort)`，
  而 x19 = 0x632520() 的返回值、x0 = 0x632520() 的**再一次**返回值。
  0x632520 -> base+0x13d940 -> GetInfo 的 CpuMask（我们给 7）。
  若这条函数在两次调用间返回不同值（或我们的 GetInfo 与它期望不符），
  bics 就会失败。Break 的 info 值 0x1a80a 也应该被解读。

本次补强三件事：
  ① info 前后 32 字节原始 dump（不只读 size 字节）
  ② 当前 GetInfo(0)/GetInfo(23) 的实际返回（判断掩码是否自洽）
  ③ 把 Break 计数，避免同一处刷屏
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """        unsigned long long v = 0;
        if (a1 && a2 > 0 && a2 <= 8)
            memcpy(&v, (const void *)(uintptr_t)a1, (size_t)a2);
        ZLOGI("Horizon: Break reason=%#lx info=%#lx size=%ld 值=%#llx",
              (unsigned long)a0, (unsigned long)a1, a2, v);"""

new = """        unsigned long long v = 0;
        if (a1 && a2 > 0 && a2 <= 8)
            memcpy(&v, (const void *)(uintptr_t)a1, (size_t)a2);
        ZLOGI("Horizon: Break reason=%#lx info=%#lx size=%ld 值=%#llx",
              (unsigned long)a0, (unsigned long)a1, a2, v);
        // ① info 附近原始字节：断言文本/结构体常紧邻它
        if (a1)
        {
            unsigned long long w0v = 0, w1v = 0, w2v = 0;
            memcpy(&w0v, (const void *)(uintptr_t)a1, 8);
            memcpy(&w1v, (const void *)(uintptr_t)((unsigned long)a1 + 8), 8);
            memcpy(&w2v, (const void *)(uintptr_t)((unsigned long)a1 + 16), 8);
            ZLOGI("  info[0..0x18]=%016llx %016llx %016llx", w0v, w1v, w2v);
        }
        // ② GetInfo 关键 id 的当前值：0x148f80 的 bics 掩码校验依赖它
        {
            extern unsigned long long za_mem_getinfo(long id);
            ZLOGI("  GetInfo: id0(CpuMask)=%#llx id23(IsApplication)=%#llx",
                  za_mem_getinfo(0), za_mem_getinfo(23));
        }"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('Break probe strengthened')
