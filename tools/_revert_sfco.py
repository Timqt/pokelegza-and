# -*- coding: utf-8 -*-
"""撤回「把 SFCO 写进 ro+0x10」的改动。

实测反馈（决定性）：
  写完 SFCO 后 Break 的值从 0x1a80a 变成 **0x4f434653 (=SFCO 本身)**
  ⇒ 证明那块内存确实被客机当成 **Result 字段**读走了，
    我写的位置是 Result，不是它要的「应答魔法字」位置。
  ⇒ 撤回该写入；保留 [ro+0xc]=0（Result 成功）这一条，
    因为 0x154058 `ldp w8,w0,[x20,#0xc]` 确实读 Result。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """            // ★ 上层 nn::fs 校验（sdk+0x14eb60）要求应答首字为
            //   0x4F434653 = "SFCO"；不等就 return 0x1a80a 然后 abort。
            //   落在 ro+0x10 起（客机 0x15404c 只覆盖 ro+0 与 ro+8）。
            {
                static const unsigned int sfco = 0x4F434653u;
                memcpy((void *)(uintptr_t)(ro + 0x10), &sfco, 4);
            }"""

new = """            // ⚠ 曾在这里把 0x4F434653("SFCO") 写进 ro+0x10，实测**错位**：
            //   Break 的值立刻从 0x1a80a 变成 0x4f434653 ⇒ 证明这块被客机
            //   当成 **Result** 读走（0x154058 `ldp w8,w0,[x20,#0xc]`）。
            //   所以这里只保证 Result=0，SFCO 要写在上层解析出的结构体里
            //   （sdk+0x14eb60 的 x8 = [sp+0x90] + idx*4，对齐后读首字）。"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('reverted SFCO write; kept Result=0')
