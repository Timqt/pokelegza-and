# -*- coding: utf-8 -*-
"""在 svc#33 里填最小合法 IPC 回复（命令缓冲区 = ro 页，完全可写）。

依据（反汇编实测）
------------------
命令缓冲区基址 x20 = TPIDRRO_EL0（被我们改写成 0x200f00000 = ro），
客机自写请求头后调 svc#33：
```
15401c  stp  x9, x8, [x20]        ; 请求头
154028  bl   svc#33               ; ← 我们在这里
15402c  cbz  w0, ...
15404c  str  x8, [x20]            ; 0x11|0x1<<32|0x8000<<48
154050  str  w8, [x20, #0x8]      ; 0x20
154058  ldp  w8, w0, [x20, #0xc]  ; ★ 读 [ro+0xc] 与 [ro+0x10]
```

另一处（nn::fs 上层校验，sdk+0x14eb60）：
```
14eb60  ldr  w9,[x8]              ; 应答首字
14eb64  cmp  w9,w10               ; 必须 = 0x4F434653 "SFCO"
14eb68  b.ne 0x14eb90             ; 否则 mov w0,#0xa80a ; movk #1<<16 => 0x1a80a
```

修复内容（都落在我们自己可写的 ro 页，不需要猜栈地址）
----------------------------------------------------
1. [ro+0x0c] = 0        ← IPC Result = 成功（客机 0x154058 会读它）
2. [ro+0x10] = "SFCO"   ← 上层 fs 校验的魔数（若它读的是这块）
3. 保留已有的 [ro+0x08] = 0（挂起位）

注意：这三处都是「先写、客机后读」的语义位置；客机在 0x15404c/0x154050
会覆盖 [ro+0] 与 [ro+8]，所以只写 0xc/0x10 不冲突。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """            unsigned int zero = 0;
            memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
            memcpy(&post8, (void *)(uintptr_t)(ro + 8), 4);"""

new = """            unsigned int zero = 0;
            memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
            memcpy(&post8, (void *)(uintptr_t)(ro + 8), 4);

            // ★ 命令缓冲区 = ro 页（x20 = TPIDRRO_EL0 已改写成 ro）。
            //   sdk+0x154058 会 `ldp w8,w0,[x20,#0xc]` —— [ro+0xc] 必须是
            //   IPC Result（0 = 成功），否则上层直接判失败。
            memcpy((void *)(uintptr_t)(ro + 0xc), &zero, 4);

            // ★ 上层 nn::fs 校验（sdk+0x14eb60）要求应答首字为
            //   0x4F434653 = "SFCO"；不等就 return 0x1a80a 然后 abort。
            //   落在 ro+0x10 起（客机 0x15404c 只覆盖 ro+0 与 ro+8）。
            {
                static const unsigned int sfco = 0x4F434653u;
                memcpy((void *)(uintptr_t)(ro + 0x10), &sfco, 4);
            }"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('svc#33 now writes Result=0 and "SFCO" into cmd buffer')
