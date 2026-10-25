# Horizon IPC 协议 —— 真机实测结论（2026-10-25）

本文件记录**在小米平板真机（25079RPDCC）上实测**得到的 Horizon IPC 机制。
所有结论都有实机日志/反汇编支撑，不要凭直觉改。

---

## 1. svc#33 SendSyncRequest 的参数语义

实测（`za_horizon.c` case 33 打印 a0..a7）：

| 路径 | a0 | a1 | a2 | a3 | a4 |
|---|---|---|---|---|---|
| TIPC（`sm:` 服务管理器） | 0x1 (session) | 0x200b9c59c | **0x200b3b2b8** | 0x200bebdb0 | 4 |
| CMIF（普通服务） | 0x10000 (句柄) | 0x200f00000 (ro 页) | **0x10000** | 0x10000 | 4 |
| CMIF（普通服务，第二次） | 0x10000 | 0x200f00000 | 0x10000 | 0 | **0x6d6881e1a8** |

结论：

- `a0` = session handle
- `a1` = **请求缓冲区地址**（CMIF 时 = 客机只读 TLS 页 = `TPIDRRO_EL0` 指向处）
- `a2` / `a3` = **应答缓冲区地址** ← 内核（我们）必须把应答写进 `a2`
- ⚠ `a4` = **不是出参缓冲**！见 §1.1。

### 1.1 ⚠ a4 是 SDK 的 `Object**` 槽，内核**绝对不能写**

反汇编 `SDK+0x10be2c`（`nn::hipc` 的派发函数）：

```
0x10be4c: mov  x19, x4            ; a4 = 一个 Object** 槽
0x10bf94: ldr  x0, [x19]          ; x0 = *a4  ← SDK 刚建好的 IPC 对象指针
0x10bf98: cbz  w23, <无出参分支> ; w23 = SFCO 槽 +0x20 的类型码
0x10bfc8: str  xzr, [x19]        ; ← SDK **自己**把 *a4 清零
0x10bfdc: ldr  x8, [x19]         ; 再读回来
0x10bfe0: str  xzr, [x19]
0x10bfe8: str  x8, [x25]         ; 结果写回请求描述符
```

⇒ 内核（我们）**从不**往 `a4` 写任何东西；`a4` 是 SDK 调用方的局部变量。

**踩过的坑**：我们以前往 `a4` 塞占位 `{0x0000000100000001, 0}`，正好把 SDK 刚建好的
IPC 对象指针顶掉 ⇒ SDK 拿 `0x100000001` 当对象解引用：

```
0x3c46a4: ldr  x8, [x0]          ; x0 = 0x100000001
0x3c46a8: ldr  x8, [x8, #0x8]    ; ← SIGSEGV
```

`0x100000001` = `main_base + 1`，从那里读到的 8 字节正好是 main 映像头部
（`01 00 00 00 48 80 fc 02 7c 80 fc 02`）⇒ `0x7c02fc8048000000` ⇒ 野指针。

**这一条曾伪装成「MOD0 / runtime module object 问题」，其实是我们自己写的。**

---

## 2. SDK 会把「服务句柄」当地址用 ⚠ 最重要

`GetServiceHandle` 的应答里 SDK 读的是 **u32** 句柄（`ldp w8,w0,[x20,#0xc]`），
但它随后把这个 u32 **直接当作 reply buffer 地址**传回 svc#33 的 `a2`。

实测：句柄 = 0x7000 时，SDK 直接去读 0x7000 ⇒ `SIGSEGV addr=0x7000`。

⇒ **假句柄必须是一块我们自己 mmap 出来的、真实可写的内存。**

⚠ 地址必须 **≥ 0x10000**：Linux `vm.mmap_min_addr` 默认 65536，低于它的
`mmap` 会被内核直接拒绝（实测 0x7000 映射失败，`errno=EINVAL`）。

当前实现：句柄 = `0x10000 + idx * 0x400`（每服务一块 1KB 槽，SDK 读应答的
槽位最大到 +0x3f0，服务之间不能重叠）。整块用一次 `mmap` 覆盖。

---

## 3. 应答写在哪：★ **SFCO 必须与 SFCI 同槽位**

这是本轮最关键的一条。

SDK 校验应答的两条路径：

```
路径 A（SDK+0x14eb28）
  bl   0xc4b68(out, buffer)      ; out[0x00] = buffer, out[0x1f] = idx
  ldr  x8, [out[0x00]]            ; base = buffer（= 请求缓冲 ro 页）
  ldrb w9, [out[0x1f]]
  add  x8, x8, x9, lsl #2
  add  x8, x8, #0xf
  and  x8, x8, #0xfffffffffffffff0 ; 槽位 = align16(buffer + idx*4 + 15)
  ldr  w9, [x8]                   ; ★ 槽位+0 必须 == "SFCO"
  cmp  w9, #"SFCO" ; b.ne → Abort(0x1a80a)
  ldr  w0, [x8, #0x8]             ; 槽位+8 = IPC 结果码（必须 0）
  ldrh w8, [x8, #0x10]            ; 槽位+0x10 = 命令返回（u16）

路径 B（SDK+0x10be2c）
  bl   0x9a81c(out, buffer)
  ... 槽位 = align16(base + idx*4 + 15)
  ldr  w9, [x8, #0x10]            ; ★ 槽位+0x10 必须 == "SFCO"
  ldr  x21, [x8, #0x18]           ; 槽位+0x18 = 出参句柄
  ldr  w23, [x8, #0x20]           ; 槽位+0x20 = 类型码
```

两条路径的「槽位」差 0x10（路径 B 的槽位 = 路径 A 的槽位 − 0x10），
而**两条路径算出来的 SFCO 落点完全一致**：

> **SFCO 必须写在 SDK 放 "SFCI" 请求头的同一个位置。**

⇒ 实现（`za_horizon.c` `za_write_cmif_reply`）：
**在请求缓冲里扫 "SFCI"（0x49434653），把 "SFCO" 写在同一偏移。**

实测对照：

| 请求头 | SFCI 位置 | 之前固定写 +0x10 的结果 |
|---|---|---|
| `07 00 00 00 08 00 00 00 20 00` | ro+0x10 | 通过 |
| `06 00 00 00 0e 80 00 00 01 00` | ro+0x30 | **Abort(0x1a80a)** |

⚠ 副作用（真机上同样会发生）：应答写在请求头同一位置 ⇒ **请求头被应答覆盖**。
这是内核的正常行为（请求与应答共用一块缓冲），不要去「修复」它。

⚠ `za_cmif_slot_offset()`（按 idx 复刻 `0xc4b68`+`0x9a8f0`）**不可信**：
我们复刻的 out 结构体布局与 SDK 实际布局不一致（SDK 的 `out[8..]` 是
`(u32)(x11|x10)` / `u16((x11|x10)>>32)` / `u8(x11>>48)` 三段，
不是我们拼的 `x9` + `x11|x10`）。现在只把它当「找不到 SFCI 时的兜底」。

---

## 4. 出参（返回值）：★ 当前唯一的卡点

出参**不在** `a4`，而在**应答共享内存**里；SDK 的 IPC 客户端代码
（`nn::hipc` 的虚函数）会把它取出来写进调用方的出参槽。

证据链（`SDK+0x3fc960` 一带）：

```
0x3fca04: add  x8, sp, #0x8
0x3fca08: str  xzr, [sp, #0x8]      ; 出参槽先清 0
0x3fca18: ldr  x8, [x0] ; ldr x8,[x8,#0x28] ; blr x8   ; 客户端发请求并填出参
0x3fca98: ldp  x8, x0, [sp, #0x8]    ; x8 = 出参值
0x3fcaac: str  x8, [x9, #0x4b8]     ; ★ 全局 0xc024b8 = 出参值
...
0x3fcbf0: ldr  x0, [x8, #0x4b8]     ; 再取出来当对象用
0x3fcbf4: ldr  x8, [x0]             ; ← 出参为 0 ⇒ SIGSEGV addr=0x0
```

⇒ **`SDK+0xc024b8` 就是「IPC 出参值」本身**。我们的应答从不带出参 ⇒ 出参恒 0
⇒ 这个全局恒 NULL ⇒ SDK+0x3fcbf4 崩。

⇒ 下一步要做的是：**在应答里带上出参**。
候选位置（路径 B 的读法）：`SFCO+0x08` = 出参句柄、`SFCO+0x10` = 类型码；
真正的数据在共享内存里（依赖服务管理器下发的「IPC 内存偏移表」，
真机上由 `RegisterClient` 一类的机制提供，我们目前靠「句柄 = 自己 mmap 的地址」绕过）。

---

## 5. 已修的 bug（都曾导致 Abort(0x1a80a) / SIGSEGV）

1. **协议判定不能按句柄数值反查静态表**。
   `za_fake_svc_is_tipc()` 原来用 `g_fake_svcs[handle - base]`，
   句柄改成按调用顺序动态分配后，`ectx:aw`(0x7002) 正好撞上 `g_fake_svcs[2]="sm:m"`(TIPC)
   ⇒ 被误判 ⇒ 压根没写 "SFCO"。**必须按名字判定。**
2. **找不到 "SFCI" 时不能兜底写 "SFCO"**。
   有的请求 body 里根本没有 CMIF 头（例：hdr0=0x6 hdr1=0x8，body 头是 0x00000002），
   兜底写会把请求内容覆盖掉。
3. **句柄数组必须 u64 或注意截断**：`unsigned int g_fake_handles[]` 存不下真实地址。
4. `ZA_SDK_EXT_SIZE` 其实是**映射总大小**（`mapped = (ZA_SDK_TOTAL_SIZE+0xFFF)&~0xFFF`），
   不是扩展区长度 —— 名字有误导性。
5. **不要把 "SFCO" 铺满整页**：客机 `0x14eb3c` 有 `ldrh w8,[sp,#0xb2]; cmp w8,#0x41; b.hs trap`
   的描述符合法性校验。
   （另外铺满后若整段还原 `ro[0..0x200]`，会把自己写的 SFCO 覆盖掉 —— 只能逐槽还原。）
6. **不能往 svc#33 的 `a4` 写出参**（§1.1）——曾伪装成 MOD0 问题。
7. **SFCO 不能固定写在 +0x10**（§3）——必须与 SFCI 同槽位。

---

## 6. 当前卡点（2026-10-25 第 8 轮）

IPC 层已通：**Abort(0x1a80a) 与 SIGSEGV 均消失**，SDK 连续完成 33 次 IPC，
依次拿到这些服务的句柄：

```
lm → apm(拒绝) → appletOE(拒绝) → aoc:u → ectx:aw → pctl → pctl:s → pctl:a → pctl:r
```

新崩溃：**`SDK+0x3fcbf4`，`addr=0x0`** —— 出参机制缺失（§4）。

### 附：main NSO 的 MOD0（已解出，`tools/mod0.py`）

| 项 | main (entry_0) | SDK (entry_32848007) |
|---|---|---|
| 映像大小 | 0x5f7a000 | 0xc5e000 |
| MOD0 magic 偏移 | **0x2fc8048**（= .rodata 起点 0x2fc8000 + 0x48） | 0x64f010 |
| .dynamic | 0x3cc4278 | 0xb73630 |
| .bss start / end | 0x3d7f1c0 / 0x5f79cc8 | 0xb90000 / 0xc5d3a8 |
| runtime module object (MOD0+0x18) | 0x3d7f1c8 | 0xb90008 |

main 映像头部 16 字节（NSO 模块头）：
`01 00 00 00 | 48 80 fc 02 | 7c 80 fc 02 | 00 00 00 00`
（+0 = 版本，+4 = MOD0 偏移，+8 = 0x0002fc80）

---

## 7. 有用的逆向工具（`tools/`）

| 脚本 | 用途 |
|---|---|
| `disasm_range.py` | 反汇编 text.bin 某段（可存文件后 grep） |
| `mod0.py` | 解 NSO 的 MOD0 头（各字段换算成映像偏移） |
| `sdk_sym_of.py` | 偏移 → 所属符号/函数 |
| `sdk_sym_named.py` | 名字 → 符号 |
| `sdk_callers.py` | 谁调用了某地址 |
| `sdk_plt.py` | PLT 跳板 ↔ 符号 |
| `find_const.py` | 在 text/rodata 里搜 32 位常量（找魔数/构造点） |
| `find_global_writer.py` | 找谁写了某个全局变量 |
| `scan_ptr_table.py` | 扫函数指针表 |
| `work/scan_global.py` | 找某全局的读写点（adrp 相对寻址） |
| `work/slot_calc.py` | 离线算 `za_cmif_slot_offset`（⚠ 复刻不可信，见 §3） |
