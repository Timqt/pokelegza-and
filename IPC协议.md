# Horizon IPC 协议 —— 真机实测结论（2026-10-25）

本文件记录**在小米平板真机（25079RPDCC）上实测**得到的 Horizon IPC 机制。
所有结论都有实机日志/反汇编支撑，不要凭直觉改。

---

## 1. svc#33 SendSyncRequest 的参数语义

实测（`za_horizon.c` case 33 打印 a0..a7）：

| 路径 | a0 | a1 | a2 | a3 | a4 |
|---|---|---|---|---|---|
| TIPC（`sm:` 服务管理器） | 0x1 (session) | 0x200b9c59c | **0x200b3b2b8** | 0x200bebdb0 | 4 |
| CMIF（普通服务，lm） | 0x7000 (句柄) | 0x200f00000 (ro 页) | **0x7000** | 0x7000 | 4 |
| CMIF（普通服务，lm 第三次） | 0x10000 | 0x200f00000 | 0x10000 | 0 | **0x6d6881e1a8** |

结论：

- `a0` = session handle
- `a1` = **请求缓冲区地址**（CMIF 时 = 客机只读 TLS 页 = `TPIDRRO_EL0` 指向处）
- `a2` / `a3` = **应答缓冲区地址** ← 内核（我们）必须把应答写进 `a2`
- `a4` = **出参指针**（无出参时 = 4；有出参时 = 客机堆上的真实地址）← 返回值写这里

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

## 3. 应答槽位怎么算（复刻 SDK）

SDK 读应答：`SDK text 0x14eb28` 起

```
0x14eb34 bl 0xc4b68(out, buffer)     ; buffer = a2（reply buffer）
0x14eb44 ldr x8, out[0x00]           ; = buffer
0x14eb50 ldrb w9, out[0x1f]          ; idx
0x14eb54 add x8, x8, x9, lsl #2
0x14eb58 add x8, x8, #0xf
0x14eb5c and x8, x8, #~0xf           ; 槽位 = align_down_16(buffer + idx*4 + 15)
0x14eb60 ldr w9, [x8] ; cmp w9, #"SFCO"   ; 不等 ⇒ Abort(Result 0x1a80a)
```

- `idx` 由 `0x9a8f0` 从 `out[8..0x17]` 解出，而 `out[8..0x17]` 由 `0xc4b68`
  从 `buffer[0] / buffer[4] / buffer[8]` 算出 —— 已 1:1 复刻成
  `za_cmif_slot_offset()`（`app/native/za_horizon.c`）。
- 实测校验：请求 A（buffer=`07 00 00 00 08 00 00 00 20 00`）⇒ idx=10 ⇒ 槽位 +0x30；
  请求 R3（`06 00 00 00 0e 80 00 00 01 00`）⇒ idx=19 ⇒ 槽位 +0x50。
- **最容易踩的坑**：应答头必须写在 `buffer[0..0xa]`（SDK 用它算 idx）。
  我们把 `buffer[0..0xf]` 清零 ⇒ idx=2 ⇒ 槽位固定 = `buffer + 0x10`，
  自己与 SDK 用同一段内容算，必然自洽。

---

## 4. 出参（返回值）写在哪

- **不是**应答头里，而是在**独立的出参缓冲**，地址由 SDK 通过 svc#33 的 `a4` 给出
  （客机堆上的真实地址）。
- 早期误判：请求 `+0x20` 处的 `0x200f01000` 被当成出参地址，其实那是**入参**
  （它 = SDK基址 + 0xF01000，只读 TLS 页 + 0x1000），而且是用 `%08x` 打印 32 位
  才看起来像 `0x00f01000`。
- 每个方法要返回什么语义各不相同（u64 句柄 / u16 结果码 / 指针数组），
  目前统一写 `{0x0000000100000001, 0}` 占位，靠实测反应反推。

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

---

## 6. 当前卡点（2026-10-25）

IPC 层已通：lm 的 SFCO 校验不再失败，pctl 的 NULL 解引用也消除。

新的崩溃：**`SDK+0x3c46a8`（`nn::lm` 内），野指针 `addr=0x2fc8048000000`**。

```
0x2fc8048 = main NSO 的 MOD0 magic
0x2fc8048000000 = magic << 32
```

⇒ 某处把「MOD0 头里的 u32 值」当成 64 位指针的一部分 ⇒ 属于
**模块对象 / MOD0 runtime object** 的问题，与 IPC 无关。

已知线索：
- MOD0 `+0x18` 是「runtime-generated module object」的偏移，真机由 nnrtld 装载时生成
- 我们登记的模块链表：main 节点 @`0x103d7f1c8`，sdk 节点 @`0x200b90008`
- 客机 `0x3c46e8` 通过虚调用 `[vtable+0x10](0x38, 0x8)` 取对象，
  再由 `0x3c46a4: ldr x8,[x0]` / `0x3c46a8: ldr x8,[x8,#0x8]` 调虚函数 ⇒ 崩

---

## 7. 有用的逆向工具（`tools/`）

| 脚本 | 用途 |
|---|---|
| `disasm_range.py` | 反汇编 text.bin 某段（可存文件后 grep） |
| `sdk_sym_of.py` | 偏移 → 所属符号/函数 |
| `sdk_sym_named.py` | 名字 → 符号 |
| `sdk_callers.py` | 谁调用了某地址 |
| `sdk_plt.py` | PLT 跳板 ↔ 符号 |
| `find_const.py` | 在 text/rodata 里搜 32 位常量（找魔数/构造点） |
| `find_global_writer.py` | 找谁写了某个全局变量 |
| `find_reloc.py` | 查重定位槽 |
| `scan_ptr_table.py` | 扫函数指针表 |
