# Horizon IPC 协议 —— 真机实测 + 静态逆向结论（2026-10-25）

本文件记录**在小米平板真机（25079RPDCC）上实测** + 对 SDK NSO
静态逆向得到的 Horizon IPC 机制。所有结论都有实机日志/反汇编支撑，不要凭直觉改。

SDK NSO = `entry_32848007`，装载基址 `0x200000000`。
下文 `SDK+X` 一律指 **SDK 映像内偏移**（不是绝对地址）。

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

反汇编 `SDK+0x10be2c`（`nn::sf::hipc` 的派发函数）：

```
0x10be4c: mov  x19, x4            ; a4 = 一个 Object** 槽
0x10bf94: ldr  x0, [x19]          ; x0 = *a4  ← SDK 刚建好的 IPC 对象指针
0x10bf98: cbz  w23, <无出参分支> ; w23 = SFCO 槽 +0x20 的 token
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
0x3c46a8: ldr  x8, [x8, #8]      ; ← SIGSEGV
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

## 3. ★★ CMIF 应答的完整布局（2026-10-25 静态逆向闭合）

### 3.1 槽位怎么算

应答槽 = `align16(base + idx*4 + 15)`，其中 `base` = 应答缓冲（= 请求缓冲，同一块），
`idx` 由**应答头**算出（两条路径的解码器不同，但写出的 out struct 布局一致）：

* 路径 B：`SDK+0x9a81c`（`out` 结构在 sp+0x8，idx 取 `out[0x27]`）
* 路径 A：`SDK+0xc4b68`（`out` 结构在 sp+0x78，idx 取 `out[0xaf]`）

`idx` 的精确公式（`SDK+0x9a8f0`）：

```
b4 = (word0 >> 20) & 0xF      ; = out[0x0c] 的低字节
b5 = (word0 >> 24) & 0xF      ; = out[0x0d] 的低字节
b6 = 0                        ; out[0x0e] 被 strb 强制清 0
U16 = (word1 & 0x3FF) << 2   ; = out[0x10] & 0xffff

idx = 0                        ; 当 U16 == 0（word1 低 10 位全 0）
idx = 2 + 3*b4 + 3*b5 + 3*b6  ; 当 U16 != 0
```

⇒ **idx 只能取 2、5、8、11…（≡2 mod 3）**。
`idx=2` ⇒ 槽 = base+0x10；`idx=5` ⇒ 槽 = base+0x20。

### 3.2 两条路径读哪些字段

| 槽内偏移 | 路径 A（`SDK+0x14eb28`） | 路径 B（`SDK+0x10be2c` / `SDK+0xc637c`） |
|---|---|---|
| +0x00 | u32 `"SFCO"` | 不读 |
| +0x08 | u32 Result（必须 0） | 不读 |
| +0x10 | u16 命令返回 | u32 `"SFCO"` |
| +0x18 | 不读 | u64 Result（必须 0） |
| +0x20 | 不读 | u32 **token（非 0）** |

### 3.3 ★ 统一律：SFCO 魔数的落点 == 请求侧 SFCI 魔数的落点

两套框架的 SFCI 描述符布局本就不同（路径 A 的魔数在描述符 +0x00，路径 B 在 +0x10），
所以 SFCO（= SFCI 的镜像）在槽内的相对偏移也跟着变。

> **⇒ 宿主只要「照着请求里 SFCI 的位置写 SFCO」就同时覆盖两条路径。**

实测对照（真机日志）：

| 请求头 | SFCI 位置 | 路径 | 描述符字 |
|---|---|---|---|
| `07 00 00 00 08 00 00 00 20 00`（cmd=0x7） | ro+0x10 | A | `[0x00]=7`（不是描述符字） |
| `06 00 00 00 0c 00 00 00 20 00`（cmd=0x6） | ro+0x20 | B | `[0x10]=0x00100001` |

**路径判定**（`za_horizon.c` 用）：看 `[SFCI-0x10]` 是不是描述符字
`0x00180001`（取子对象）或 `0x00100001`（普通命令）：

* 是 ⇒ **路径 B** ⇒ `SFCI+0x10` 处要写 **token（非 0）**
* 否 ⇒ **路径 A** ⇒ `SFCI+0x10` 处是「u16 命令返回」，应当写 **0**

### 3.4 ★★★ token：pctl 崩溃的真正原因

`SDK+0x10bf98`：

```
cbz  w23, <无出参分支>   ; w23 = 槽+0x20 = token
```

* `token == 0` ⇒ SDK 走「无出参」分支 ⇒ **它自己把出参指针清 0**
  ⇒ `SDK+0x3fcaac` 把 NULL 写进全局 `SDK+0xc024b8`
  ⇒ 下一次 `SDK+0x3fcbf4` 对 NULL 解引用 ⇒ **SIGSEGV**
* `token != 0` ⇒ 出参代理被激活并交付出参指针 ⇒ 一切正常

SDK **不校验** token 的值，只把它原样回填进下一次请求的 `SFCI+0x04`
（`SDK+0xc637c`：`ldr w23,[x0,#0x10]` → `stp w8,w23,[x20]`）。
⇒ 宿主可以自由取值，只要**非 0**。

真机日志里能看到回环：请求 `[0x04]` 出现了我们上次写的 token 值。

### 3.5 ⚠「出参」不是从应答里取的一段数据

出参**不是**应答缓冲里的一段字节。`SDK+0x3fcf58` 在**发请求之前**就预建好
56 字节的 CmifProxy 出参代理对象：

```
3fcf7c: mov  w1, #0x38          ; 56 字节
3fcf90: blr  x8                 ; 分配
3fcfac: ldr  x8, [x8, #0x498]   ; *(SDK+0xb75498) = base+0xB5EBA0
3fcfb0: add  x9, x8, #0x10      ; vtable address point = base+0xB5EBB0
3fcfb4: add  x8, x8, #0x3b8     ; base+0xB5EF58（代理命令描述符表）
3fcfbc: stp  x9, xzr, [x0]     ; out->+0x00 = vtable, out->+0x08 = 0
3fcfc0: str  x8, [x0, #0x20]    ; out->+0x20 = base+0xB5EF58
```

激活时（`SDK+0x10bfb4`）：

```
10bfb8: str  x20, [x0, #0x8]    ; out->+0x08 = 父客户端对象
10bfbc: str  w23, [x0, #0x10]   ; out->+0x10 = token
10bfc0: strb w8, [x0]           ; out->+0x00 = 1（激活标志）
```

⇒ **宿主不需要伪造任何 fd/handle**，出参代理复用**父客户端**的句柄。
实际业务数据由后续命令（msgid 1001–1004，`SDK+0xc637c` 一族）各自的 IPC 往返提供。

### 3.6 `SDK+0x632c30` 是什么

`0x632c30` 是 PLT 跳板（GOT 槽 `SDK+0xb78dc8`），落点
**`nn::sf::hipc::detail::HandleHipcErrorOnClient(nn::sf::Result)`**（`SDK+0x14dc50`）：

```
14dc50: adrp x8, 0xb9c000
14dc54: ldr  x1, [x8, #0x4a8]   ; 已注册的客户端错误处理器
14dc58: cbz  x1, 0x14dc64
14dc5c: and  x0, x0, #0xffffffff
14dc60: br  x1
14dc64: ret
```

它是**错误码分发器**，不是「句柄→地址转换」。宿主**不需要**为它实现任何 svc。

---

## 4. ★ 怎么解 SDK 里的 C++ vtable（可复用方法）

`.data` 里的 vtable 指针在文件里是 0，靠**重定位**填充。重定位表在
`work/nso_sdk/sdk_relocs.bin`（由 `tools/gen_sdk_tables.py` 从 SDK NSO 的
`.rela.dyn`/`.rela.plt` 生成），格式：

```
u32 count
每条 16 字节: u32 slot, u32 kind, u32 symidx, u32 addend
    kind: 0=写宿主符号地址  1=写(基址+符号值+addend)  2=写(基址+addend)  3=写0
```

用法（本次用到的例子）：

```powershell
# ① 找某个 vtable 指针槽
python work/check_sdk_relocs.py 0xb75490
#   → slot=0xb75490 kind=1 addend=0xb5ea90     ⇒ 运行时 *(SDK+0xb75490) = 基址+0xb5ea90

# ② 展开一张表（每个槽 → 它指向的东西）
python work/resolve_table.py 0xb5eaa0 10
```

**关键点**：vtable 表本身在 `.data` 里，其条目在**文件里是「模块内偏移」**，
靠 `za_sdk.c` 的 `za_sdk_relocate_base()` 加基址（规则：值落在
`[0x1000, 映像大小)` ⇒ 加基址）。所以**读文件里的原始 u64 就能拿到函数偏移**。

本次解出的三张表：

| 表 | 地址 | 说明 |
|---|---|---|
| 客户端对象 vtable | `0xb5eaa0`（= B+0x10，B=`*(SDK+0xb75490)`=0xb5ea90） | `vfunc[5]` @+0x28 = **0x3fcea4**（发请求并填出参） |
| 出参代理 vtable | `0xb5ebb0`（= `*(SDK+0xb75498)`+0x10） | `vfunc[2]`=0x3fd064（`add x0,x0,#0x20; ret`）、`vfunc[4]`=0x3fd06c |
| 命令描述符表 | `0xb5ea70` | 4 个服务名指针：`pctl` / `pctl:s` / `pctl:a` / `pctl:r` |

---

## 5. ★ svc#19 MapSharedMemory 必须真的映射（2026-10-25 新发现）

客机流程（实测反汇编 `SDK+0x143c44`）：

```
① SDK 自己的地址空间分配器（SDK+0x636f20）在 ASLR 区内挑一块空位
   ⇒ 例如 0x404b60000
② svc#19 MapSharedMemory(handle, addr, size, perm)   ← 内核要在这儿真的映射
③ SDK+0x636f30 把它登记进自己的页表
④ SDK 之后直接当这块内存存在（seqlock 读它）
```

我们以前 svc#19 是**空实现** ⇒ ②什么都没做 ⇒ ④读 0x404b60038 ⇒ SIGSEGV
（真机：pc=SDK+0x42ff34 addr=0x404b60038）。

签名（`SDK+0x1700bc` = `svc #0x13`，纯 B 型，结果在 W0）：
`MapSharedMemory(handle=x0, addr=x1, size=x2, perm=w3)`。
`svc#20 UnmapSharedMemory(handle=x0, addr=x1, size=x2)`。
`svc#21 CreateTransferMemory(out=x0, addr=x1, size=x2, perm=w3)` → 句柄在 W1。

实现要点：我们的 ASLR 区是整块 `PROT_NONE` 预留的（5GB），
所以**不能用 mmap**（那段地址已被预留映射占住），要用 **mprotect** 开口子。

---

## 6. ★ 服务存在性：哪些能拒、哪些不能拒

| 服务名 | 独立（非 applet）标题有吗 | 结论 |
|---|---|---|
| `apm`（applet manager） | **有**（真机上每个标题都有） | **不能拒** |
| `appletOE` | 没有 | 拒（返回 0x202） |
| `ae` | 没有 | 拒（返回 0x202） |

⚠ 2026-10-25 修正：我们曾把 `apm` 也拒掉 ⇒
`nn::am::GetApplicationFunctions()`（`SDK+0x1c61c0`，只是读全局 `SDK+0xbaca10`）
返回 NULL ⇒ `nn::diag::InitializeApplicationAbortObserver`（`SDK+0x349e40`）的回调
`ldr x8,[x0]` 解引用 NULL ⇒ **SIGSEGV（pc=SDK+0x349e64 addr=0x0，x1=0x2a2）**。

⇒ 我们改为给 `apm` 假句柄；并把 `nn::am::GetApplicationFunctions` 直接改写成
「返回我们自造的哑对象」（只返回 0 的空壳 vtable），见 `za_sdk.c` 第 5.6 步。

---

## 7. 已修的 bug（都曾导致 Abort(0x1a80a) / SIGSEGV）

1. **协议判定不能按句柄数值反查静态表**。
   `za_fake_svc_is_tipc()` 原来用 `g_fake_svcs[handle - base]`，
   句柄改成按调用顺序动态分配后，`ectx:aw`(0x7002) 正好撞上 `g_fake_svcs[2]="sm:m"`(TIPC)
   ⇒ 被误判 ⇒ 压根没写 "SFCO"。**必须按名字判定。**
2. **找不到 "SFCI" 时不能乱兜底**。
   有的请求 body 里根本没有 CMIF 头（例：cmd=0x2 hdr0=2 hdr1=0，
   请求里 `[0x20]` 还是我们上次写的 "SFCO" —— SDK 这次没重写魔数）。
   ⇒ 现在改成：扫不到 SFCI 就沿用**上次应答的 "SFCO" 位置**（同一个 IPC 缓冲里）。
3. **句柄数组必须 u64 或注意截断**：`unsigned int g_fake_handles[]` 存不下真实地址。
4. `ZA_SDK_EXT_SIZE` 其实是**映射总大小**，不是扩展区长度 —— 名字有误导性。
5. **不要把 "SFCO" 铺满整页**：客机 `0x14eb3c` 有 `ldrh w8,[sp,#0xb2]; cmp w8,#0x41; b.hs trap`
   的描述符合法性校验。
6. **不能往 svc#33 的 `a4` 写出参**（§1.1）——曾伪装成 MOD0 问题。
7. **SFCO 不能固定写在 +0x10**（§3.3）——必须与 SFCI 同落点。
8. **应答槽+0x20 必须写非 0 的 token**（§3.4）——写 0 会让 SDK 把出参指针清零 ⇒ 后续 NULL 解引用。
9. **svc#19 必须真的 mmap/mprotect**（§5）。
10. **不能拒 "apm"**（§6）。

---

## 8. 附：main NSO 的 MOD0（已解出，`tools/mod0.py`）

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

SDK 段布局：text `0x0..0x64e230`、rodata `0x64f000..0xb3b000`、
data `0xb3b000..0xb8f4e0`、bss `0xb8f4e0..0xc5e000`。

---

## 9. 有用的逆向工具

### `tools/`

| 脚本 | 用途 |
|---|---|
| `disasm_range.py` | 反汇编 text.bin 某段（可存文件后 grep） |
| `mod0.py` | 解 NSO 的 MOD0 头（各字段换算成映像偏移） |
| `grep_sdk_exports.py` | 按名字筛 SDK 导出符号 |
| `sdk_sym_of.py` / `sdk_sym_named.py` | 偏移 → 符号 / 名字 → 符号 |
| `sdk_callers.py` | 谁调用了某地址 |
| `sdk_plt.py` | PLT 跳板 ↔ 符号 |
| `find_const.py` | 在 text/rodata 里搜 32 位常量（找魔数/构造点） |
| `find_global_writer.py` | 找谁写了某个全局变量（⚠ 对 0xb75298 漏报，不可靠） |
| `scan_ptr_table.py` | 扫函数指针表 |
| `gen_sdk_tables.py` | 生成 SDK 的导出表/重定位表资产 |

### `work/`

| 脚本 | 用途 |
|---|---|
| `scan_global.py` | 找某全局的读写点（adrp 相对寻址） |
| `slot_calc.py` | 离线算 `za_cmif_slot_offset`（⚠ 复刻不可信，见 §3.1） |
| `find_vtable.py` | 在 rodata/data 里找「连续多个文本段代码指针」的 vtable |
| `find_reloc.py` | 在 NSO 里找 R_AARCH64_RELATIVE 重定位 |
| `check_sdk_relocs.py` | 查 SDK 重定位表里某个槽的条目 |
| `resolve_table.py` | 按重定位表展开 SDK 里的一张指针表（vtable 等） |
| `sym_at.py` | 查离某地址最近的导出符号 |
