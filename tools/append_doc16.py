# -*- coding: utf-8 -*-
"""往《客机装载.md》末尾追加第 16 章（本轮定位与修复）"""
import io, os

P = r"D:\feiniukexinhome\Code\pokeLegza-and\客机装载.md"

CH = r"""
---

## 第 16 章：★ 采样器从未安装 —— 潜伏了整个移植期的致命 bug ★（2026-10-25 07:3x）

### 16.1 一句话结论

**PC 采样器的信号处理器从头到尾就没被装上过。**
`sa.sa_sigaction = za_pc_sampler` 设了，但 `sigaction()` 那一行**漏掉了**；
于是定时器信号按**默认动作（终止进程）**处理 —— 进程被信号静默带走，
**没有日志、没有 tombstone**，只在 `dumpsys activity exit-info` 里留下
一句 `reason=2 (SIGNALED) status=42`。

### 16.2 为什么是 42 而不是 32

安卓（bionic）上 **`SIGRTMIN == 42`**，不是 32：

```
ZaGuest: 定时器信号号=3f SIGRTMIN=2a SIGRTMAX=40
                        └ 63    └ 42      └ 64
```

（bionic 把 32..41 留给内部用，`SIGRTMIN` 从 42 起。
之前一直以为 `SIGRTMIN == 32`，于是「请求的信号」与「实际收到的信号」
对不上号，排查方向被带偏了好几轮。）

**教训：平台常量的数值必须**在设备上实测**并打进日志，不能靠推理。**

### 16.3 采样器信号的选择

SDK 初始化时把线程信号掩码设成 `0xffffffffbaff`（56 位），
即 **bit0..55 全挡**（只放行 SIGFPE=8 / SIGUSR1=10 / SIGALRM=14）。

| 信号 | 是否被 SDK 挡住 | 结论 |
|---|---|---|
| 32..55 | **挡** | ❌ 用不了 |
| 42 (SIGRTMIN) | 挡 | ❌ 且 bionic 内部 POSIX 定时器要用 |
| 56..63 | **不挡** | ✅ **用 63** |

⇒ 采样器改用 **信号 63**；同时给 **32..62** 装「只记录不致命」的捕获器
（`SIGRTMIN` 单独处理成 note 模式，别抢 bionic 的定时器信号），
用来抓「到底是哪个信号要了我们的命」（打印 si_code / si_pid / si_tid）。

### 16.4 同轮修掉的另外三个 bug

1. **trampoline 寄存器回写 off-by-one**
   `ldp x1,x2,[x16]` 取的是 `regs[0]/regs[1]`，而 C 侧把 Horizon 出参写在
   `regs[1]`（`ZA_REG_X1 == 1`）⇒ **客机的 x1 拿到的根本不是出参**。
   已改成 `regs[1..7]`（x0 由 C 的返回值给出，不走 regs）。

2. **`za_log_stack` 永远从 sp 的下一页开始扫**
   （原意是绕开栈溢出的保护页）⇒ **把当前帧整个跳过了** ——
   而保存 x30 的槽就在当前页里！⇒ 「ret 跳空」这类问题**根本看不到帧**。
   已改成：**先从 sp 本身 dump 64 个字**，再从下一页往上扫。

3. **QueryMemory 对未知地址谎报「Code 4KB」**
   d2r-and（已上线成品）`hle_svc.c` case 0x06 的注释原文：
   > 「原先对客体地址空间之外的地址一律回报『它所在的 4 KiB 页』，
   >   主线程栈于是被记成一页……换个环境偶发启动即中止。」

   已改成：**如实报告该地址所在的真实映射**（读 `/proc/self/maps`），
   并且优先识别宿主线程栈 ⇒ 报整段栈 + state `0x0B`。

### 16.5 新增诊断能力

| 能力 | 作用 |
|---|---|
| `ZaGuest: 真实栈边界 top=… size=… sp=…` | 客机线程的真实栈（bionic 的 256MB） |
| `ZaGuest: guest ret@+偏移 sdk+偏移` | **客机调用链回溯**（扫栈上的 main/sdk 地址） |
| `ZaGuest: x0..x30`（全部 31 个） | 原先只打 x0..x7/x29/x30，漏了 x16/x17（PLT 跳板的关键） |
| `ZaGuest: frame+偏移 …` | 当前帧的原始 64 个字 |
| `svc#6 QueryMemory addr=… -> base=… size=… state=…` | 每次 QueryMemory 的取值 |
| `ZaGuest: pc#G…` / `pc#X…` | PC 环分「可信（客机映像内）」/「不可信」两档 |

### 16.6 现在的崩溃链（已定位）

```
nn::init::Start            sdk+0x10da50   ← 我们扮演 nnrtld 调它
 └ nnosInitialize          sdk+0x145a30
    └ ThreadManager::…     sdk+0x13ed64
       └ ctor              sdk+0x14457c   ← ThreadManagerImplByHorizon
          ├ svc#6  QueryMemory @sdk+0x1445a4
          ├ svc#12 GetThreadPriority @sdk+0x1445c8
          └ svc#37 GetThreadId @sdk+0x144604
⇒ 跳空：pc=0, fault=0, x30=0
```

客机调用链（栈回溯）：
`main+0x378 → main+0x208 → main+0x1b0 → sdk+0x10da50 → sdk+0x10da88 → sdk+0x145ab8`

**已排除**：SDK 的 8 个导入全部解析成功（未解析 0）、GOT 槽全部正确
（`0xb7acf0 = 0x20013e420` = SetupThreadObjectUnsafe）、
TLS 两处补丁运行时验证通过、`#41` 只被问了 11 次（没有空转）。

### 16.7 ★ 核心未解问题：客机的 sp 跑出了线程栈 ★

```
真实栈边界：top=0x6d592c5000 size=0x10004400   （256MB + 16KB）
崩溃时    ：sp=0x6d692c9120
svc#6 时  ：sp=0x6d692c90c0
```

* 崩溃时的 sp **比栈顶高出 0x10044120 —— 正好一个栈的大小**
* 且 `svc#6` 时的 sp 比崩溃时**低 0x60（96 字节）**
* ⇒ **栈指针在 `svc #6` 之后被「抬高」了 0x60，然后落进了未映射内存**
  （`/proc/self/maps` 里查不到那个地址）
* ⇒ 0x60 = 96；trampoline 的帧是 0x70（112），**差 16（0x10）**

**下一轮的第一个抓手**：核对 trampoline 与「客机 svc 包装函数入口改写」的交互。
我们把包装函数**整个**换成了 `b 门_N`，于是包装函数里原本成对的
`str x0,[sp,#-0x10]!` / `add sp,sp,#0x10` 都不执行（净变化 0，理论平衡）；
但 trampoline 自己 `sub sp,sp,#0x70` / `add sp,sp,#0x70` 必须在**所有**路径都执行
（当前反汇编看着是对的，但要确认异常/信号打断路径不会跳过）。

### 16.8 另一个未解问题：PC 采样器没有「可信样本」

`pc#G`（落在 main/sdk 映像里的客机 PC）**一条都没有**；
采样到的 PC 全在 ART 的 boot image（`0x70e0c000-0x70e54000`，rw-p 不可执行）这类
**数据区**里 ⇒ 说明 `uc->uc_mcontext.pc` 的取值或信号投递时机仍有问题
（信号在 syscall 期间投递时，内核填的 PC 可能是返回地址而不是现场）。
⇒ 下一轮的第二个抓手：把采样器收到的 **ucontext 原始字节 + si_code** 打出来核对。

### 16.9 本轮检查清单（work/smoke/report-20261025-073143.md）

```
M1 ✅ M2 ✅ M3 ✅   M4 ❌ M5 ❌ M6 ❌      ← 卡在 M3→M4 之间
H1 ✅ H2 ✅ H3 ✅ H4 ✅ H5 ❌ H6 ✅
H7 ❌ 客机栈指针未跑飞        ← 新增，本轮最关键的健康项
H8 ❌ PC 采样器取到可信样本    ← 新增
```

顺带修掉了检查清单自身的一个 bug：`#41 按 id:` 的解析正则 `[^|]*`
会**跨行**吞掉后续内容，把下一行的 `size=10004400`（栈大小）当成调用次数
⇒ H2 误报成「1000 万次空转」。已改成 `[^\n|]*`。
"""

s = open(P, encoding="utf-8").read()
if "第 16 章" in s:
    print("已经有第 16 章了，跳过")
else:
    s = s.rstrip("\n") + "\n" + CH
    open(P, "w", encoding="utf-8", newline="\n").write(s)
    print("已追加第 16 章，文档现在 %d 字节" % os.path.getsize(P))
