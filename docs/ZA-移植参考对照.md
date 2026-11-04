# Pokémon Legends: Z-A 移植参考对照（2026-11-04 调研）

本文只记录**可核实的、对方的原始文档里写明的**内容，用来对照我们自己的实现。
所有出处都给了文件路径或 URL。传说/视频类证据单独标注。

---

## 0. 结论先行

1. **架构判断是对的**：nx2android / nxnative 与我们同属「NSO 原样跑 + Horizon HLE +
   NVN→Vulkan/Metal 回放」，没有任何一项新技术能替代这条路线。
2. **有现成的、同一个游戏的 bring-up 记录**（nxnative 的
   `dm/games/0100F43008C44000/README.md`），逐条写了 Z-A 需要什么、踩过什么坑。
   它的 SDK 版本（19.3.11 / NVN 55）和我们是同一个。
3. **有一个现成替代品不适用于本设备**：nx2android 要求 GPU 支持 BC 压缩纹理
   （Adreno / Xclipse），我们的平板是 **Mali-G925**，README 明确排除 Mali。
4. 从对方文档里能直接落地到我们代码的**确定性 bug 有一处**（SignalToAddress
   type 2 count≤0 应写 `val-2`，我们写的是 `val-1`），另有几处**高优先级假设**
   需要真机验证（内存布局/大内存路径、NVN 状态读取、CommandBufferFenceSync）。

---

## 1. 参考工程

| 工程 | 定位 | 许可 | 状态 | 对我们可以做什么 |
|---|---|---|---|---|
| [nx2android](https://github.com/shirai91/nx2android) | NSO→Android APK 的成品工具（nxnative 的安卓版） | 见仓库 | 736★，2026-11-04 仍在推 | **只作参照**：Mali 不支持（见 §2.1）。但它的 Z-A PR [#25](https://github.com/shirai91/nx2android/pull/25) 列了 Z-A 需要的改动 |
| [nxnative](https://github.com/seedds/nxnative) | 同一架构的通用实现（iOS/Mac） | MIT（README 声明） | 活跃 | **主要参照**：`docs/reference/*` + Z-A 游戏页，是最完整的同游戏 bring-up 记录 |
| [d2r-mobile](https://github.com/jhaizhou-ops/d2r-mobile) | 移动端 HLE port 的源头（我们 dm/ 的来源） | MIT | 活跃 | 同步语义（`dm/host/hle_thread.c`）我们已对齐过（E44） |
| Eden | 安卓 Switch 模拟器（Yuzu 系） | GPL | 活跃，2026-06 稳定版 0.2.1 | 仅作「如果换路线」的备选；对 Mali 无可靠证据 |

### 1.1 为什么 nx2android 不能用在这台平板上

其 README 原文：

> These games play on Android. Tested on a Lenovo Legion Y700 (Snapdragon 8
> Elite, Adreno 830). **The device's GPU must read BC-compressed textures
> (Adreno, Xclipse; not Mali or PowerVR).**

我们的设备日志：

```
RenderEngine: renderer : Mali-G925-Immortalis MC12
```

⇒ 走 nx2android 这条路必须先换 Adreno 设备。

---

## 2. Z-A 的客观事实（来自 nxnative 的同游戏页与 profile）

### 2.1 版本与引擎

| 项 | 值 |
|---|---|
| Title ID | `0100F43008C44000` |
| 引擎 | Game Freak "Trinity" |
| SDK | **19.3.11** |
| NVN | **55** |
| 物理/动画 | Havok 2022.2 |
| 模块 | `main`、`sdk` |
| 资源 | 几乎全在 `arc/data.trpfs`（4.4 GB / 13,181 包 / 238,546 文件），索引 `arc/data.trpfd`，均为 FlatBuffers；压缩是 Oodle **Mermaid** |
| 着色器 | 28,603 个 BNSH（11,633 VS / 16,845 PS / 125 CS） |

> 我们工程里 NSP 是 `[1.0.0][19.0.0]`；nxnative 记录 1.0.0 的 `main` build
> `7222e13e…` 与 2.0.2 的 `main` 在关键函数上**指纹一致**（`nso_fnmap.py` 精确匹配），
> 且两者 `sdk` 是同一个 build（`df7a3960…`）。⇒ 1.0.0 上遇到的行为可以直接参考 2.0.2 的记录。

### 2.2 内存（**与我们差异最大的一项**）

对方原文要点：

- `nninitStartup`（`main+0x1b2e650`）调用
  `StandardAllocator::Initialize(nullptr, 0x300000000)`（**12 GB** 地址空间）。
- alias 区必须同时容纳 SDK 的 **1 GB node area** 和这块 12 GB ⇒ 共 13 GB，
  手机进程给不了 ⇒ `StandardAllocator::Initialize` 在 `nninitStartup` 里 abort。
- 他们的解法：**在宿主侧把 12 GB 请求压到 3.94 GB**（`hle_svc.c` 的
  "StandardAllocator's address space"），并把 SDK 的 node area 从 1 GB 砍到 **62 MB**。
- 最终 5 GB 布局：
  `mem_reserve 0x140000000`（5 GB）、`mem_alias 0x110000000`（4.25 GB）、
  `mem_stack 0x10000000`（256 MB）、`app_pool 0xCD500000`（3.2 GB）。
- **关键一句**：
  > `QueryMemoryInfo` reporting more than 4 GB would take the game's **big-memory
  > path** (heaps of allocatable − 4.27 GB instead of − 2.76 GB).

我们的现状（`app/native/za_mem.c`）：

```
ZA_MEM_RESERVE   = 36 GB        // 实际预留（PROT_NONE + NORESERVE）
ZA_MEM_ASLR_DECL = 64 GB        // 报给客机的 ASLR 区大小
ZA_MEM_ALIAS_CAP = 16 GB
ZA_MEM_STACK_CAP = 2 GB
ZA_MEM_HEAP_CAP  = 12 GB
ZA_MEM_APP_POOL  = 3.8 GB
```

⇒ **我们报给客机的地址空间远大于 4 GB，几乎必然触发对方的 "big-memory path"**，
  游戏会按「比 4.27 GB」的公式去要堆，而我们的实际可服务量未必跟得上。
  这与我们观察到的「加载后期一次性要 490 MB 池、随后进 SDK 致命自旋」高度吻合，
  但**尚未验证**（需要在 `QueryMemory`/`GetInfo` 处把报告值降下来做 A/B）。

### 2.3 Z-A 用到的、我们可能缺的服务/NVN 接口

对方明确列出的 SDK 19 相关项：

| 接口 | 对方的结论 | 我们 |
|---|---|---|
| `crypto::GenerateCryptographicallyRandomBytes`（csrng） | `nnMain` 第一次调用；不给字节会在 `sm::Initialize` abort | 需核对 |
| `audio::GetAudioOutBufferCount` | Wwise sink 线程空指针读；要按宿主队列回答 | 有同名符号，需核对实现 |
| `nvnColorStateGetBlendEnable` 等**状态读取** | Trinity **靠读回状态**建管线；返回 x0（地址）会让 blend/depth 全判为开 | **缺**（见 §3） |
| `nvnCommandBufferFenceSync` | 游戏**每帧**在命令缓冲里 fence 一次并等待；不实现 ⇒ 每次 `SyncWait` 立即超时 | **缺**（见 §3） |
| `WaitForAddress` type 3（64-bit wait-if-equal） | SDK 19 有；Z-A 本身不调用 | 需核对 |

### 2.4 渲染侧（影响画面正确性，不影响能否提交）

对方按发现顺序记录的主要项：transform feedback 蒙皮、layered pass
（`render_target_array_index`）、depth-stencil view 的 `STENCIL` 模式、
驱动段 `c0[0x644]` 的 base instance、reduction sampler、image atomics、
零立方体替代 2D 纹理等。

我们 dm/ 的现状（grep 结果）：

| 特性 | 我们 |
|---|---|
| transform feedback | 有（5 个文件命中） |
| layered pass | 有（6 个文件） |
| reduction sampler | 有（6 个文件） |
| `nvnTextureViewSetDepthStencilMode` | 有（6 个文件） |
| `render_target_array_index` | **无** |
| 驱动段 `c0[0x644]`（base instance） | **无** |
| image atomics（atomicMax 等） | **无**（0 命中） |

> 这些"缺"会表现为**画面错误**（角色变成尖刺、腿折到背后、黑屏、条纹光照），
> 不是「没有 Submit」。等能出帧后再逐项补。

---

## 3. 我们代码里可以直接落的差距

### 3.1 已确认的 bug：`SignalToAddress` type 2

mesosphere `KAddressArbiter` 的语义（nxnative `docs/reference/threads.md` 明写，
Ryujinx / yuzu 一致）：

> for `SignalToAddress` type 2 (`SignalAndModifyByWaitingCountIfEqual`) with
> count ≤ 0 and waiters present, the new value is **`value − 2`**, not `value − 1`.

我们的实现（`app/native/za_sync.c`）：

```c
if (type == 2) {
    if (count <= 0) nv = nw > 0 ? val - 1 : val + 1;   // ← 应为 val - 2
    else nv = nw == 0 ? val + 1 : (nw <= count ? val - 1 : val);
}
```

⇒ 一行修正，低风险。

### 3.2 缺失的 NVN 接口（按对 Z-A 的重要性排序）

1. **`nvnCommandBufferFenceSync`**（每帧一次；缺了会表现为「SyncWait 立刻超时」）
2. **状态 getter**：`nvnColorStateGetBlendEnable`、`nvnPolygonStateGetCullFace`、
   `nvnDepthStencilStateGetDepthTestEnable`（Trinity 读回状态建管线）
3. `nvnSamplerCompare`（我们日志里已经被调用 3 次，落到红桩）

我们已有的相关实现：`nvnQueueFenceSync`、`nvnSyncWait`、`nvnBlendStateGetBlendFunc`、
`nvnBufferBuilderGetSize`、`nvnTextureBuilderGetWidth`。

### 3.3 待验证的假设：内存报告值

见 §2.2。验证方法（不需要改游戏逻辑）：

- 在 `QueryMemory` / `svcGetInfo` 处把「可分配地址空间」的报告值从 64 GB 降到
  ~4.25 GB（对齐对方的 5 GB 布局），其余不变，跑同一变体看：
  1. 是否还进 SDK 致命自旋（`sdk+0x9c580`）；
  2. 490 MB 池是否还出现；
  3. 帧管线是否推进。
- 若有效，再考虑是否照对方做 `StandardAllocator` 的宿主侧 cap。

### 3.4 同步语义的基准

我们 E44 对齐的是 d2r-mobile 的 `hle_thread.c`；nxnative 的 `threads.md` 是同一
谱系更新后的版本，其中额外记录了：

- `SignalToAddress` type 2 的 `−2`（§3.1）；
- `WaitForAddress` type 3（64-bit）；
- 游戏自带自旋锁缺 acquire 语义时，在 Apple 核上会双跑同一个 job——他们用
  「`ldxr` → `ldaxr`」的全模块改写解决。**我们宿主是 ARM，是否需要同样改写未知**，
  但这是「任务被执行两次」这类怪现象的候选解释。

---

## 4. 建议的推进顺序

| 优先级 | 动作 | 依赖 | 风险 |
|---|---|---|---|
| P0 | 修 `SignalToAddress` type 2（`val-2`） | 无 | 低 |
| P0 | 补 `nvnCommandBufferFenceSync` + 三个状态 getter | 无 | 低 |
| P1 | 内存报告值 A/B（64 GB → 4.25 GB 量级） | 真机 | 中（可能影响加载） |
| P1 | 查 `crypto::GenerateCryptographicallyRandomBytes` / `GetAudioOutBufferCount` 实现是否完整 | 无 | 低 |
| P2 | 渲染侧：`render_target_array_index`、`c0[0x644]`、image atomics | 能出帧后 | 中 |
| P2 | 自旋锁 acquire 语义全模块检查（`ldxr`→`ldaxr`） | 有「同一 job 跑两次」现象时 | 中 |

---

## 5. 不适用 / 已排除

- **nx2android**：Mali 不支持 BC 纹理（§1.1）。
- **静态重编译**（LASRecomp / nxrecomp / kirikae / ScarletNX / nxrt 等，2026-10 集中出现）：
  目标是 x86 PC。我们宿主就是 ARM64，客机代码可直接执行，**不需要**重编译。
- **Eden 模拟器**：Z-A 的可玩报告全部来自 Snapdragon/Adreno + Turnip；Mali 无证据。
  作为「换路线」的备选保留，但不作为主线。

---

## 6. 出处

- nxnative Z-A 页：`https://github.com/seedds/nxnative/blob/main/dm/games/0100F43008C44000/README.md`
- nxnative 内存：`docs/reference/memory.md`（StandardAllocators over 12 to 62 GB of address space）
- nxnative 线程/同步：`docs/reference/threads.md`
- nxnative 症状索引：`docs/agents/symptoms.md`
- nx2android README 与 PR #25：`https://github.com/shirai91/nx2android` / `pull/25`
- 我们自己的实现：`app/native/za_mem.c`、`app/native/za_sync.c`、
  `app/native/dm/gfx/nvn/hle_nvn.c`
