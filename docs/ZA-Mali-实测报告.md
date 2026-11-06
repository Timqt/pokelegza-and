# Z-A 在 Mali 上的实测报告（nx2android 移植）

日期：2026-11-04
设备：25079RPDCC（Mali-G925-Immortalis MC12，Android 16，屏幕 3008×1880 @120Hz）
游戏： Pokémon Legends: Z-A **base 1.0.0**（main 7222e13e…，SDK df7a3960…）
工具： nx2android（与 nxnative 同源），从源码构建 + 本地补丁

---

## 0. 结论摘要

1. **Mali 能出画面**：语言选择、外观选择（9 个 3D 角色头像）渲染完全正确，
   触屏手柄可用。nx2android README 里"Mali 不能跑"的说法，在这台设备上**被证伪**。
2. **性能不可用**：最佳配置 **3 FPS**（语言/外观菜单），离可玩差一个数量级。
   > **2026-11-04 晚更新**：根因已找到并修复（AHB native handle 的 fd 选错，见 §9）。
   > 同一菜单现在 **30 FPS**，帧工作 p50 16.9ms，`SyncWait` 不再是大头。
3. **瓶颈不是游戏、不是翻译、不是 GPU 渲染、不是 present 模式**：
   每帧 `SyncWait` 真实等待 **330–380ms** 才看到栅栏完成，而 GPU 渲染通道只有
   **6.7ms**。剩余成本尚未归因。
4. 继续推进需要 **GPU 级剖面工具**（Arm Streamline / AGI）或 **Adreno 设备对照**，
   盲做 A/B 的收益已经耗尽。

---

## 1. 移植是怎么起来的

### 1.1 工具链

| 项 | 值 |
|---|---|
| nx2android 源码 | `git clone https://github.com/shirai91/nx2android`（主分支，已含 Z-A profile） |
| 工具目录 | `NX2A_HOME=D:/feiniukexinhome/Code/nx2a-home`（NDK + .NET 放 D 盘，C 盘只剩 23GB） |
| NDK | r27c（porter 强制版本，`porter tools --download` 下载 745MB） |
| .NET | SDK 10.0.403（着色器翻译用，287MB） |
| prod.keys | `D:/feiniukexinhome/Code/d2r-and/switch key/prod.keys` |
| 游戏目录 | `D:/feiniukexinhome/Code/za-port/za.nsp`（4.03GB，硬链接失败后改为复制） |
| 产物 | `za-port/PokMonLegendsZA.apk`（1.9MB）+ `PokMonLegendsZA-data/`（5.1GB） |

### 1.2 打包/安装命令

```bash
export NX2A_HOME=D:/feiniukexinhome/Code/nx2a-home
python -m porter port   D:/feiniukexinhome/Code/za-port --mt-replay --progress lines
python -m porter install D:/feiniukexinhome/Code/za-port/PokMonLegendsZA-data \
       --device $ZA_DEVICE
```

首次 `adb install` 会弹 **「USB安装提示」**，必须在平板上手动点允许
（MIUI 限制，`INSTALL_FAILED_USER_RESTRICTED`）。

porter 的两条红色警告（已知、非本次实验引入）：

```
[RED] v0 is not a version game profile 0100F43008C44000 registers (v393216 2.0.2)
[RED] main build 7222e13e… is not the tested b1f12fd9… and has none of its 1 registered patches
```

⇒ 我们打的是 **v0 + 派生 profile**，缺 2.0.2 的帧步进桩和 StandardAllocator 补丁。
**下面所有性能数字都只代表 v0，不代表 2.0.2。**

---

## 2. 我们对 nx2android 做的本地补丁

以下补丁都只为实验，未提交上游。

### 2.1 porter：Oodle 解码结果的流式落盘（必须）

`porter/pipeline.py` `device_oodle()`：原实现把设备解码回来的
`job.bin.out`（本作 **5.0GB**）整个 `read_bytes()`，再按 label 拼成 bytes，
32GB 内存的 PC 直接 `MemoryError`。

改为：边读 `job.out` 边把每个 label 的条目写进临时文件，最后按顺序拼 `.dec`。

### 2.2 nvn_dirty.c：脏页跟踪的两个实验开关

- `DM_NO_DIRTY=1`：`nvn_dirty_protect` 直接返回，完全不设只读
  （诊断用；纹理不重传，画面会黑）。
- `DM_DIRTY_PASSIVE=N`（默认 20000）：每个内存池累计缺页超过 N 次后，
  对该 range **放弃保护**，且脏判断恒为真（每次使用重传，内容仍正确）。
  代价是把缺页成本换成上传带宽。

### 2.3 gfx_vk_present.c：present 模式 / 交换链图像数

- `DM_VK_PRESENT=fifo|mailbox|immediate`
- `DM_VK_IMAGES=N`（只增不减，受 `maxImageCount` 限制）

---

## 3. 实测数据

### 3.1 帧率（内置 FPS 显示 + SurfaceFlinger 双重确认）

| 配置 | FPS | 整帧 p50 | NVN submit+present | GPU 渲染通道 |
|---|---|---|---|---|
| 基线（FIFO，无 P1） | **2** | 343 ms | 79 ms | 4.0 ms |
| P1 passive=500 + `--mt-replay` | **3** | 252 ms | 53–73 ms | 4–6 ms |
| 同上 + MAILBOX + 6 图像 | 2 | ~380 ms | 75–82 ms | 6.7 ms |
| `DM_NO_DIRTY=1`（诊断） | 4 | ~250 ms | — | — |
| P1 关闭（passive=0） | 2 | — | — | — |

备注：
- `DM_NO_DIRTY=1` 虽然 4 FPS，但**画面全黑**（纹理不重传），不可用；
- MAILBOX / 6 图像**没有任何改善**，present 链路可以排除；
- 关闭 P1 反而更慢（2 FPS），说明"重传带宽"不是主因。

### 3.2 异步回放时间线（`DM_NVN_ASYNC=1`）

```
[timeline] per frame: game gap 0.4 ms, queue delay 0.2, replay 80.5, GPU tail 375.3; 2.0 jobs
```

| 段 | 时间 | 含义 |
|---|---|---|
| game gap | **0.4 ms** | 游戏逻辑本身几乎不花时间 |
| queue delay | **0.2 ms** | 入队到回放开始 |
| replay | **80.5 ms** | 命令翻译 |
| GPU tail | **375.3 ms** | 回放结束 → 栅栏完成 |

GPU 渲染通道 p50 **6.7 ms**（timestamp 查询）。

### 3.3 SyncWait 调用级追踪（`DM_NVN_SEQ=6`）

```
fence  0x734a02cba0
syncwait ... kind 1 timeout=inf waited 378.64 ms -> 1
syncwait ... kind 1 timeout=inf waited 336.14 ms -> 1
syncwait ... kind 1 timeout=inf waited 329.73 ms -> 1
```

⇒ **不是超时被吞**（`-> 1` = 条件满足），是栅栏真的 ~330–380ms 后才完成。

### 3.4 翻译层耗时前 5（近 300 帧累计）

```
SyncWait             111,867 ms   （≈373 ms/帧）
WindowAcquireTexture  24,241 ms   （≈ 81 ms/帧）
QueueSubmitCommands      127 ms
CommandBufferAddCommandMemory 112 ms
```

### 3.5 其它现场数据

- 写保护缺页累计 **40,269,956** 次（2 FPS 时约 8.7 万次/帧）；
- 命令内存借用 1024 次（后期会话只有 1 次，属噪声）；
- 进程 RSS 2.5GB，CPU 约 111%（单核）；
- 设备日志确认：`Mali-G925-Immortalis MC12, Vulkan 1.3, driver 0xc401000;
  timeline semaphores yes, BC no (decoded on the CPU), ASTC yes, geometry shaders yes`。

---

## 4. 已排除 / 已确认

| 假设 | 实验 | 结论 |
|---|---|---|
| BC 纹理不可用 | CPU 解压兜底（bcdec） | ✅ 工作正常，画面正确 |
| present 模式/图像数 | MAILBOX + 6 图像 | ❌ 无影响 |
| 脏页缺页是主因 | DM_NO_DIRTY / passive=0 | ❌ 只占约 1/4，且不能关 |
| 重传带宽 | passive=0 vs 500 | ❌ 关掉更慢 |
| 游戏逻辑慢 | 时间线 game gap | ❌ 0.4ms |
| GPU 渲染慢 | timestamp | ❌ 6.7ms |
| 命令翻译慢 | replay 80ms | ❌ 只占 ~20% |

## 5. 剩余假设（未验证）

1. **GPU 上还有渲染通道之外的活**：拷贝、纹理上传、barrier、清屏等不计入
   pass timestamp。需要给每个提交打 GPU 级时间戳才能确认。
2. **Mali 驱动的提交延迟**：`vkQueueSubmit` 返回后 GPU 迟迟不启动/不置位栅栏。
   验证方式只有两种：
   - Arm Streamline / AGI 抓 GPU 时间线；
   - 换 Adreno 设备（nx2android 的 Z-A profile 在 Adreno 830 上已验证 30 FPS）。

## 6. 建议的下一步

1. **Adreno 对照**（最省事、信息量最大）：同一份 APK/数据装到 Adreno 设备，
   跑同样的位置。若 30 FPS ⇒ 问题在 Mali 驱动交互；若也慢 ⇒ 是 v0/派生 profile。
2. **拿 2.0.2 更新包**再打一次（profile 真正调试过的版本）。
3. 有 GPU 剖面工具时，按提交打时间戳，定位 GPU tail 的 375ms。

---

## 7. 产物与复现

| 文件 | 说明 |
|---|---|
| `D:/feiniukexinhome/Code/nx2android` | 上游源码 + 本文补丁 |
| `D:/feiniukexinhome/Code/za-port/PokMonLegendsZA.apk` | 移植 APK（1.9MB） |
| `D:/feiniukexinhome/Code/za-port/PokMonLegendsZA-data/` | 数据包（5.1GB） |
| `work/tmp/za_port_screen3.png` | 外观选择页截图（3D 头像正常） |
| `work/tmp/za_port_fps.png` | 2 FPS 内置显示 |
| `work/tmp/plza_async2.txt` | 时间线日志（GPU tail 375ms） |
| `work/tmp/plza_seq.txt` | SyncWait 追踪日志 |

平板上的最佳配置（已恢复）：

```
DM_LANG=en-US
DM_SHARED_FONT_EXT=/sdcard/Android/data/org.nx2a.plza/files/nintendo_ext.ttf
DM_VK_MT_REPLAY=1
DM_DIRTY_PASSIVE=500
```

---

## 8. 后续调研（2026-11-04 晚）：找到了 375ms 的真正来源

### 8.1 根因：771MB 的"复制池"每个提交都要双向 memcpy

运行时日志：

```
[dm] [vk] [RED] memory pool 0x742b715000 +0xf500000 could not be zero-copy (-1):
            a GPU copy is refreshed before each submission (slow)
[dm] [vk] memory pool ...: copied (zero-copy 0.0 MB, copied 771.1 MB)
```

- Z-A 的内存池在 Mali 上**全部走了 copied 路径**（零拷贝 AHB 导入失败，返回 -1），
  累计 **771 MB**；
- 每次提交：开头 `vk_pools_sync` 把整池拷进 shadow，完成线程在更新 `g_done`
  **之前**再 `pools_copy_back` 把整池拷回 guest 内存；
- 771 MB 双向拷贝 ≈ 300–400 ms —— 与时间线里的 **GPU tail 375.3 ms** 完全对上。

⇒ 之前测到的"栅栏完成延迟"其实是**完成线程里的整池 memcpy**，不是 GPU、不是驱动。
这也解释了为什么 present 模式、交换链图像数、脏页开关都无效。

### 8.2 上游已有同方向的修复

- nx2android **PR #95** `perf(vk): preserve copied-pool writes and narrow tracked readback`
  （open，未合并）：正文明确写 "scanning device-mapped memory and repeatedly copying
  whole baselines is expensive on **Mali**"，改动包括按范围回读、缓存分配等。
  与我们的实测完全一致，可直接借鉴/挑选。
- **PR #37 / PR #33 / issue #52**：无 timeline、无 BC、无 dynamic rendering 的
  驱动降级路径——我们这台 Mali 都支持，不是问题。

### 8.3 d2r 方案的可借鉴之处

- `d2r-and` 的图形后端是 **Metal**（`dm/gfx/metal/mtl_backend.m`），
  Apple 统一内存 ⇒ 根本不存在"零拷贝失败"这一层；
- 它的 Android 分支自带 **Turnip 驱动**（`assets/turnip/vulkan.purple.so`，
  另有 Qualcomm 840 / v25.3.0 / v26.0.0 几个版本），即**换掉厂商驱动**；
- 这套思路在 Mali 上的对应物是 Mesa 的 **PanVK**（开源 Mali Vulkan 驱动）。
  nx2android 的 porter 本身支持 `--vulkan-driver FILE`，所以能不能用 PanVK
  取决于它是否支持 Immortalis-G925（CSF，需实测，官方文档未确认）。
- 同步/栅栏代码两边一致（都是 `mtl_wait`），没有额外技巧可借。

### 8.4 下一步（按性价比）

1. **修零拷贝**（最高优先）：给 `pool_zero_copy` 的每个失败点加日志
   （AHB 分配 / sendHandle / mmap / MAP_FIXED / Vulkan 导入），确认 Mali 上卡在哪一步。
   成功即消除 771MB×2 的拷贝，预期直接从 3 FPS 跳到 10+。
2. **cherry-pick PR #95** 的按范围回读，作为零拷贝修不好时的退路。
3. **可选：PanVK** —— 用 `--vulkan-driver` 加载，验证厂商驱动是否是另一个瓶颈。
4. ~~以上~~ → **已完成**，见 §9。

---

## 9. 零拷贝已修复（2026-11-04 深夜）：MTK gralloc 的 fd 布局

### 9.1 根因：`fds[0]` 不是 dma-buf

`pool_zero_copy()` 把 `AHardwareBuffer_sendHandleToUnixSocket` 收到的
**第一个 fd** 当成缓冲区去 `mmap`。在这台 MT6991 上，gralloc 的 native handle
带 **3 个 fd**：

| fd | 权限 | `st_size` | mmap 结果 |
|---|---|---|---|
| `fd[0]` | `O_RDONLY` | **0** | RO → `ENODEV`；RW → **`EACCES`** |
| `fd[1]` | `O_RDWR` | **== 池大小** | ✅ 就是 dma-buf |
| `fd[2]` | `O_RDWR` | 6480 | 元数据 |

所以每个池都在 `mmap` 这一步失败（日志 `temp mmap ... errno 13`），
全部退回"整池双向 memcpy"——即 §8.1 的 771 MB × 2。

验证工具：[`tools/ahb_probe.c`](../tools/ahb_probe.c)（NDK 编出 arm64 二进制，
`adb push` 到 `/data/local/tmp` 以 shell 身份跑）。它同时回答了另一条路：

```
151 device extensions; external-memory ones:
  VK_KHR_external_memory / VK_KHR_external_memory_fd / VK_EXT_external_memory_dma_buf
  VK_ANDROID_external_memory_android_hardware_buffer / VK_EXT_external_memory_acquire_unmodified
```

⇒ **没有 `VK_EXT_external_memory_host`**，宿主机指针导入不可用；dma-buf 是 Mali 上
唯一的零拷贝通道。探针还验证了整条机制：

```
MAP_FIXED test over guest 0x73b48b7000 (16 MB), nfd=3
  buffer fd = [1] (of 3)
  wrote through the mapping; lock rc=0 first=0x5a last=0x77
```

即：fd[1] `MAP_FIXED` 覆盖 guest 地址成功，写入后 `AHardwareBuffer_lock`
读到同样的字节 → 同一块物理内存，零拷贝成立。

### 9.2 修复

```c
// nxnative/dm/android/gfx_vk_core.c
static int ahb_buf_fd(const int *fds, int n, uint64_t size) {
    for (int i = 0; i < n; i++) { struct stat st;
        if (!fstat(fds[i], &st) && (uint64_t)st.st_size == size) return fds[i]; }
    return n > 1 ? fds[1] : n == 1 ? fds[0] : -1;   // 按大小认不出来时的退路
}
```

`pool_zero_copy()` 与 `vk_pool_remap_ro()`（脏页保护拆分后的重映射）都改用它。
Adreno 上只有一个 fd 且大小相符，行为不变。

### 9.3 结果

```
zero-copy: pool 0x742b715000 245 MB imported
memory pool 0x742b715000 +0xf500000: zero-copy (zero-copy 245.0 MB, copied 0.0 MB)
...
memory pool 0x734b4be000 +0x1000: zero-copy (zero-copy 771.2 MB, copied 0.0 MB)
```

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 零拷贝池 | 0 MB / 771 MB | **771.2 MB / 771.2 MB** |
| 语言选择页 FPS | 2–3 | **30**（窗口帧率上限 30） |
| 帧工作 p50 / p90 | 343 ms | **16.9 / 17.7 ms** |
| 整帧 | ~343 ms | 33 ms |
| submit+present | 53–82 ms | 3.1–4.5 ms |
| GPU 渲染 | 4–6.7 ms | 20–21 ms（此时 GPU 才是大头） |

**进游戏了**：用触屏假手柄（左摇杆 + A/+）走完 语言 → 外观 → 取名 →
CONFIRM → Ready!，进入了开场场景：

- `work/tmp/za_start3.png`：列车车厢内部（3D 场景、灯光、金属件），30 FPS；
- `work/tmp/za_start4.png`：字幕 **“Your train has arrived in Lumiose City!”**
  —— 即 nx2android profile 里说的洛市车站；
- 场景内：帧工作 p50 19.4 / p90 21.0 ms，GPU 25.5 ms，submit+present 7.9 ms；
  纯文字帧（字幕淡入）时帧工作 3.0 ms，自适应帧率报到 60 fps。

截图：`work/tmp/za_fix_screen.png`（语言选择）、`work/tmp/za_fix_screen3.png`
（外观选择，9 个 3D 头像）。日志：`work/tmp/plza_zc2.txt`、`plza_zc7.txt`。

### 9.4 现在的瓶颈

- 菜单里 GPU 渲染 20–21 ms ⇒ 这台机器在该场景的 GPU 上限约 48 FPS；
- 游戏自身 `WindowSetPresentInterval=1`，窗口帧率报 **30 fps**，与 nx2android 在
  Adreno 830 上的 30 FPS 一致；
- `SyncWait` 已从 373 ms/帧 降到不在前列（`CommandBufferFenceSync`/`SyncWait`
  每帧仍各 1–2 次，属正常语义）。

### 9.5 补丁

我们对 nx2android 的全部本地改动（含本次 fd 修复与诊断日志、脏页 passive、
present 模式、porter 的 Oodle 流式落盘）导出为
[`patches/nx2android/local-patches-2026-11-04.patch`](../patches/nx2android/local-patches-2026-11-04.patch)。

---

## 10. 进游戏后黑屏（2026-11-05，调查未完结）

### 10.1 症状

Prism Tower 开场过场（「Your train has arrived…」之后）开始，3D 世界全黑
（文字/UI 正常），Mali 反复报 `GROUP_ERROR_FATAL`（status 恒 `0x…2c3`，
sideband 指向同一 VA 区），帧时间 32ms → 526ms → 7.8s，FPS 变 `--`；
`GROUP_ERROR_TIMEOUT` 随后出现，进程最终被杀。昨晚游戏以 30 FPS 跑了
8.8 小时（菜单+列车）未触发，推进到这段过场才崩。

### 10.2 关键证据（PASSDUMP 导出过场全部 96 个 pass）

- **世界几何画出来了**：pass_40 能看到楼群、街道、塔的剪影，但整个场景
  只有环境光（~1/255，max 48）——**光照项整体丢失**；
- pass_88 是 64×64 的光斑贴图（有内容）；pass_92–95 是 UI/文字（27% 非零）；
- ⇒ 黑屏 = 无光照的世界 + 后续合成被 GPU 崩溃反复杀掉。

### 10.3 排除项（全部做了对照）

| 假设 | 实验 | 结果 |
|---|---|---|
| 我们的 fd 修复（§9） | `DM_VK_NO_ZEROCOPY=1` 回退复制池 | **照样崩**（22 FATAL 后进程死）|
| Transform feedback | `DM_VK_XFB=0` | 照崩（12 FATAL）|
| Compute | 过场帧调用表 | **无 Dispatch** |
| Conservative raster | 回放层未实现；设备有扩展但不影响 | 无关 |
| 跨 256MB 分块绑定 | across-two-chunks 日志 | 无 |

过场帧 vs 菜单帧的调用差异：`DrawElementsInstanced=22`、
`SetConservativeRasterEnable=2`、`SetLineWidth`、`ReportCounter=26/ResetCounter=37`。

### 10.4 与上游的关系

- nx2android 的 Z-A profile 在 Adreno 830 上**同一过场正常**（标 playable）
  ⇒ Mali 特有的执行崩溃；
- 上游 issue #80（Metroid Dread 光照丢失、场景压黑）是 Adreno 上的同类
  症状但**无 GPU fatal** —— 回放层另一个正确性问题，与我们这里 Mali 驱动崩溃不同源。

### 10.5 二分工具与已知坑

- `DM_VK_SKIP_OPS=<op 号>`（枚举见 `nvn_obj.h`：25=DRAW 26=DRAW_IDX
  27=DISPATCH 34=COPY_T2B 36=COPY_T2T 49=DRAW_TF…）逐类跳过 replay；
- 过场前**没有存档**：每次重启都要触屏走完 语言→外观→取名→Ready；
- 触屏假手柄流程的失败模式：**overlay（虚拟手柄）初始化失败**（日志无
  `[overlay]` 行）时所有输入落到游戏触摸屏被忽略——多见于 GPU 崩溃循环
  强杀之后的下一次启动；重启平板可恢复，重试启动有时也可恢复；
- MIUI 重启后可能把应用**禁用**（`pm path` 有、Activity 不存在、`enabled=0`）：
  `adb shell pm enable org.nx2a.plza` 直接恢复，**不需要**重装 APK、不弹安装确认框；
- 重启后 `/sdcard/Android/data/<pkg>`「整个消失」的真因是 **FBE 锁屏**：这台机器
  全盘加密，重启后用户数据（连 `/data/media/0`）要**物理解锁一次**才挂载。
  `pm enable` + 等解锁即可，与安装/数据包无关。

### 10.6 待办

1. SKIP_OPS 二分：先 25,26,49（跳 draw），再 34/36/31（跳纹理拷贝），
   再 5/37（跳计数器）——定位杀 GPU 的 op 类；
2. 定位后针对性修（改 replay 或绕开该状态）；
3. 拿 2.0.2 更新包重打（profile 真正调试过的版本）；
4. Adreno 设备对照。

---

## 11. 装机 APK 一直是旧的：合并后**编译失败**，所有 11-05 上游修复都没进过机器（2026-11-06）

### 11.1 现象

设备上装的 APK（`lastUpdateTime=2026-10-05 23:51`，md5 `e2e753a2…`）与
`za-port/0100F43008C44000_build/android/host/libdmhost.so`（**23:18 构建**）逐字节相同。
用它跑整个 11-06 凌晨的实验，结论都是「旧构建」的。

### 11.2 真因：两个编译错误让 23:44 / 23:51 两次重新构建都失败

23:38 `git merge origin/main`（快进）把上游 11-05 的修复带进来，23:42/23:43 提交
（`24c29ae`、`af2f420`）。之后两次 `porter port` 都失败（`port17.log` / `port18.log`）：

| 文件 | 错误 | 原因 |
|---|---|---|
| `android/gfx_vk_exec.c:1917` | `xfb_end(...)` 少一个参数（期望 5，实到 4） | 上游 #107 把 `xfb_end` 签名加了第 5 个参数 `xf`；本地 `af2f420` 补的 indexed draw 调用点没跟上 |
| `gfx/nvn/hle_nvn.c:487` | `NVN_TEXTURE_TARGET_CUBE` 未定义 | 本地那条未提交的 Z-A 补丁写错了枚举名，应为 `NVN_TEXTURE_TARGET_CUBEMAP` |

两处都已修好（`gfx_vk_exec.c` 补 `xf`；`hle_nvn.c` 改枚举名），重编 **141 sources, 0 failed**，
`.so` 从 1606 KB → 1717 KB。用 `NX2A_HOME` 里那把签名 key（`nx2a-home/signing-key.json`，
SHA-256 `1c19e552…`）重打包，`versionCode` 递增到 3，`install -r` 成功。

> ⚠️ 打包命令要么带 `NX2A_HOME`，要么把 key 路径写成 `D:/feiniukexinhome/Code/nx2a-home/signing-key.json`；
> 用 `%APPDATA%\nx2android\signing-key.json` 会**新建一把 key**，签名变化 → `install -r` 报
> `UPDATE_INCOMPATIBLE`，只能卸载（连带删掉 5GB 数据）。

### 11.3 新构建实测

| 指标 | 旧构建（23:18） | 新构建（11-06 重编） |
|---|---|---|
| 过场能跑到的 frame | ~700 就崩 | **3400+**（GPU 不再轻易挂死） |
| `GROUP_ERROR_FATAL` | 有 | 0 |
| `GROUP_ERROR_TIMEOUT` | — | robust ON 时 3–6 次/场 |
| 世界光照 | 黑（只自发光） | **仍然黑（只自发光）** |

### 11.4 顺带查清的：那条 Z-A cubemap 补丁的前提是错的

未提交的 `hle_nvn.c` 补丁注释称「Z-A 的 light-probe cube maps 带 `NVN_TEXTURE_FLAGS_IMAGE`
且是 CUBEMAP target，所以被上游 #80 的 IMAGE 排除挡掉」。实测（新加的 `DM_NVN_TEXDIAG=1`，
见 §11.5）**不是这样**：

```
TEXDIAG ser=24954 tgt=4 flags=0x4 fmt=0x29 32x32x6  lv1  poolflags=0x21 virt=0 layout=1 pkg=0 data=1
TEXDIAG ser=24955 tgt=4 flags=0x4 fmt=0x29 128x128x6 lv8 poolflags=0x21 virt=0 layout=1 pkg=0 data=1
TEXDIAG ser=10   tgt=8 flags=0x8 fmt=0x27 4x4x1   lv1  poolflags=0xa1 virt=0 layout=0 pkg=0 data=0
```

- Z-A 的「cube map」是 **`NVN_TEXTURE_TARGET_2D_ARRAY`（tgt=4）6 层**，不是 `CUBEMAP`（tgt=8）；
- 它们带 `IMAGE`（0x4）**且 `has_layout=1`**，走的是 Vulkan 后端的 `packaged_tex()` 上传路径
  （`gfx_vk_tex.c`），**本来就会上传**——上游 #80 那条（还有本地那条收窄）在 Vulkan 后端根本轮不到；
- 真的 CUBEMAP（tgt=8）那个是 4x4、`COMPRESSIBLE`、`data=0`，不是光照 probe。

⇒ 「环境光 cubemap 没上传」这个假设**排除**。

### 11.5 新增诊断开关：`DM_NVN_TEXDIAG=1`

`nvnTextureInitialize` 里对「CPU_NO_ACCESS 池 或 cube map」的每条纹理打印
`tgt/flags/fmt/poolflags/virt/layout/pkg/data/size`（最多 64 条）。

> 为什么不能用现成的 `DM_NVN_LOG`：它在 `nvn_init_slots()` 里读，而那是 **library constructor**，
> 跑在 `env.txt` 加载**之前**，所以 Android 上 OLOG 一行都不会出。

### 11.6 robustBufferAccess 与 GPU 挂死

- robust **ON**（当前默认）：`GROUP_ERROR_TIMEOUT` 3–6 次/场，画面仍黑；
- robust **OFF**（`DM_VK_NO_ROBUST=1`）：**GPU 错误 0**，画面**仍然黑**。

⇒ robust 不是光照黑的原因（但它确实是 GPU 挂死的原因）。**实验台请用 `DM_VK_NO_ROBUST=1`**。

### 11.7 待办（更新）

1. 用 robust OFF 做光照对照实验（不再有 GPU 挂死）；
2. `DM_VK_PASSDUMP` + `DM_VK_PASSDUMP_TARGET=n` 逐 colour target 找光照 pass，
   确认是「没写」还是「写了没被读」；
3. 查灯光列表 buffer（compute 裁剪的输出）——直接光全没，最可能是它；
4. 拿 2.0.2 更新包重打；Adreno 设备对照。

---

## 12. 光照黑屏定位到**自动曝光为 0**（2026-11-06）

### 12.1 结论

**光照本身算出来了**：过场帧里 `pass 161` 的 1920×1080 **format 43（R8G8B8A8_SRGB）**
目标就是完整光照好的车站场景（见 `work/tmp/pd_cut/pass_162.png`）。
最终图黑不是光照没算，而是**最后合成时乘了一个 = 0 的曝光**。

### 12.2 证据链（标题屏，免输入，最快复现）

给 pass dump 加了 **R32G32B32A32_SFLOAT（109）** 与「≤4 texel 的浮点目标打印每个 texel」后：

```
pass dump 65: 1x1 format 109 → pass_65.ppm
   NaN/inf channels 0, finite values 0.000 .. 0.000, mean 0.00000
   texels: (0 0 0 0)          ← 曝光值 = 0
```

这个 1×1 目标由 `pass 56`（1 draw，着色器 `684c03ae5a801ec2` + `1b7c7e0eb10f11e1`）写出，
它的两个输入（`DM_VK_LOG_FS`）：

| binding | 纹理 | 说明 |
|---|---|---|
| 1 | 1×1 nvn format 0x2e（R16G16B16A16_SFLOAT） | 上一帧的曝光（反馈） |
| 2 | **7×4** nvn format 0x3f（B10G11R11） | 场景亮度直方图/降采样 |

而整条 format 122（B10G11R11）的降采样链**全是 0**：

```
1920x1080 / 960x540 / 480x270 / 240x135 / 120x67 / 60x33 / 30x16 / 15x8 / 7x4
全部 mean 0.00000
```

⇒ 曝光 = 0 ⇒ 最终合成 = 光照场景 × 0 + 自发光 = **黑底 + 自发光**，与症状完全一致。

### 12.3 为什么曝光是 0

标题屏里写第一个 1920×1080 format 122 目标的 `pass 4`（depth 129 + colour 122）
**一帧画都没有**（`DM_VK_TRACE_SIZE=1920x1080:122:0` 追到 `traced pass 4` 但无 `draw:`），
所以整条链从源头就是 0。曝光 pass 只是忠实地把 0 读出来。

> 过场帧不一样：`pass 171/173` 的 1920×1080 format 122 **有内容**
> （mean 0.10 / 0.13，max 2.81），但过场帧里**没有 1×1 曝光 pass**，
> 最终仍然是黑的——说明过场和标题屏走的是两条不同的合成路径，**两条都黑**。

### 12.4 下一步

1. 查 `pass 4`（标题）/`pass 171`（过场）的画为什么在标题屏没有、以及过场为什么仍有内容却合成不出；
2. 确认「format 122 的 HDR 场景」是不是被 **conditional render** 跳过
   （`SetRenderEnableConditional`，主机目前是「反正都画」）；
3. 拿到 2.0.2 更新包后重测（profile 真正调试过的版本）；
4. Adreno 设备对照（最省事、信息量最大）。

### 12.5 新增诊断（已随构建生效）

- pass dump 支持 **R32G32B32A32_SFLOAT**，并对 **≤4 texel 的浮点目标**打印每个 texel
  （`texels: (...)`）——专门用来读曝光/统计这类微小目标。

---

## 13. 再往下：**场景（深度预通道 + G-buffer）一帧画都没有**（2026-11-06）

### 13.1 因果链（已逐段实测）

```
场景深度预通道/G-buffer 没有 draw
  → 深度缓冲全 0（pass dump: depth 1920x1080 format 129, values 0.000000 .. 0）
  → 光照 pass（pass 21，format 122）读深度=+0 的 G-buffer，输出 0
  → HDR/亮度链（format 122）全 0
  → 自动曝光（1x1）= 0
  → 最终合成 = 光照场景 × 0 + 自发光 = 黑底 + 自发光
```

### 13.2 证据

**（a）光照 pass 的输入**（`DM_VK_LOG_FS=ead6e2a32540b19a`，pass 21 = 1920×1080 format 122，1 draw）：

| binding | 纹理 | VkFormat |
|---|---|---|
| 1、2 | 1920×1080 nvn format 0x35 | **129 = 深度** |
| 3、6 | 1920×1080 nvn format 0x25 | 37 = RGBA8 |
| 4 | 1920×1080 nvn format 0x3f | **122 = B10G11R11（HDR）** |
| 5 | 1920×1080 nvn format 0x38 | 43 = RGBA8_SRGB |
| 7 | 1920×1080 nvn format 0x29 | 97 = RGBA16F |

**（b）每个 pass 的 draw 数**（`DM_VK_TRACE_PASS=-2`）：
场景 pass（`pass 4` format 122+深度、`pass 16` format 43+深度）**都是 0 draw**；
有 draw 的全是后处理链（深度降采样 6–15、17、21、22…59）。

**（c）子命令缓冲是空的**（`DM_NVN_ERLOG=1`）：每帧 333 个 `EndRecording` 的 `used` 都是 **8**
（只有一条 END）；`DM_NVN_BRLOG=1` 显示 `BeginRecording` 时命令内存是 **全 0**（游戏没有直接预写）。
`DM_VK_TRACE_CALLS=1` 显示这些 CALL 目标里只有 `BIND_STATE`/`BIND_TEX1`/`BIND_UBO`，**没有 DRAW**。

**（d）回放确实看到了 draw**（`ops at submission N`）：DRAW 92 + DRAW_IDX 23 + CALL 535 + SET_RT 103 + CLEAR_COLOR 50
——即后处理链的 draw；场景的 draw 不在其中。

**（e）conditional render 不是原因**（`DM_VK_TRACE_RC=1`）：全部 `mode 1, values 0/0, known 0/0 -> skip 0`
（未知 → 继续画）。打开 profile 的 `render_cond on` 也没有改变画面。

### 13.3 下一步

1. 场景的 draw 到底记录到哪里去了——`CommandBufferDrawArrays` 每帧只有 7+1+1 次（后处理），
   而场景应有几百次；
2. 检查主机对「游戏直接写命令内存 / 预录制命令缓冲」的处理（Z-A 的引擎可能在 `AddCommandMemory`
   的环里自己写命令，而主机的 `cmd_alloc` 把 END 写在段首，**可能正好覆盖掉游戏预写的命令**）；
3. 拿 2.0.2 更新包重打；Adreno 对照。

---

## 14. 深度确认为 0，场景 draw 不在回放里（2026-11-06 续）

### 14.1 深度确实是 0（修了 pass dump 的深度读取后）

pass dump 原来把 D24S8 当 RGBA 读（`else` 分支），读出来恒为 0。补上
`D24_UNORM_S8_UINT / D32_SFLOAT / D32_SFLOAT_S8_UINT / D16_UNORM` 的解码后，
标题屏所有深度目标仍然是 **`values 0.000000 .. 0`**：

```
pass dump 01: depth 1920x1080 format 129, values 0.000000 .. 0
pass dump 03: depth 1024x1024 format 126, values 0.000000 .. 0
```

⇒ 深度预通道真的没写。光照 pass 读深度=0 → 输出 0，与 §13 的链一致。

### 14.2 命令流的实测结构

| 项 | 实测 |
|---|---|
| 每帧 `BeginRecording`/`EndRecording` | 333 |
| 每帧 `CallCommands` | 340 |
| 每个子命令缓冲的 `used` | **8**（只有一条 END）——`DM_NVN_ERLOG=1` |
| `BeginRecording` 时命令内存内容 | **全 0**——`DM_NVN_BRLOG=1`（游戏没有直接预写） |
| 主命令缓冲（`used 760`）的 ops | `BIND_STATE…DEPTH_CLAMP…STENCIL×6…BLEND_COLOR…END`，**没有 DRAW** |
| 有 DRAW 的子命令缓冲 | 只有 `(10 ops) BIND_STATE×3 BIND_UBO BIND_PROGRAM DRAW BIND_STATE×2`，约 10 个 |
| 每帧 NVN API 的 draw | `DrawArrays 7 + DrawElements 1 + DrawArraysInstanced 1` |
| 回放看到的 draw | DRAW 92 + DRAW_IDX 23（= 后处理链） |

⇒ **场景的 draw 既不在主命令缓冲、也不在子命令缓冲里**。

> **2026-11-06 更正**：上面这条**是错的**——当时 `DM_NVN_ERLOG` 只记了前 80 条。把上限提到 400 后，
> 392 条 `EndRecording` 里有 **205 条 `used > 8`**，子命令缓冲**是有内容的**：
> `0x77ccb4a400 (used 344) ops BIND_STATE×3 BIND_TEX1×2 BIND_PROGRAM DRAW BIND_STATE×2`、
> `0x77ccb47800 (used 360) ops REPORT_COUNTER BIND_STATE×2 BIND_VATTR BIND_VSTREAM BIND_VBUF BIND_PROGRAM DRAW_IDX BARRIER …`。
> `DM_VK_TRACE_CALLS=1`（带 pass 号）显示这些带 DRAW 的子命令缓冲被 **pass 0、6–15、17、20、21…** 调用。
> 即：**场景的 draw 确实存在**，被后处理链的 pass 调用；而场景自己的 pass（4、16）既不带 draw 也不 CALL。
> 这条线索还没解释清楚（pass 归属为何错位），但是目前最可疑的地方。

### 14.3 结论

断点已经定到最底层：**场景（深度预通道 + G-buffer）的 draw 没有进入主机的回放**，
于是深度=0 → 光照=0 → HDR=0 → 曝光=0 → 画面黑。
光照、HDR、曝光、合成这几级本身都是好的（它们忠实地把「没画的场景」算成 0）。

下一步只能从「游戏把场景 draw 记录到哪里去了」入手：
- 每帧 333 个录音、340 次 CALL，但 API 只有 9 次 draw——**录音和 draw 对不上**；
- 最可疑的是主机对「子命令缓冲 / 命令内存环」的处理（`cmd_alloc` 的 END 位置、
  `AddCommandMemory` 的 0x400 小块、host-lent 段），需要拿一个能正常画场景的游戏做对照。
