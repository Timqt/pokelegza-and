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
       --device SCXOHA8TCUN7RWJ7
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

截图：`work/tmp/za_fix_screen.png`（语言选择）、`work/tmp/za_fix_screen3.png`
（外观选择，9 个 3D 头像）。日志：`work/tmp/plza_zc2.txt`。

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
