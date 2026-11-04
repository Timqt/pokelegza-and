# pokeLegza-and —— 把《宝可梦传说 Z‑A》跑在安卓上

> 目标：复用 `D:\feiniukexinhome\Code\d2r-and` 那套「Switch 原生 ARM64 代码 + 自己实现 Vulkan 后端」的移植方法，
> 把《宝可梦传说 Z‑A》（Pokémon Legends: Z‑A）搬到安卓设备上。

## 最新进展（2026-11-05）：Mali 平板跑进游戏开场，30 FPS

两条路线的现状：

| 路线 | 状态 |
|---|---|
| **本仓库自己的移植**（`app/`，NSO 原样跑 + Horizon HLE + NVN→Vulkan） | 客机已能执行，帧管线推进到 3/8（Submit 未达）——卡在「某条 submit 的任务对象从未入队」 |
| **nx2android 路线**（参照工程，本地补丁） | **已能在 Mali‑G925 上出画面并进开场：菜单 30 FPS**（修复前 2–3 FPS），并走到字幕 “Your train has arrived in Lumiose City!” |

### Mali 上从 3 FPS 到 30 FPS：问题与解法

**现象**：Z‑A 在 Mali‑G925（MT6991）平板上菜单只有 2–3 FPS。逐段计时显示每帧
`SyncWait` 真实等待 330–380 ms，而 GPU 渲染只要 6.7 ms——「栅栏完成延迟」占了
一整帧。深挖发现：NVN 内存池共 771 MB **全部**走了 copied 路径，每个提交要把
整池 `memcpy` 进 shadow、完成后再整池拷回，双向约 300–400 ms，与计时完全对上。

**定位**：给 `pool_zero_copy()` 的每一步失败点加日志后看到 `temp mmap … errno 13`；
再写独立探针 [`tools/ahb_probe.c`](tools/ahb_probe.c)（NDK 编 aarch64，推到设备上跑）确认：

- MTK 的 gralloc 给 `AHardwareBuffer` 的 native handle 是 **3 个 fd**：
  `fd[0]` 是 size 0 的只读元数据（mmap 必失败），`fd[1]` 才是 dma-buf
  （`st_size == 缓冲区大小`），Qualcomm 通常只有 1 个 fd；
- 原代码恒取 `fds[0]`，于是在 Mali 上**每个池都** mmap 失败、退回整池拷贝；
- Mali **没有** `VK_EXT_external_memory_host`，dma-buf 是唯一零拷贝通道；
- 用 `fd[1]` `MAP_FIXED` 覆盖 guest 地址后，CPU 写经 `AHardwareBuffer_lock`
  读回同样字节 ⇒ 零拷贝机制本身在这台机器完全可用。

**修法**（已导出 [`patches/nx2android/local-patches-2026-11-04.patch`](patches/nx2android/local-patches-2026-11-04.patch)）：

```c
// 按 fstat 的大小认出真正的 dma-buf fd，而不是拿 fds[0] 碰运气
static int ahb_buf_fd(const int *fds, int n, uint64_t size) {
    for (int i = 0; i < n; i++) { struct stat st;
        if (!fstat(fds[i], &st) && (uint64_t)st.st_size == size) return fds[i]; }
    return n > 1 ? fds[1] : n == 1 ? fds[0] : -1;
}
```

`pool_zero_copy()` 与 `vk_pool_remap_ro()`（脏页保护拆分后的重映射）都改用它。

**结果**：

| | 修复前 | 修复后 |
|---|---|---|
| 零拷贝池 | 0 / 771 MB | **771.2 / 771.2 MB** |
| 菜单 FPS | 2–3 | **30**（游戏自身 `WindowSetPresentInterval` 上限） |
| 帧工作 p50 | 343 ms | **16.9 ms** |
| submit+present | 53–82 ms | 3–4.5 ms |
| GPU 渲染 | 4–6.7 ms | 20–25 ms（**现在的瓶颈**，≈48 FPS 上限） |

完整实验记录（含逐段计时、被排除的假设、进开场的截图）见
[`docs/ZA-Mali-实测报告.md`](docs/ZA-Mali-实测报告.md)（§8 根因、§9 修复）。

---

## 一句话结论（2026-10-24 实测已闭环）

**可行性成立；着色器链路整条跑通，且刚刚修掉了一个会让 2 万个着色器「阶段全错」的致命坑。**

| 环节 | 结果 |
|---|---|
| 本体是 Switch 1 (Maxwell) | ✅ Program/Control NCA **SDK 19.3.11.0** |
| 游戏数据归档（ONEPACK / TRPFS / TRPFD / TRPAK） | ✅ **自研解包器**，9,892 / 9,892 路径全部对上 |
| Oodle 压缩（`.trpak` 内层） | ✅ `oo2core 2.9.14`，**232 个文件 / 88 MB** 全部解出 |
| 着色器归档 | ✅ 4 个 `.bnsh` / `.trsha` 包 + **3,102 个容器内嵌 BNSH（3.9 GB）** |
| **Maxwell SASS → SPIR-V** | ✅ **47,378 个 SPH → 42,896 个 SPIR-V（90.5%）：19,906 顶点 + 22,990 片元** |
| **平板实机验收** | ✅ **Mali‑G925 驱动：42,896 / 42,896 接受、拒绝 0**；二进制里的执行模型分布 = 顶点 19,906 / 片元 22,990（与真值一致） |
| 运行时查表（控制段哈希 → SPIR-V） | ✅ **18,410 个唯一 key**，含 4 处真冲突已裁定 |

失败的 4,482 个**不是「Maxwell 翻不了」**，而是 Ryujinx 自身 IR 的 bug
（`AstTextureOperation` 强转 3,549、`AstOperand` 键缺失 702、`AstOperation` 强转 222、越界 9），
属于可修的软件问题，不是 ISA 障碍。

详细论证见 [`评估报告.md`](评估报告.md)。

---

## ⚠ 本轮最重要的一个修正：阶段被整体误判（已修）

之前全量语料「44,031 个模块**全是片元**」是**错的**，顶点着色器其实就在游戏数据文件里。

**根因**：Ryujinx 的 `ShaderHeader` 取 `GetCode(addr, 0x50)`，把**第一个 u32 的 bits 10..13** 当成阶段
（1 = 顶点、5 = 片元）。而我们一直从 `0x12345678` **魔数**处开始喂 —— 魔数的 bits 10..13 恰好 = 5，
于是**每个着色器都被判成片元**。

真实布局（Z‑A 与 D2R 完全一致）：

```
[0x30 字节 NVN 头：0x12345678 + 零][0x50 字节 SPH：第 0 字 = 阶段字][指令]
   魔数在 +0                SPH 在 +0x30，指令在 +0x80
```

⇒ 喂给 Ryujinx 的起点必须是 **魔数 + 0x30（SPH 本体）**。

**修正前后对比**：

| | 修正前 | 修正后 |
|---|---|---|
| 阶段判定 | 全部 Fragment | **19,906 顶点 + 22,990 片元** |
| 全语料真值普查 | — | 47,369 个 SPH：**20,179 顶点 + 27,190 片元**（字段取值恰好只有 {1,5}） |
| 平板驱动接受 | 5,272/5,272（旧语料） | **42,896/42,896，拒绝 0** |
| 执行模型（从二进制读回） | 全是片元 | **顶点 19,906 / 片元 22,990** ✓ |

**教训**：GPU 驱动「接受」只证明 SPIR-V **合法**，不证明**语义正确**。
阶段错的东西照样能被驱动编译通过 —— 必须拿二进制里的 `OpEntryPoint` 执行模型回验。

**附带结论**：顶点着色器在数据文件里 ⇒ **不需要接管 glslc**（原计划的移植最硬一块被取消）。
3,102 个着色器容器的文本区扫 GLSL 特征串 **零命中**，与该结论一致。

---

## 现在的状态

- ✅ **可行性关已过**：着色器链路（游戏资源 → 解包 → Oodle → BNSH → Maxwell SASS → SPIR-V → 平板 GPU 驱动）整条跑通，阶段正确。
- ✅ **运行时查表口径已定**：key = `sha256(控制段 0x880 字节)[:16]`（与 D2R 同款），`work/spv_map_final.tsv` 18,410 条。
- ✅ **独立安卓工程已建好、装上并跑起来了**：`app/` 下是**宝可梦 Z‑A 自己的**应用（包名 `org.pokelegza.android.port`、
  应用名「宝可梦ZA」、so 名 `libzaandroid.so`），**与暗黑破坏神那个 APK 同机并存、互不覆盖**；
  平板上实测稳定出帧（3008×1880，logcat 持续报「已渲染 N 帧」）。
  详见 [`app/README.md`](app/README.md)。
- ⬜ **工程关未开**：Horizon 服务补齐、NVN 宿主接入、触屏 UI、音频（Wwise）、整包数据部署。
  （**NSO 加载已于 2026-10-25 打通**：SDK/main 两个模块都装上了，见下文「客机装载」与
  [`借鉴清单.md`](借鉴清单.md) 的第三节。）
- ⬜ **4,482 个翻译失败待修**：Ryujinx IR bug，不是 ISA 障碍。
- ⬜ **顶点属性/贴图类型尚未如实作答**：Ryujinx 的 accessor 现在一律返回默认值（Texture2D + R8G8B8A8Unorm），
  需按控制段元数据补齐（这是下一步）。

---

## 宝可梦 Z‑A 的安卓应用（独立于暗黑）

```
app/
├── AndroidManifest.xml      包名 org.pokelegza.android.port · 应用名 宝可梦ZA
├── native/za_activity.c     NativeActivity 前端：dlopen libvulkan → 实例/设备 → 交换链 → 渲染
├── shaders/za.vert|frag     自写 GLSL（NDK 的 glslc 编成 SPIR-V 打进 assets）
├── tools/build.py           独立构建脚本（aapt2 → zipalign → apksigner，不走 Gradle）
└── build/PokemonZA-Android-port.apk
```

| | 宝可梦 Z‑A | 暗黑破坏神 |
|---|---|---|
| 包名 | `org.pokelegza.android.port` | `org.d2r.android.port` |
| 应用名 | 宝可梦ZA | 暗黑破坏神II |
| 原生库 | `libzaandroid.so` | `libdmandroid.so` |
| 签名密钥 | `app/keys/debug.keystore`（自建） | d2r 自己的 |

**d2r-and 目录只读借用它的 build-tools-win 工具链，任何产物都不写进那个工程**；
`app/tools/build.py` 里有一条硬断言：所有写操作目标必须落在 `app/` 之内。

```bash
python app/tools/build.py --install
```


## 借鉴与参考

许可细节与全文见 [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)。

| 项目 | 许可 | 我们借鉴了什么 | 落在哪 |
|---|---|---|---|
| [d2r-mobile](https://github.com/jhaizhou-ops/d2r-mobile) | MIT | **`app/native/dm/` 的源头**：NVN→Vulkan 命令回放、HLE 线程/同步模型、命令缓冲语义；「Switch 原生代码 + 自研 GPU 后端」的整套方法也来自同谱系的前作 d2r-and | `app/native/dm/`（按 Z‑A/Mali 大改） |
| [nxnative](https://github.com/seedds/nxnative) | MIT | Z‑A 的 bring-up 记录（内存布局、`SignalToAddress` type2 的 `−2`、`nvnCommandBufferFenceSync`、Trinity 读回状态等）——我们照它核对并修了 P0 一批 | 行为核对与 `app/native/za_*.c` |
| [nx2android](https://github.com/shirai91/nx2android) | 无 LICENSE | 同路线的成品安卓 porter：Z‑A profile、设备端 Oodle、着色器分包；Mali 上 3→30 FPS 的零拷贝修复就是对它的 `gfx_vk_core.c` 做的（补丁见 [`patches/nx2android/`](patches/nx2android/)） | 对照实验与 Release 的 APK |
| [Ryujinx](https://github.com/Ryujinx/Ryujinx) | MIT | **Maxwell SASS → SPIR-V** 的现成翻译器（`Ryujinx.Graphics.Shader`）：42,896 个着色器全量翻成 SPIR-V 并在 Mali 上通过验收 | `tools/bnsh_xlate`、`tools/bnsh_dump`（运行时链接，DLL 不随仓库分发） |
| RAD oo2core | 商业（随游戏分发） | `.trpak` 的 Oodle 解压（必须 2.9.x） | `tools/oodle.py`（用户自备） |

「Switch 原生 ARM64 客机 + Horizon HLE + 自研 GPU 后端」这条路线本身来自
d2r 系（我们 2025 年的暗黑破坏神 II 安卓移植实践）；本工程是把它第一次完整
用于宝可梦传说 Z‑A。

---

## 自备文件与公开性

**本仓库不含、也绝不入库**：游戏本体/更新包、NSO/NCA/RomFS 等任何游戏转储、
prod.keys/title.keys 等任何密钥、从转储生成的构建输入。前者由 `.gitignore` 挡住
（`*.nsp/*.xci/*.nca/work/…`），后者是 `tools/*.py` 从**你自己的**游戏转储生成的
头文件，本地保留、不入库：

| 生成文件（不入库） | 生成脚本 | 内容 |
|---|---|---|
| `app/native/za_tls_mrs_blob.h` / `za_tls_mrs.h` | `tools/patch_tls_mrs.py` | main 里 10,193 处 `mrs TPIDR_EL0` 的改写桩 |
| `app/native/za_tls_patch.h` | `tools/patch_tls_helpers.py` | TLS helper 的 `adrp` 改写表 |
| `app/native/za_tlsro_patch.h` | `tools/patch_tls_ro.py` | SDK 123 处 `mrs TPIDRRO_EL0` 改写表 |
| `app/native/za_svc_patch.h` | `tools/patch_svc.py` | SDK `svc` 包装入口 → 宿主门 |
| `app/native/za_romfs_embed.h` | （从 romfs 的 `trinity_config.trowc` 生成） | 客机会读的默认配置 |

新克隆按「怎么用」一节自备转储、跑对应脚本即可构建。运行期查表
`shader_map.tsv` 等只含哈希/元数据，没有游戏字节。

地址/符号类的生成文件（`za_guest_info.h`、`za_relocs.h`、`za_imports.h`、
`za_stub.h`、`za_thunk_got.h`、`za_nvn_names.h`）只是布局事实（偏移、大小、符号名），
不含游戏代码或资产，随仓库分发。

> 仓库里对 nx2android（`https://github.com/shirai91/nx2android`，无 LICENSE 文件）
> 的引用均为兼容性记录；`patches/nx2android/` 是我们自己对它的本地改动，
> 供复现实验用。

---

## 目录

```
pokeLegza-and/
├── README.md                  ← 本文件
├── 评估报告.md                 ← 完整评估：证据链、门槛、工作量、获取方式
├── work/                      ← 过程产物（可随时删）
│   ├── base/{exefs2,romfs}     ← 解出的 ExeFS / RomFS
│   ├── ncas/ nsz-src/ keys/   ← 拆出的 NCA、nsz 源码、密钥
│   ├── nso/{text,rodata,data}  ← 解压出的 main NSO 三段
│   ├── shaders/                ← 232 个解出的 .bnsh / .trsha（88 MB）
│   ├── shaders_all/            ← 全量扫出的 3,102 个含着色器容器（5.0 GB）
│   ├── bnsh_all/               ← 抠出的 3,098 个内嵌 BNSH（3.9 GB）
│   ├── spv_all4/               ← ★ 阶段修正后的 42,896 个 SPIR-V（1.1 GB）
│   ├── spv_all3/               ← ⚠ 废弃：阶段误判时期的旧语料（全被当成片元），留作对照，别用
│   ├── spv_map_final.tsv       ← ★ 运行时查表（18,410 条，含 stage）
│   ├── spv_map_final.tsv.conflicts.tsv ← 4 处真冲突的裁定记录
│   ├── shader_index.tsv        ← 每个容器的 SPH/控制段/魔数索引
│   ├── dotnet/sdk              ← 本地 .NET 10 SDK（翻译器需要）
│   └── oodle/                  ← oo2core 2.9.14（Oodle 解压）
└── tools/
    ├── onepack.py              ← 【主力】ONEPACK/TRPFS/TRPFD/TRPAK 自研解包器
    ├── oodle.py                ← Oodle 解压封装（ctypes → oo2core）
    ├── extract_shaders.py      ← 从 TRPFS 抽 .bnsh/.trsha 并解压
    ├── extract_nso.py          ← 解 main NSO 三段（LZ4）
    ├── bnsh_xlate/             ← 【主力】BNSH → SPIR-V（.NET 10 + Ryujinx.Graphics.Shader）
    ├── scan_all_shaders.py      ← 全量 9,892 包扫描找着色器（40 秒）
    ├── extract_embedded_bnsh.py ← 从容器抠内嵌 BNSH
    ├── build_runtime_table.py   ← 建运行时查表 + 冲突裁定
    ├── stage_census.py          ← 按真值规则普查全语料阶段
    ├── vkcheck/                ← 平板端 Vulkan 验收器（aarch64 原生，可扫目录 + 读执行模型）
    └── probe_*.py survey_*.py cmp_*.py  ← 探索期脚本，留档
```

---

## 怎么用

### 1. 解 ONEPACK 归档（游戏数据）

Z‑A 的 RomFS 里 `arc/data.trpfs`（3.1 GB）是 Game Freak 的 ONEPACK 归档，格式是
FlatBuffers：`ONEPACK\0` + u64 init_offset + 数据区 + 尾部 `{hashes[], file_offsets[]}`。
路径在 `data.trpfd` 里，靠 **Game Freak 自定义的 FNV‑1a**（偏移基 `0xCBF29CE484222645`，不是标准值）对应。

```bash
python tools\onepack.py --trpfs work\base\romfs\arc\data.trpfs --trpfd work\base\romfs\arc\data.trpfd --list 20
```

### 2. 抽着色器包并解压（Oodle）

`.trpak` 内层用 Oodle 压缩。**必须用 oo2core 2.9.x**：
2.3.0 只会写出开头几个字节（返回 0，像成功一样），9.x 才正确。

```bash
python tools\extract_shaders.py            # -> work/shaders/*.bnsh
python tools\scan_all_shaders.py --max-gb=7   # -> work/shaders_all/（3,102 个容器）
python tools\extract_embedded_bnsh.py         # -> work/bnsh_all/（3,098 个内嵌 BNSH）
```

### 3. BNSH → SPIR-V（决定性验证）

Ryujinx 的 Maxwell 前端在 `Ryujinx.Graphics.Shader.dll` 里（**没有 BNSH 读取器**，
但不需要：把 accessor 的 `GetCode` 直接映射到 BNSH 字节，Ryujinx 自己认 SPH）。
**关键：喂的起点是 SPH 本体（魔数 + 0x30），不是魔数**，否则阶段全判成片元。

```bash
dotnet build tools\bnsh_xlate -c Release -p:TranslatorBin=<d2r-and 的 translator-bin 目录>
dotnet tools\bnsh_xlate\bin\Release\net10.0\bnsh_xlate.dll work\shaders_all work\spv_all4
```

### 4. 平板实机验收

```bash
# 用 NDK（d2r-and/build-tools-win/ndk28/android-ndk-r28c）交叉编译
aarch64-linux-android26-clang.cmd -O2 -fPIE -pie -o work\vkcheck\vkcheck tools\vkcheck\vkcheck.c -ldl
adb push work\vkcheck /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/vkcheck
adb shell /data/local/tmp/vkcheck /data/local/tmp/z4/spv_all4/shaders_all   # 目录会递归遍历
```

实测输出：

```
待检文件 42896 个
GPU: Mali-G925-Immortalis MC12
  API版本 1.3.278  驱动 49.1.0  类型 1
  逻辑设备已创建（图形队列族 0）
SPIR-V 模块: 接受 42896  拒绝 0
执行模型分布: 顶点 19906  片元 22990
```

---

## 已经确认 / 还没确认

| 结论 | 状态 |
|---|---|
| 本体是 Switch 1 (Maxwell)，方法适用 | ✅ 实测（SDK 19.3.11.0） |
| 更新包是 Switch 2 内容，做不了 | ✅ 实测（SDK 20.5.21.0） |
| NVN 调用面 521/535 命中 D2R 已实现 | ✅ 实测 |
| ONEPACK / TRPAK / Oodle 归档可解 | ✅ 实测，9,892 包 + 232 文件 |
| **Maxwell SASS 能翻成 SPIR-V** | ✅ **实测：42,896 个模块（19,906 顶点 + 22,990 片元）** |
| **平板 GPU 接受这些 SPIR-V** | ✅ **实测：Mali‑G925 42,896/42,896，拒绝 0** |
| **顶点着色器在哪** | ✅ **就在数据文件里**（20,179 个）；原先「全在运行时 glslc 编译」的结论是阶段误判造成的 |
| **运行时按控制段哈希查表** | ✅ **实测：18,410 个唯一 key，4 处真冲突已裁定**（`work/spv_map_final.tsv`） |
| 顶点属性类型 / 贴图格式能否如实作答 | ⬜ 未做（accessor 现返回默认值） |
| 4,482 个翻译失败 | ⬜ Ryujinx IR bug，未修 |
| NSO 补丁 / Horizon 服务 / NVN 宿主 | ❌ 未动 |
| 触屏 UI 工作量 | ⚠️ 推断（比 D2R 难），未量化 |

---

## 客机装载：main NSO 已经在平板上跑起来了（2026-10-24 夜）

除了着色器链路，**Switch 原生的客机代码（main NSO）也已经在平板上真机执行**。
逆向结论与实现细节见 **[`客机装载.md`](客机装载.md)**，这里只列结论：

| 环节 | 状态 |
|---|---|
| NSO 映像装载（段权限 text=RX / rodata=R / data=RW） | ✅ 实测 |
| **基址重定位**（NSO 里**一条 RELATIVE 重定位都没有**，36.7 万个模块内指针要自己加基址） | ✅ 实测修正 367,522 个 |
| **固定链接基址 0x100000000**（客机代码里硬编码，映像必须映射到这个地址） | ✅ 实测映射成功 |
| 导入解析（`.dynamic` → JUMP_SLOT / GLOB_DAT / ABS64） | ✅ 2,319 个符号落到真实现（含随包发布的 `libc++_shared.so` 提供的 C++ ABI） |
| 客机 TLS（Horizon 线程上下文 `[tp+0x98]` = 模块 TLS 块偏移） | ✅ 影子描述符生效 |
| `nn::os` 宿主实现（线程/互斥锁/信号量/事件/TLS 槽/参数/时间） | ✅ 第一批已实现 |
| 客机 `_init` + 静态构造器 | ✅ **已跑起来，客机开始调真实 `nn::os` API** |
| **SDK NSO 装载**（第二个模块） | ✅ **2026-10-25 实测**：SDK 映像基址 `0x200000000`，导出 23,000、重定位 19,167（未解析 0）；main 的 `nn::*` 导入从 2319 → **4255**（真查到 SDK 导出表了） |
| 当前卡点 | SDK 的 `nn::init::Start` 已读通（顺序与上游一致，且它自己会调 nnMain）。崩在它内部那个 os 初始化函数（`sdk+0x145a30`）：`svc#6` 之后、解析完参数区、从**正常出口**往下走时，`blr` 了一个 **NULL 函数指针**（`pc=0, x8=0`）。<br>已实测排除 6 项（svc 返回值/perm、参数区格式、memcpy 与 getter/setter 是否 NULL、模块链表、`+0x1f0` 两种取值、Start 顺序）。<br>下一步：给 `blr` 打点拿客机真实 PC 链，定位那个「本该由 loader 填」的字段。详见 [`借鉴清单.md`](借鉴清单.md) 第四节 |

三个踩过才知道的坑（都写进 `客机装载.md` 了）：

1. **别换 TPIDR_EL0**：换掉 bionic 的线程 TLS 之后，线程里任何 bionic 调用都立刻崩。
   正确做法是「影子描述符」——TPIDR_EL0 不动，只把客机读的 `[tp+0x98]` 指向自备区域。
2. **客机线程把几乎所有信号都屏蔽了**（只剩 SIGSEGV/SIGKILL/SIGTERM），
   而 bionic 的 `abort()` 在 SIGABRT 被屏蔽时会直接 `_exit(127)` ——
   进程「干净消失」，没有任何 tombstone。查进程死因要用
   `dumpsys activity exit-info`。
3. **自己的 SIGSEGV 处理器不要吞信号**：打印完要 `abort()`，让 debuggerd 出回溯。

---