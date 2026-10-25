# pokeLegza-and —— 把《宝可梦传说 Z‑A》跑在安卓上

> 目标：复用 `D:\feiniukexinhome\Code\d2r-and` 那套「Switch 原生 ARM64 代码 + 自己实现 Vulkan 后端」的移植方法，
> 把《宝可梦传说 Z‑A》（Pokémon Legends: Z‑A）搬到安卓设备上。

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