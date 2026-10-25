# 宝可梦 Z-A 安卓应用（独立工程）

这是**宝可梦传说 Z‑A** 的安卓移植应用，和暗黑破坏神那个 APK **完全分开**：

| | 宝可梦 Z‑A（本工程） | 暗黑破坏神（d2r-and） |
|---|---|---|
| 包名 | `org.pokelegza.android.port` | `org.d2r.android.port` |
| 应用名 | 宝可梦ZA | 暗黑破坏神II |
| 原生库 | `libzaandroid.so` | `libdmandroid.so` |
| 工程目录 | `pokeLegza-and/app/` | `d2r-and/d2r-android/dm/android/` |
| 产物 | `app/build/PokemonZA-Android-port.apk` | `d2r-android/dm/android/build/D2R-Android-port.apk` |
| 签名密钥 | `app/keys/debug.keystore`（本工程自己生成） | d2r 自己的 |

包名不同 ⇒ 两个应用可以**同时装在同一台设备上**，互不覆盖。
`app/tools/build.py` 里有一条硬断言：所有写操作的产物路径必须落在 `app/` 之内，
防止误写到 d2r 的构建目录。

## 现在的进度（里程碑 M1 —— 已在平板实机跑通）

- ✅ 独立 APK 工程跑通：glslc 编译自己的着色器 → NDK 交叉编译 `libzaandroid.so` →
  aapt2 打包 → zipalign → apksigner 签名（**不走 Gradle**）。
- ✅ 包名/应用名/图标已验证：`aapt2 dump badging` 输出 `package: org.pokelegza.android.port`、
  `application-label:'宝可梦ZA'`。
- ✅ **装到平板并跑起来了**：与暗黑破坏神的 APK **同机并存**（`pm list packages` 两个包都在，
  暗黑的 `lastUpdateTime` 没变）。
- ✅ **真机渲染出画面**：logcat 稳定输出「已渲染 N 帧 (3008x1880)」，截图可见全屏渐变三角形。
  整条通路 = 自写 Vulkan 宿主 + 自带 SPIR-V + Android 表面 + 交换链 + 呈现，全部实测通过。

```
GPU: Mali-G925-Immortalis MC12
Vulkan API 1.3.278  驱动 49.1.0
vkCreateAndroidSurfaceKHR -> 0
交换链就绪: 5 张图, 3008x1880, 格式 37
着色器模块已加载: shaders/za.vert.spv / shaders/za.frag.spv
渲染管线就绪
已渲染 4560 帧 (3008x1880)
```

### 踩过的坑（安卓 NativeActivity + Vulkan）

| 坑 | 症状 | 解法 |
|---|---|---|
| **WSI 函数取错了地方** | 渲染 1 帧后崩在 loader 的 `vkQueuePresentKHR`（空指针，fault addr 0x50） | AOSP loader 的表面/交换链/呈现函数**必须用 `vkGetInstanceProcAddr(instance, ...)` 取**；用 `vkGetDeviceProcAddr(device, ...)` 拿到的是 ICD 裸函数，loader 侧数据建不起来 |
| `vkCreateSemaphore` 的 pCreateInfo 传 NULL | 崩在 ICD 里，fault addr 0x8 | 传合法的 `VkSemaphoreCreateInfo`（`pCreateInfo` 是必需参数） |
| 声明了动态 viewport 却没设置 | 全屏一片黑（只有清屏色） | 每帧 `vkCmdSetViewport` / `vkCmdSetScissor`（这个 NDK 头是 **4 参**旧签名） |
| 没申请 `VK_KHR_swapchain` 设备扩展 | present 时 loader 装拒绝桩 → 崩 | 设备创建时申请该扩展（数组必须是函数作用域的，不能在 if 块里出作用域） |
| 窗口没设缓冲区几何 | loader 呈现路径取不到 BufferQueue | 建表面前 `ANativeWindow_setBuffersGeometry(window,0,0,WINDOW_FORMAT_RGBA_8888)`（`setBuffersTransform` 是平台私有符号，链不上） |
| NDK 头是旧版 API | 各种编译错 | `vkCmdRenderPassBegin` 不存在（用 `vkCmdBeginRenderPass`）；`vkCreateGraphicsPipelines` 带 pipelineCache 参数 |
| `gCreateDevice`/`gDestroyDevice` 漏赋值 | 调空指针 | 加了函数指针审计脚本思路：声明了却没赋值的都要查 |

**排查手法**：编译加 `-g`，用 NDK 的 `llvm-nm` 拿符号偏移 + `llvm-addr2line` 精确定位到源码行；
设备上的 `/system/lib64/libvulkan.so` 可以 pull 下来用 `llvm-objdump` 反汇编看崩在哪个成员上。

### 还没做

- ⬜ **还没接游戏**：NSO 加载、NVN 宿主、触屏 UI、Wwise 都没动。
  下一步把第 3 步的「自带 SPIR-V」换成「控制段哈希 → 预翻 SPIR-V 运行时查表」。
- ⬜ 4,482 个翻译失败待修（Ryujinx IR bug）。

### 客机模块（main NSO）装载：导入机制已逆向完成

Switch 的客机代码是 **ARM64**，安卓原生 ARM64，**直接跑、不翻译**。装载要解决的就是「导入怎么解析」。

**NSO0 的导入不是常见 PLT 桩**，实测（`tools/nso_import_table.py`）结构是：

| 项 | 位置 / 形态 |
|---|---|
| 导入桩 | **.text 末尾**，每个 16 字节：`adrp x16,<GOT页> ; ldr x17,[x16,#off] ; add x16,x16,#off ; br x17`（Z‑A：917 个，完全连续） |
| GOT 槽 | **.data 段**（Z‑A：data+0x308000 起，1001 个 8 字节槽） |
| 槽的初值 | 未解析时统一装**占位桩地址** 0x2FC38E0；**为 0 的槽 = 该符号没有桩**（数据符号，84 个） |
| 符号 ↔ 槽 | **dynsym 里未定义符号的顺序**；有桩的按顺序依次领用 .text 末尾的桩 |
| NSO 头关键字段 | 0x90/0x94 = dynstr（rodata 内偏移/大小）、0x98/0x9C = dynsym；0x60/0x64/0x68 = 三段压缩后大小 |
| .text 段头 | 12 字节 `(1, mod0偏移, apiinfo偏移)`，两个偏移指向 rodata（MOD0 / NSP 依赖表） |

⇒ **宿主只要「按名字解析出地址 → 写进对应 GOT 槽」**，不需要解析任何重定位表。
段要**整块连续映射**（adrp 是页内相对偏移，整块连续就天然正确）。

**已产出**：
- `app/native/za_imports.h` — 917 个「符号名 → GOT 槽」映射（`tools/gen_guest_headers.py` 生成）
- `app/native/za_guest_info.h` — 三段布局与 GOT 位置
- `app/native/za_guest.c` — 装载器骨架（映射映像 + 填 GOT）

**导入面（1001 个）**：C 运行库 344、其它 253、`nn::os` 102、libc++ 87、`nn::hid/fs/time` 73、
`nn::网络/账号` 70、`nn::crypto/util` 50、`nn::err/res` 15、`nn::mem` 6、**nvn 仅 1 个**
（其余 NVN 函数靠 `nvnQueueGetProcAddr` 按名取，与 D2R 结论一致）。
**好消息**：Android 的 libc / libc++ 与 NSO 用**同一套 Itanium mangling**（`std::__1::` 相同），
这 400 多个可直接 `dlsym` 命中；只有 `nn::*` 需要自己实现。

**下一步**：① 定位模块入口点；② 实现 `nn::os` 的第一批桩（线程/事件/内存）；③ 把客机映像打进 APK 资产并跑起来。

## 构建

```bash
# 默认借用 d2r-and/build-tools-win 里的工具链（只读），可用环境变量覆盖
python app/tools/build.py              # 只构建
python app/tools/build.py --install    # 构建完装到设备
```

环境变量：
- `ZA_ANDROID_TOOLS` → 含 `build-tools/{aapt2,apksigner,zipalign}`、`platform/android.jar`、`jdk/`
- `ZA_NDK` → 含 clang 与 `shader-tools/{glslc,spirv-*}`

## 目录

```
app/
├── AndroidManifest.xml      包名/应用名/图标/横屏声明
├── native/za_activity.c     NativeActivity 前端（Vulkan 初始化 + 渲染循环）
├── shaders/za.vert|frag     自写的 GLSL（用 NDK 的 glslc 编成 SPIR-V 打进 assets）
├── res/                     自绘矢量图标（纯项目美术，不含任何游戏素材）
├── keys/debug.keystore      本工程自己的调试签名密钥
├── tools/build.py           独立构建脚本（不走 Gradle）
└── build/                   构建产物（PokemonZA-Android-port.apk）
```

## 下一步（M2：把游戏跑起来）

1. **NSO 加载**：把解出来的 main NSO 三段（text/rodata/data）映射进内存，补一份 Switch libc 垫片，
   进游戏入口。参考 `d2r-and` 的 `dm/host/loader.c`（只读参考，不改它）。
2. **NVN 宿主**：实现 `nvnBootstrapLoader` + NVN HLE，把 NVN 调用翻译成 Vulkan ——
   这部分要接我们翻好的 SPIR-V：运行时按 `sha256(控制段 0x880)[:16]` 查
   `work/spv_map_final.tsv`（18,410 条）取预翻的 SPIR-V。
3. **触屏 UI**：把 Switch 手柄输入映射成安卓触控。
4. **Wwise 音频**：走 android 的 AAudio/OpenSL。

---

## 客机装载（M2）：main NSO 已在平板上真机执行

宿主除了渲染自己的三角形，还负责装载并运行 **《宝可梦 Z‑A》main NSO**（Switch 原生 ARM64 代码）。
详细的逆向结论见仓库根目录的 [`客机装载.md`](../客机装载.md)，这里只记工程要点：

- 客机段资产在 `app/build/assets/guest/{text,rodata,data}.bin`（61.5 MB，来自 `work/nso/`）。
- 装载器在 `app/native/za_guest.c`：
  1. 映像映射到 **0x100000000**（Switch 的固定链接基址，客机代码里硬编码）；
  2. **基址重定位**：NSO 没有一条 RELATIVE 重定位，`.data` 里 36.7 万个模块内指针要自己加基址；
  3. 导入解析：`.dynamic` → JUMP_SLOT / GLOB_DAT / ABS64，落到真实现或自动桩；
  4. **客机 TLS 影子描述符**：`[tp+0x98]` = 自备变量区相对 tp 的偏移；
  5. 跑 `DT_INIT` → `DT_INIT_ARRAY`（1912 个静态构造器）→ `nninitStartup` → `nnMain`。
- `app/native/za_os.c`：`nn::os` 宿主实现（线程/互斥锁/信号量/事件/TLS 槽/参数/时间）。
- `app/native/za_stubs.c`：**自动生成**（`tools/gen_stubs.py`），每个导入一个桩，
  首次调用打印符号名 —— 一轮实机跑完就知道客机调了哪些 `nn::*`。
- `libc++_shared.so` 随 APK 发布（NDK 自带），提供客机需要的 C++ ABI
  （`__cxa_guard_acquire` / `__cxa_throw` / `__gxx_personality_v0`）。

### 实机日志（2026-10-24）

```
ZaGuest : 宿主库 libc++_shared.so 已加载
ZaGuest : 基址重定位：修正 367522 个模块内指针
ZaGuest : 映像 0x100000000（100114432 字节），重定位 4275 条；宿主符号：系统解析 2319，落到自动桩 1956，无解 0
ZaGuest : 客机 TLS 描述符(tid=7639): tp=0x6d6df47780 变量区=0x6d54a26000 槽原值=0 现值=0x1ffffffffcd5c000
ZaGuest : 调 _init @0xcdb060
ZaGuest : 未实现(桩) -> __nnmusl_init_dso
ZaGuest : 未实现(桩) -> _ZN2nn2ro12ProtectRelroEPKvS2_S2_S2_S2_
ZaGuest : 客机致命信号 11: pc=0x100024f2c 段=text 偏移=0x24f2c 访问地址=0x0
```

**当前卡点**：客机在映像偏移 `0x24F2C` 崩（对 NULL 对象调虚函数）。

### 调试注意

- 自己的 SIGSEGV 处理器**不能吞信号**（打印完要 `abort()`），否则进程静默消失、没有回溯。
- 渲染线程崩了不要带死整个进程 —— 用 tid 区分「渲染崩」和「客机崩」。
- 查「进程为什么没了」用 `adb shell dumpsys activity exit-info <包名>`。