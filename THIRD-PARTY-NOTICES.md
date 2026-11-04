# 第三方组件与致谢（THIRD-PARTY NOTICES）

本仓库构建/运行时用到的第三方项目及其许可。**本仓库不随附任何第三方二进制**；
下述 DLL/库由使用者自行从上游获取。

## 1. Ryujinx（MIT）—— Maxwell SASS → SPIR-V 翻译

- 上游：<https://github.com/Ryujinx/Ryujinx>（原仓库已归档；镜像于 2025-03 遭
  DMCA 下架，许可文本仍随其历史发布有效）
- 用途：`tools/bnsh_xlate`、`tools/bnsh_dump` 链接 `Ryujinx.Graphics.Shader`
  （把 BNSH 里的 Maxwell SASS 翻成 SPIR-V）。DLL 由使用者自行构建/提供
  （`-p:TranslatorBin=<目录>`），**不随本仓库分发**。

```
MIT License

Copyright (c) 2018 Ryujinx Team and Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 2. d2r-mobile（MIT）—— `app/native/dm/` 图形/宿主层的源头

- 上游：<https://github.com/jhaizhou-ops/d2r-mobile>
- 用途：`app/native/dm/`（NVN→Vulkan 回放引擎、HLE 线程模型、命令缓冲语义）
  从该工程移植/派生，并按本项目（Z‑A / Mali）改造。

```
MIT License

Copyright (c) 2025 jhaizhou-ops

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 3. nxnative（MIT）—— Z‑A bring-up 记录与同步语义参照

- 上游：<https://github.com/seedds/nxnative>
- 用途：只读参照其文档（`docs/reference/threads.md`、`memory.md`、
  `dm/games/0100F43008C44000/README.md`）核对行为——例如
  `SignalToAddress` type 2 count≤0 应写 `value−2`、SDK 19 内存布局等。
  未复制其代码。

## 4. nx2android（无 LICENSE 文件）—— Z‑A 安卓移植参照工程

- 上游：<https://github.com/shirai91/nx2android>
- 用途：兼容性记录与对照实验；Release 里的 APK 由其 porter 从使用者自备的
  游戏构建（宿主运行时 `libdmhost.so` 含我们对它的本地改动，改动以补丁形式
  发布在 [`patches/nx2android/`](patches/nx2android/)）。上游未附许可文件，
  版权归其作者；如上游要求下架衍生构建，请提 issue。

## 5. RAD oo2core（Oodle）—— 不分发

- 用途：`tools/oodle.py` 以 ctypes 调用 `oo2core` 解 `.trpak`（2.9.x）。
  库文件由使用者自备（随游戏或 RAD 授权获取），不随本仓库分发。

---

除上述外，仓库内其余代码/文档为原创（见仓库主页）。
游戏《宝可梦传说 Z‑A》及其全部内容版权归 Nintendo / Game Freak /
The Pokémon Company 所有；本工程不含、不分发任何游戏数据或密钥，
运行需要使用者自备正版游戏转储。
