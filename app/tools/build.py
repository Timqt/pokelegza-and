#!/usr/bin/env python3
"""构建**宝可梦 Z-A** 的独立安卓 APK（不走 Gradle）。

这个脚本只会写 app/ 目录下的 build/，**绝不碰 d2r-and**（暗黑破坏神那个工程）——
所有输出路径都在 ROOT 内，脚本会显式断言这一点。

工具链（默认借用 d2r-and/build-tools-win 里的只读工具，可用环境变量覆盖）：
    ZA_ANDROID_TOOLS  → 含 build-tools/{aapt2,d8,zipalign,apksigner}、platform/android.jar、debug.keystore
    ZA_NDK            → 含 clang 与 shader-tools/{glslc,spirv-*}

用法:
    python app/tools/build.py                # 只构建
    python app/tools/build.py --install      # 构建完顺带装到设备
"""
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # app/
REPO = ROOT.parent                                  # pokeLegza-and/
BUILD = ROOT / "build"
PKG = "org.pokelegza.android.port"
APK_NAME = "PokemonZA-Android-port.apk"

DEFAULT_TOOLS = Path(r"D:\feiniukexinhome\Code\d2r-and\build-tools-win")
TOOLS = Path(os.environ.get("ZA_ANDROID_TOOLS", str(DEFAULT_TOOLS)))
NDK = Path(os.environ.get("ZA_NDK", str(TOOLS / "ndk28" / "android-ndk-r28c")))


def run(args, **kw):
    print("  $", " ".join(str(a) for a in args), flush=True)
    # 编译器的输出可能是 UTF-8 或 OEM 代码页；Windows 默认 GBK 解码会炸，这里一律容错解码。
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    r = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        sys.exit("命令失败: %s" % args[0])
    return r.stdout


def tool(*parts):
    """找工具：Windows 上这些工具有 .exe / .bat 变体。"""
    base = TOOLS.joinpath(*parts)
    for cand in (base,
                 base.with_name(base.name + ".exe"),
                 base.with_name(base.name + ".bat"),
                 base.with_name(base.name + ".cmd")):
        if cand.exists():
            return cand
    sys.exit("缺少工具: %s" % base)


def java_env():
    """apksigner / keytool 是 java 程序，需要 JAVA_HOME。"""
    env = dict(os.environ)
    jdk = TOOLS / "jdk"
    if (jdk / "bin" / "java.exe").exists():
        env["JAVA_HOME"] = str(jdk)
    return env


def assert_inside(path: Path):
    """所有写操作的目标必须落在 app/ 之内 —— 防止误写到别的工程。"""
    p = path.resolve()
    if not str(p).startswith(str(ROOT.resolve())):
        sys.exit("拒绝写出 app/ 之外的路径: %s" % p)
    return p


def build_shaders():
    out = assert_inside(BUILD / "assets" / "shaders")
    out.mkdir(parents=True, exist_ok=True)
    glslc = NDK / "shader-tools" / "windows-x86_64" / "glslc.exe"
    if not glslc.exists():
        glslc = NDK / "shader-tools" / "linux-x86_64" / "glslc"
    if not glslc.exists():
        sys.exit("缺少 glslc: %s" % glslc)
    for src, stage, name in [("za.vert", "vert", "za.vert.spv"), ("za.frag", "frag", "za.frag.spv")]:
        run([glslc, "-fshader-stage=" + stage, "--target-env=vulkan1.1",
             "-O", "-o", assert_inside(out / name), ROOT / "shaders" / src])
    print("  着色器已编译 -> %s" % out)


def find_clang(suffix=""):
    """aarch64-linux-android26-clang[++][.cmd]：Windows 上是 .cmd 包装，Linux 上是普通脚本。"""
    base = NDK / "toolchains" / "llvm" / "prebuilt"
    for host in ("windows-x86_64", "linux-x86_64", "darwin-x86_64"):
        for ext in (".cmd", ""):
            p = base / host / "bin" / ("aarch64-linux-android26-clang" + suffix + ext)
            if p.exists():
                return p
    sys.exit("缺少 clang%s: %s" % (suffix, base))


# dm/ 是我们移植进来的**参考工程图形层**（NVN→Vulkan 翻译器 + 安卓呈现）：
#   gfx/nvn/      NVN 函数跳板（nvn_thunks.S 523 个计数跳板）、槽表、纹理/脏区工具
#   gfx/vulkan/   engine/ 下的 xbg_* 翻译引擎（管线、着色器、绘制、呈现）
#   android/      ANativeWindow 的 Vulkan 交换链
#   compat/       mach_absolute_time 等苹果 API 垫片
DM = ROOT / "native" / "dm"
DM_INC = [DM / "gfx" / "nvn" / "include", DM / "compat", DM / "gfx", DM / "host", DM,
          DM / "gfx" / "vulkan" / "engine" / "third_party"]
# 只排掉参考工程自带的单元测试；其余 *.c/*.cpp/*.S 全编译
DM_SKIP = ("gfx/tex/tests/",)

ZA_SRC = ["za_activity.c", "za_guest.c", "za_mod.c", "za_sdk.c", "za_horizon.c",
          "za_os.c", "za_stubs.c", "za_mem.c", "za_nvn.c", "za_sync.c", "za_vi.c",
          "za_gfx.c"]


def dm_sources():
    out = []
    for pat in ("**/*.c", "**/*.cpp", "**/*.S"):
        for p in sorted(DM.glob(pat)):
            rel = p.relative_to(DM).as_posix()
            if any(rel.startswith(s) for s in DM_SKIP):
                continue
            out.append(p)
    return out


def build_native():
    clang = find_clang()
    clangxx = find_clang("++")
    # 宿主函数自动桩要先按导入表重新生成（导入表变了，桩的索引就变了）。
    run([sys.executable, str(REPO / "tools" / "gen_stubs.py")])
    so = assert_inside(BUILD / "libzaandroid.so")
    objdir = assert_inside(BUILD / "obj")
    objdir.mkdir(parents=True, exist_ok=True)
    incs = []
    for d in DM_INC:
        incs += ["-I", str(d)]
    # -fsigned-char：Switch/苹果的 char 是有符号的，bcdec 等按有符号写
    common = ["-O2", "-g", "-fPIC", "-fvisibility=hidden", "-fsigned-char",
              "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-missing-braces",
              "-Wno-format", "-Wno-incompatible-pointer-types"] + incs
    objs = []
    srcs = [(ROOT / "native" / n, "c") for n in ZA_SRC if (ROOT / "native" / n).exists()]
    srcs += [(p, p.suffix.lstrip(".").lower()) for p in dm_sources()]
    for i, (src, kind) in enumerate(srcs):
        tag = ("%02d_" % i) + src.relative_to(ROOT / "native").with_suffix("").as_posix().replace("/", "_")
        obj = objdir / (tag + ".o")
        if kind == "cpp":
            run([clangxx, "-std=c++17"] + common + ["-c", "-o", obj, src])
        elif kind == "s":
            run([clang] + common + ["-c", "-o", obj, src])
        else:
            run([clang, "-std=gnu11"] + common + ["-c", "-o", obj, src])
        objs.append(obj)
    # 链接：C++ 代码要 clang++ 才会带 libc++_shared
    run([clangxx, "-shared", "-o", so,
         "-Wl,-z,relro,-z,now",   # ★ GOT 全只读：客机越界写打到 GOT 会立刻 SIGSEGV
         ] + objs + ["-lvulkan", "-llog", "-ldl", "-landroid", "-lm"])
    print("  原生库已编译 -> %s (%.1f KB，%d 个目标文件)"
          % (so, so.stat().st_size / 1024, len(objs)))


def find_libcxx():
    """NDK 自带的 libc++_shared.so —— 客机的 C++ ABI 符号（__cxa_* / __gxx_personality_v0）
    在 Switch 上来自 SDK 模块，安卓这边靠它顶替（ABI 相同，Itanium mangling 一致）。"""
    hits = list(NDK.glob("toolchains/llvm/prebuilt/*/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"))
    if not hits:
        sys.exit("NDK 里找不到 libc++_shared.so（客机 C++ ABI 无宿主实现）")
    return hits[0]


def build_guest_asset():
    """把 main NSO 与 SDK NSO 的段、以及运行时表打进 assets。

    - guest/        main NSO 三段 + main 的导出符号表
    - guest_sdk/   SDK NSO 三段 + SDK 导出表 + SDK 重定位表
    （段由 tools/extract_nso_mod.py 解出，运行时表由 tools/gen_sdk_tables.py 生成。）
    """
    guest = BUILD / "assets" / "guest"
    guest.mkdir(parents=True, exist_ok=True)
    src = REPO / "work" / "nso"
    for name in ("text.bin", "rodata.bin", "data.bin"):
        s = src / name
        if not s.exists():
            sys.exit("缺少客机段文件: %s（先跑 tools/extract_nso.py）" % s)
        shutil.copyfile(s, guest / name)
    # main 的导出符号表（SDK 查 nnMain/nninitStartup 用）
    sdk = REPO / "work" / "nso_sdk"
    tbl = sdk / "main_exports.bin"
    if not tbl.exists():
        sys.exit("缺少 main 导出表: %s（先跑 tools/gen_sdk_tables.py）" % tbl)
    shutil.copyfile(tbl, guest / "main_exports.bin")
    total = sum((guest / n).stat().st_size for n in os.listdir(guest))
    print("  main NSO 资产: %.1f MB" % (total / 1048576))

    sdkout = BUILD / "assets" / "guest_sdk"
    sdkout.mkdir(parents=True, exist_ok=True)
    # 段在 work/nso_<模块名>/（extract_nso_mod.py 的输出），运行时表在 work/nso_sdk/（gen_sdk_tables.py）
    sdkseg = REPO / "work" / "nso_32848007"
    for name in ("text.bin", "rodata.bin", "data.bin"):
        s = sdkseg / name
        if not s.exists():
            sys.exit("缺少 SDK 段文件: %s（先跑 tools/extract_nso_mod.py）" % s)
        shutil.copyfile(s, sdkout / name)
    for name in ("sdk_exports.bin", "sdk_relocs.bin", "sdk_gate.bin"):
        s = sdk / name
        if not s.exists():
            sys.exit("缺少 SDK 运行时表: %s（先跑 tools/gen_sdk_tables.py）" % s)
        shutil.copyfile(s, sdkout / name)
    total = sum((sdkout / n).stat().st_size for n in os.listdir(sdkout))
    print("  SDK NSO 资产: %.1f MB" % (total / 1048576))


def build_apk():
    res = assert_inside(BUILD / "res")
    if res.exists():
        shutil.rmtree(res)
    shutil.copytree(ROOT / "res", res)
    assets = assert_inside(BUILD / "assets")
    build_guest_asset()

    unsigned = assert_inside(BUILD / "unsigned.apk")
    resources = assert_inside(BUILD / "resources.zip")
    run([tool("build-tools", "aapt2"), "compile", "--dir", res, "-o", resources])
    run([tool("build-tools", "aapt2"), "link", "--manifest", ROOT / "AndroidManifest.xml",
         "-I", tool("platform", "android.jar"), "-A", assets, "-o", unsigned, resources])

    with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_STORED) as z:
        z.write(BUILD / "libzaandroid.so", "lib/arm64-v8a/libzaandroid.so")
        # C++ 运行时：客机的 __cxa_* / __gxx_personality_v0 等 ABI 符号靠它解析
        z.write(find_libcxx(), "lib/arm64-v8a/libc++_shared.so")

    aligned = assert_inside(BUILD / "aligned.apk")
    run([tool("build-tools", "zipalign"), "-f", "-P", "16", "4", unsigned, aligned])

    # 签名用**我们自己的**调试密钥（放在 app/keys/），不碰暗黑那个工程的任何东西。
    keys = assert_inside(ROOT / "keys")
    keys.mkdir(exist_ok=True)
    keystore = keys / "debug.keystore"
    if not keystore.exists():
        run([tool("jdk", "bin", "keytool"), "-genkeypair", "-keystore", keystore,
             "-storepass", "android", "-keypass", "android", "-alias", "androiddebugkey",
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
             "-dname", "CN=Android Debug,O=Android,C=US"], env=java_env())
    apk = assert_inside(BUILD / APK_NAME)
    run([tool("build-tools", "apksigner"), "sign", "--ks", keystore, "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--out", apk, aligned], env=java_env())
    run([tool("build-tools", "apksigner"), "verify", apk], env=java_env())
    print("  APK 已签名: %s (%.1f MB)" % (apk, apk.stat().st_size / 1048576))
    return apk


def main():
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)
    print("构建宝可梦 Z-A 独立 APK")
    print("  工程根目录: %s" % ROOT)
    print("  工具链    : %s" % TOOLS)
    print("  NDK       : %s" % NDK)
    if "--native-only" in sys.argv:
        # 迭代图形层时只编译 .so，不打包 APK（前面会 rmtree BUILD，这里补回来）
        build_native()
        return
    build_shaders()
    build_native()
    apk = build_apk()
    print("包名: %s   （暗黑是 org.d2r.android.port，两者可并存）" % PKG)
    if "--install" in sys.argv:
        run([tool("platform-tools", "adb"), "install", "-r", apk])
        print("已安装到设备")
    print("APK:", apk)


if __name__ == "__main__":
    main()
