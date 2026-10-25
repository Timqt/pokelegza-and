#!/usr/bin/env python3
"""生成「未实现宿主函数」的自动桩。

客机 NSO 里有近千个 nn::* 的导入，安卓上根本不存在这些符号。
逐个手写不现实，但**完全不给桩**也不行 —— 客机一调就跳飞。

这里的做法：给每个导入生成一个**专属**的桩函数
    uint64_t za_stub_N(void) { za_stub_hit(N); return 0; }
桩在被调用时打印自己的符号名（每个符号只打第一次，之后计数），
这样一次实机跑下来就能拿到「游戏到底调了哪些 nn::*」的完整清单，
再按清单把真正要实现的那几十个换成真实现。

用法:
    python tools/gen_stubs.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
IMPORTS = APP / "native" / "za_imports.h"
OUT_C = APP / "native" / "za_stubs.c"
OUT_H = APP / "native" / "za_stub.h"

ENTRY = re.compile(r'\{\s*"((?:[^"\\]|\\.)*)"\s*,\s*(0x[0-9a-fA-F]+|\d+)[uUlL]*\s*\}')


def parse_imports():
    text = IMPORTS.read_text(encoding="utf-8")
    out = []
    for name, slot in ENTRY.findall(text):
        out.append((name, int(slot, 0)))
    if not out:
        sys.exit("在 %s 里没解析出导入表" % IMPORTS)
    return out


def main():
    imports = parse_imports()
    n = len(imports)

    lines = [
        "// 自动生成：tools/gen_stubs.py —— 别手改，重新跑生成器。",
        "//",
        "// 每个客机导入对应一个专属桩；桩被调用时打印符号名（每个符号只打一次），",
        "// 返回 0。nn::Result 的 0 就是「成功」，多数查询类函数这样就够用了。",
        "#include <stdint.h>",
        '#include "za_stub.h"',
        "",
    ]
    for i in range(n):
        # 桩体里要临时切回 bionic 的 TLS（printf/log 要用），再切回客机的那块。
        lines.append("uint64_t za_stub_%d(void) { za_tls_enter(); za_stub_hit(%d); za_tls_leave(); return 0; }" % (i, i))
    lines.append("")
    lines.append("const void *const za_stub_table[ZA_STUB_COUNT] = {")
    for i in range(n):
        lines.append("    (const void *)za_stub_%d," % i)
    lines.append("};")
    lines.append("")
    OUT_C.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    OUT_H.write_text(
        "// 自动生成：tools/gen_stubs.py\n"
        "#ifndef ZA_STUB_H\n#define ZA_STUB_H\n"
        "#define ZA_STUB_COUNT %d\n"
        "#define ZA_IMPORT_COUNT %d\n"
        "// 桩被调用时上报符号名（索引对应 za_imports[] 的下标）。\n"
        "void za_stub_hit(unsigned index);\n"
        "// 宿主函数调用前后临时切换 TPIDR_EL0（客机用自己的线程上下文，宿主用 bionic 的）。\n"
        "void za_tls_enter(void);\n"
        "void za_tls_leave(void);\n"
        "extern const void *const za_stub_table[ZA_STUB_COUNT];\n"
        "#endif\n" % (n, n),
        encoding="utf-8", newline="\n")

    print("生成 %d 个宿主桩 -> %s" % (n, OUT_C))


if __name__ == "__main__":
    main()
