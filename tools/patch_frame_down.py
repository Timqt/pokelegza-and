# -*- coding: utf-8 -*-
"""★ 帧 dump 必须覆盖 sp **下方** ★

实测：崩溃时 sp 落在构造函数帧的内部（+0x60），而保存 x29/x30 的槽
（构造函数帧的 +0x40/+0x48）在 **sp 下方 0x20/0x18** 处 ——
原来只 dump sp 往上的 0x200 字节，**从来没看到过那两个槽**，
所以「x30=0」查不到来源。

改成：dump sp-0x100 .. sp+0x200，并把落在 main/sdk 映像里的字标出来。
"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

gp = ROOT + r"\za_guest.c"
g = rd(gp)

old = enc("""    {
        char line[512];
        unsigned long w[8];
        for (int r = 0; r < 64; r += 8)
        {
            int ok = 1;
            for (int i = 0; i < 8; i++)
                if (!za_read_word(sp + (unsigned long)(r + i) * 8, &w[i])) ok = 0;
            if (!ok) break;
            char *p = line;
            p = za_put_str(p, "ZaGuest: frame+");
            p = za_put_hex(p, (unsigned long long)(r * 8));
            for (int i = 0; i < 8; i++)
            {
                p = za_put_str(p, " ");
                p = za_put_hex(p, (unsigned long long)w[i]);
            }
            p = za_put_str(p, "\\n");
            size_t len = (size_t)(p - line);
            ssize_t w2 = write(2, line, len);
            (void)w2;
            if (za_crash_fd >= 0) { ssize_t w3 = write(za_crash_fd, line, len); (void)w3; }
        }
    }
""")
new = enc("""    {
        // ★ 从 sp-0x100 往上 dump 到 sp+0x200：
        //   崩溃时 sp 常常落在**某个函数帧的内部**（实测：sp = 构造函数的帧+0x60），
        //   而那个函数保存 x29/x30 的槽在 **sp 下方**（-0x20/-0x18）——
        //   只 dump sp 往上的话，那两个槽**从来没被看到过**，「x30=0」就永远查不到来源。
        char line[640];
        unsigned long w[8];
        unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
        for (int r = -32; r < 64; r += 8)
        {
            unsigned long addr = sp + (unsigned long)(int64_t)(r * 8);
            int ok = 1;
            for (int i = 0; i < 8; i++)
                if (!za_read_word(addr + (unsigned long)i * 8, &w[i])) ok = 0;
            if (!ok) continue;
            char *p = line;
            p = za_put_str(p, r < 0 ? "ZaGuest: frame-" : "ZaGuest: frame+");
            p = za_put_hex(p, (unsigned long long)(r < 0 ? -(unsigned long long)(r * 8)
                                                       : (unsigned long long)(r * 8)));
            for (int i = 0; i < 8; i++)
            {
                p = za_put_str(p, " ");
                p = za_put_hex(p, (unsigned long long)w[i]);
                // 落在 main/sdk 映像里的字 = 可能是返回地址 ⇒ 标一下
                if ((bm && w[i] >= bm && w[i] < bm + ZA_IMAGE_SIZE) ||
                    (sm && w[i] >= sm && w[i] < sm + za_sdk_size))
                {
                    p = za_put_str(p, "*");
                    if (bm && w[i] >= bm && w[i] < bm + ZA_IMAGE_SIZE)
                        p = za_put_str(p, "main+");
                    else
                        p = za_put_str(p, "sdk+");
                    p = za_put_hex(p, (unsigned long long)((bm && w[i] >= bm && w[i] < bm + ZA_IMAGE_SIZE)
                                                         ? w[i] - bm : w[i] - sm));
                }
            }
            p = za_put_str(p, "\\n");
            size_t len = (size_t)(p - line);
            ssize_t w2 = write(2, line, len);
            (void)w2;
            if (za_crash_fd >= 0) { ssize_t w3 = write(za_crash_fd, line, len); (void)w3; }
        }
    }
""")
if b"frame-" not in g:
    assert old in g, "帧 dump 块没找到"
    g = g.replace(old, new, 1)
    wr(gp, g)
    print("[guest] 帧 dump 扩展到 sp 下方 + 标注客机返回地址")
else:
    print("[guest] 已扩展")

print("done")
