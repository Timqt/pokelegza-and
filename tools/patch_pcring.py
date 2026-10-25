# -*- coding: utf-8 -*-
"""PC 环分两档打印：
   · 落在 main/sdk 映像里的 = 可信样本（客机真在这儿执行）
   · 其它地址（ART boot image 等）= 不可信样本，单独归类，避免干扰判断
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

if b"pc#G" not in g:
    old = enc("""        // 崩溃前的客机 PC 轨迹（最近 32 个采样点）
        {
            unsigned long pos = za_pc_ring_pos;
            int n = (pos > 32) ? 32 : (int)pos;
            for (int i = 0; i < n; i++)
            {
                unsigned long long p = za_pc_ring[(pos - (unsigned long)n + (unsigned long)i) % ZA_PC_RING];
""")
    new = enc("""        // 崩溃前的客机 PC 轨迹（最近 32 个采样点）
        //
        // ★ 分两档打印：
        //   「pc#G」= 落在 main/sdk 映像里的 —— **可信**，客机确实在这儿执行；
        //   「pc#X」= 其它地址 —— 不可信（实测采样器会取到 ART boot image 这类
        //   不可执行的数据区地址，说明信号投递时机/上下文读取有问题），
        //   单独归类，免得把噪音当成客机的行踪。
        {
            unsigned long pos = za_pc_ring_pos;
            int n = (pos > 32) ? 32 : (int)pos;
            unsigned long bm = za_guest_base, sm = za_sdk_base;
            for (int pass = 0; pass < 2; pass++)
            {
            for (int i = 0; i < n; i++)
            {
                unsigned long long p = za_pc_ring[(pos - (unsigned long)n + (unsigned long)i) % ZA_PC_RING];
                int is_guest = (bm && p >= bm && p < bm + ZA_IMAGE_SIZE) ||
                               (sm && p >= sm && p < sm + za_sdk_size);
                if ((pass == 0) != (is_guest != 0)) continue;
""")
    assert old in g, "PC 环打印块没找到"
    g = g.replace(old, new, 1)

    old2 = enc("""                char buf[256];
                char *q = buf;
                q = za_put_str(q, "ZaGuest: pc#");
                q = za_put_hex(q, (unsigned long long)i);
""")
    new2 = enc("""                char buf[256];
                char *q = buf;
                q = za_put_str(q, is_guest ? "ZaGuest: pc#G" : "ZaGuest: pc#X");
                q = za_put_hex(q, (unsigned long long)i);
""")
    assert old2 in g, "pc# 标签没找到"
    g = g.replace(old2, new2, 1)

    # 关掉内层循环 + 加上外层 pass 循环的收尾
    old3 = enc("""                q = za_put_str(q, "\\n");
                size_t len = (size_t)(q - buf);
                ssize_t w = write(2, buf, len);
                (void)w;
                if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, buf, len); (void)w2; }
            }
        }
        // 解析崩溃 PC 落在哪个库/符号（诊断用；dladdr 不是异步信号安全的，
""")
    new3 = enc("""                q = za_put_str(q, "\\n");
                size_t len = (size_t)(q - buf);
                ssize_t w = write(2, buf, len);
                (void)w;
                if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, buf, len); (void)w2; }
            }
            }
        }
        // 解析崩溃 PC 落在哪个库/符号（诊断用；dladdr 不是异步信号安全的，
""")
    assert old3 in g, "PC 环循环收尾没找到"
    g = g.replace(old3, new3, 1)

    wr(gp, g)
    print("[guest] PC 环分「可信/不可信」两档打印")
else:
    print("[guest] 已分档")

print("done")
