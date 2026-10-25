# -*- coding: utf-8 -*-
"""按 d2r-and（已上线成品）的权威实现修正 QueryMemory 的「栈」判定，
   并把线程真实栈边界打进崩溃日志。

d2r-and hle_svc.c case 0x06 的注释原文：
  「原先对客体地址空间之外的地址一律回报『它所在的 4 KiB 页』，主线程栈于是被记成一页
    ——初始化时的 sp 与后来的 sp 是否同页，取决于宿主栈顶的绝对位置……换个环境偶发启动即中止。」
  「之后 nn::os::GetCurrentStackInfo 会断言 sp 仍在那个区间里，不在就中止。」

我们现在的实现正好踩在这个坑上：
  · 用 pthread_getattr_np 取栈，而 d2r 用的是 pthread_get_stackaddr_np/size_np；
  · 取不到时一律谎报成「Code 4KB」⇒ SDK 把主线程栈记成一页 ⇒ 后面断言失败/跳空。
"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

# ---------------------------------------------------------------- za_mem.c
mp = ROOT + r"\za_mem.c"
m = rd(mp)

old = enc("""        // 地址落在「当前宿主线程的栈」里：回报整段栈（state 0xB）。
        // SDK 初始化主线程记录时会拿当时的 sp 查这里，把这段当主线程栈；
        // 之后 nn::os::GetCurrentStackInfo 会断言 sp 仍在该区间内。
        void *top = NULL;
        size_t ssz = 0;
        pthread_attr_t attr;
        if (pthread_getattr_np(pthread_self(), &attr) == 0)
        {
            pthread_attr_getstack(&attr, &top, &ssz);
            pthread_attr_destroy(&attr);
        }
        unsigned long long t = (unsigned long long)(uintptr_t)top;
        if (ssz && addr < t && addr >= t - ssz)
        {
            base = t - ssz;
            size = ssz;
            state = 0x0B;   // Stack
            perm = 3;
        }
""")
new = enc("""        // 地址落在「当前宿主线程的栈」里：回报整段栈（state 0x0B）。
        //
        // ★ 2026-10-25：这一段是照 d2r-and（已上线成品）hle_svc.c case 0x06 改的。
        //   d2r 用的是 pthread_get_stackaddr_np / pthread_get_stacksize_np，
        //   我们原来用 pthread_getattr_np —— 取不到时就谎报成「Code 4KB」，
        //   结果 **SDK 把主线程栈记成一页**（真机上是整段栈），
        //   之后 nn::os::GetCurrentStackInfo 断言 sp 仍在该区间里 ⇒ 失败/跳空。
        //   d2r 的原注释：
        //     「原先对客体地址空间之外的地址一律回报『它所在的 4 KiB 页』，
        //       主线程栈于是被记成一页——初始化时的 sp 与后来的 sp 是否同页，
        //       取决于宿主栈顶的绝对位置，而它随环境变量/启动参数总长移动
        //       （换个环境偶发启动即中止）。」
        unsigned long long t = (unsigned long long)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
        unsigned long long ssz = (unsigned long long)pthread_get_stacksize_np(pthread_self());
        if (ssz && addr < t && addr >= t - ssz)
        {
            base = t - ssz;
            size = ssz;
            state = 0x0B;   // Stack
            perm = 3;
        }
""")
if b"pthread_get_stackaddr_np" not in m:
    assert old in m, "za_mem.c 栈判定块没找到"
    m = m.replace(old, new, 1)
    wr(mp, m)
    print("[mem] QueryMemory 栈判定改用 pthread_get_stackaddr_np/size_np")
else:
    print("[mem] 已改")

# ---------------------------------------------------------------- 崩溃日志里打线程真实栈边界
gp = ROOT + r"\za_guest.c"
g = rd(gp)
if "真实栈边界".encode("utf-8") not in g:
    old2 = enc("""        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);
""")
    new2 = enc("""        // ★ 崩溃线程的**真实栈边界**（bionic 专用 API）：
        //   用来核对「客机实际跑在哪个栈上」——之前登记的 256MB 客机栈
        //   与崩溃时的 sp 根本不在同一段里 ⇒ sp 落在了 PROT_NONE 区。
        {
            char bb[192];
            char *q = bb;
            q = za_put_str(q, "ZaGuest: 真实栈边界 top=");
            q = za_put_hex(q, (unsigned long long)(uintptr_t)pthread_get_stackaddr_np(pthread_self()));
            q = za_put_str(q, " size=");
            q = za_put_hex(q, (unsigned long long)pthread_get_stacksize_np(pthread_self()));
            q = za_put_str(q, " sp=");
            q = za_put_hex(q, (unsigned long long)uc->uc_mcontext.sp);
            q = za_put_str(q, "\\n");
            size_t l = (size_t)(q - bb);
            ssize_t w = write(2, bb, l); (void)w;
            if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, bb, l); (void)w2; }
        }
        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);
""")
    assert old2 in g, "za_log_guest_trace 调用点没找到"
    g = g.replace(old2, new2, 1)
    wr(gp, g)
    print("[guest] 崩溃日志加「真实栈边界」")
else:
    print("[guest] 已有")

print("done")
