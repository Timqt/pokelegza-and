#!/usr/bin/env python3
"""诊断 Oodle 解压：检查输出非零密度，并尝试不同的 oo2core 参数组合。"""

import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
DLL = os.path.join(ROOT, "work", "oodle", "oo2core_3_win64.dll")
FNV_BASIS = 0xCBF29CE484222645
FNV_PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    h = FNV_BASIS
    for ch in path:
        h ^= ord(ch)
        h = (h * FNV_PRIME) & MASK
    return h


def load():
    dll = ctypes.CDLL(DLL)
    fn = dll.OodleLZ_Decompress
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                   ctypes.c_uint, ctypes.c_uint, ctypes.c_ulonglong, ctypes.c_uint,
                   ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                   ctypes.c_uint, ctypes.c_int]
    return dll, fn


def get_chunk(name_contains, idx=0):
    tfs = Trpfs(os.path.join(ARC, "data.trpfs"))
    tfd = Trpfd(os.path.join(ARC, "data.trpfd"))
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)
    for i in range(tfs.count()):
        p = h2p.get(tfs.hashes[i], [""])[0]
        if name_contains in p:
            blob = tfs.read(i)
            fb = FB(blob)
            root = fb.root()
            tabs = fb.vec_table(root, 1)
            t = tabs[idx]
            enc = fb.scalar(t, 1, "u8", 255)
            size = fb.scalar(t, 3, "u64", 0)
            d = fb.field(t, 4)
            ds, n = fb.vector(d)
            raw = blob[ds:ds + n]
            print("块 %s idx=%d enc=%d comp=%d raw=%d head=%s"
                  % (p, idx, enc, n, size, raw[:12].hex(" ")))
            tfs.close()
            return raw, size
    tfs.close()
    raise SystemExit("没找到 " + name_contains)


def attempt(raw, size, dst_len=None, status=None, tm=3, label=""):
    dll, fn = load()
    src = ctypes.create_string_buffer(raw, len(raw))
    dl = dst_len or size
    dst = ctypes.create_string_buffer(dl)
    cptr = ctypes.cast(status, ctypes.c_ulonglong) if status is not None else 0
    r = fn(src, len(raw), dst, dl, 0, 0, cptr, 0, 0, 0, 0, 0, 0, tm)
    nz = sum(1 for b in dst.raw[:dl] if b)
    head = dst.raw[:16]
    print("  %-28s ret=%-4d nonzero=%-9d head=%s" % (label, r, nz, head.hex(" ")))
    return dst.raw[:dl], nz


def main():
    raw, size = get_chunk("specialimgui")
    print("尝试不同的参数组合：")
    attempt(raw, size, tm=0, label="tm=0")
    attempt(raw, size, tm=1, label="tm=1")
    attempt(raw, size, tm=2, label="tm=2")
    attempt(raw, size, tm=3, label="tm=3")
    for mult in (1, 3, 4):
        st = ctypes.create_string_buffer(max(1024, size * mult))
        attempt(raw, size, status=st, tm=3, label="status buf x%d" % mult)
        attempt(raw, size, status=st, tm=0, label="status x%d tm=0" % mult)
    # 试着把状态缓冲放到 d/e/f/g 各个参数位
    st = ctypes.create_string_buffer(max(1024, size * 4))
    dll, fn = load()
    src = ctypes.create_string_buffer(raw, len(raw))
    dst = ctypes.create_string_buffer(size)
    for slot in range(4):
        args = [0] * 10
        args[slot] = ctypes.cast(st, ctypes.c_ulonglong).value
        r = fn(src, len(raw), dst, size, args[0], args[1], args[2], args[3], args[4],
               args[5], args[6], args[7], args[8], 3)
        nz = sum(1 for b in dst.raw[:size] if b)
        print("  status->arg%-9d ret=%-4d nonzero=%-9d head=%s"
              % (slot, r, nz, dst.raw[:16].hex(" ")))


if __name__ == "__main__":
    main()
