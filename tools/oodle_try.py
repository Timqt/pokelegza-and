#!/usr/bin/env python3
"""单个 (DLL, 签名) 组合的 Oodle 解压试验。用法: python tools\\oodle_try.py <dll> <sig>"""

import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
FNV_BASIS = 0xCBF29CE484222645
FNV_PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    h = FNV_BASIS
    for ch in path:
        h ^= ord(ch)
        h = (h * FNV_PRIME) & MASK
    return h


def get_chunk(needle="specialimgui", idx=0):
    tfs = Trpfs(os.path.join(ARC, "data.trpfs"))
    tfd = Trpfd(os.path.join(ARC, "data.trpfd"))
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)
    for i in range(tfs.count()):
        p = h2p.get(tfs.hashes[i], [""])[0]
        if needle in p:
            blob = tfs.read(i)
            fb = FB(blob)
            tabs = fb.vec_table(fb.root(), 1)
            t = tabs[idx]
            size = fb.scalar(t, 3, "u64", 0)
            d = fb.field(t, 4)
            ds, n = fb.vector(d)
            raw = blob[ds:ds + n]
            tfs.close()
            return raw, size
    tfs.close()
    raise SystemExit("not found")


def main():
    dll_path = sys.argv[1]
    sig = sys.argv[2]
    raw, size = get_chunk()
    dll = ctypes.CDLL(dll_path)
    src = ctypes.create_string_buffer(raw, len(raw))
    dst = ctypes.create_string_buffer(size)
    scratch = ctypes.create_string_buffer(4 << 20)

    if sig == "legacy7":
        fn = dll.OodleLZ_Decompress
        fn.restype = ctypes.c_longlong
        fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                       ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        r = fn(src, len(raw), dst, size, 0, 0, None)
    elif sig == "legacy9":
        fn = dll.OodleLZ_Decompress
        fn.restype = ctypes.c_longlong
        fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                       ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        r = fn(src, len(raw), dst, size, 0, 0, None, None, 0)
    elif sig == "legacy14":
        fn = dll.OodleLZ_Decompress
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                       ctypes.c_uint, ctypes.c_uint, ctypes.c_ulonglong, ctypes.c_uint,
                       ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                       ctypes.c_uint, ctypes.c_int]
        r = fn(src, len(raw), dst, size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3)
    elif sig == "decoder8":
        fn = dll.OodleLZDecoder_Decode
        fn.restype = ctypes.c_longlong
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p,
                       ctypes.c_longlong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_longlong]
        r = fn(None, src, len(raw), dst, size, None, scratch, len(scratch))
    else:
        raise SystemExit("未知签名 " + sig)

    nz = sum(1 for b in dst.raw[:size] if b)
    print("RESULT dll=%s sig=%s ret=%s nonzero=%d/%d head=%s"
          % (os.path.basename(dll_path), sig, r, nz, size, dst.raw[:16].hex(" ")))


if __name__ == "__main__":
    main()
