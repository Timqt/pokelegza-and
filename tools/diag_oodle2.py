#!/usr/bin/env python3
"""找出能正确解 Z-A Oodle 数据的 (DLL, 调用签名) 组合。"""

import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
OODLE_DIR = os.path.join(ROOT, "work", "oodle")
FNV_BASIS = 0xCBF29CE484222645
FNV_PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    h = FNV_BASIS
    for ch in path:
        h ^= ord(ch)
        h = (h * FNV_PRIME) & MASK
    return h


def get_chunk(needle, idx=0):
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


def sig_legacy7(dll):
    fn = dll.OodleLZ_Decompress
    fn.restype = ctypes.c_longlong
    fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                   ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    return fn, "legacy7"


def sig_legacy9(dll):
    fn = dll.OodleLZ_Decompress
    fn.restype = ctypes.c_longlong
    fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                   ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    return fn, "legacy9"


def sig_legacy14(dll):
    fn = dll.OodleLZ_Decompress
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                   ctypes.c_uint, ctypes.c_uint, ctypes.c_ulonglong, ctypes.c_uint,
                   ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                   ctypes.c_uint, ctypes.c_int]
    return fn, "legacy14"


def sig_decoder(dll):
    fn = dll.OodleLZDecoder_Decode
    fn.restype = ctypes.c_longlong
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p,
                   ctypes.c_longlong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_longlong]
    return fn, "decoder8"


SIGS = [sig_legacy7, sig_legacy9, sig_legacy14, sig_decoder]


def try_all(dll_path, raw, size):
    print("=== %s ===" % os.path.basename(dll_path))
    try:
        dll = ctypes.CDLL(dll_path)
    except OSError as e:
        print("   加载失败:", e)
        return
    exports = [n for n in ("OodleLZ_Decompress", "OodleLZDecoder_Decode",
                            "OodleLZ_GetInternalDecompressSize", "OodleLZ_GetDecodeBufferSize")
               if hasattr(dll, n)]
    print("   导出:", exports)
    src = ctypes.create_string_buffer(raw, len(raw))
    for maker in SIGS:
        try:
            fn, name = maker(dll)
        except AttributeError:
            continue
        dst = ctypes.create_string_buffer(size)
        try:
            if name == "legacy7":
                r = fn(src, len(raw), dst, size, 0, 0, None)
            elif name == "legacy9":
                r = fn(src, len(raw), dst, size, 0, 0, None, None, 0)
            elif name == "legacy14":
                r = fn(src, len(raw), dst, size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3)
            else:
                r = fn(None, src, len(raw), dst, size, None, None, 0)
        except Exception as e:
            print("   %-9s 调用异常 %s" % (name, e))
            continue
        nz = sum(1 for b in dst.raw[:size] if b)
        print("   %-9s ret=%-10d nonzero=%-9d head=%s"
              % (name, r, nz, dst.raw[:16].hex(" ")))


def main():
    raw, size = get_chunk("specialimgui")
    print("样本: comp=%d raw=%d head=%s" % (len(raw), size, raw[:12].hex(" ")))
    for f in sorted(os.listdir(OODLE_DIR)):
        if f.lower().endswith(".dll"):
            try_all(os.path.join(OODLE_DIR, f), raw, size)


if __name__ == "__main__":
    main()
