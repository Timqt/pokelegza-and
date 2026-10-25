#!/usr/bin/env python3
"""把 SDK 的 58 个 Horizon svc 包装函数全部反汇编出来。

这些函数是 Horizon 系统调用的 ABI 权威：每个 svc 号一个，
从它的 prologue/epilogue 能读出「哪些参数是入参、哪些是出参、结果在哪」。
"""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
OBJDUMP = os.path.join(ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
                       "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")
TEXT_SZ = 0x64E230

# switchbrew 的服务名（1..0x2E 已确认；更高的先留空）
NAMES = {
    1: "SetHeapSize", 2: "SetMemoryPermission", 3: "SetMemoryAttribute",
    4: "MapMemory", 5: "UnmapMemory", 6: "QueryMemory", 7: "ExitProcess",
    8: "CreateThread", 9: "StartThread", 10: "ExitThread", 11: "SleepThread",
    12: "GetThreadPriority", 13: "SetThreadPriority", 14: "GetThreadCoreMask",
    15: "SetThreadCoreMask", 16: "GetCurrentProcessorNumber", 17: "SignalEvent",
    18: "ClearEvent", 19: "MapSharedMemory", 20: "UnmapSharedMemory",
    21: "CreateTransferMemory", 22: "CloseHandle", 23: "ResetSignal",
    24: "WaitSynchronization", 25: "CancelSynchronization", 26: "ArbitrateLock",
    27: "ArbitrateUnlock", 28: "WaitProcessWideKeyAtomic", 29: "SignalProcessWideKey",
    30: "GetSystemTick", 31: "ConnectToNamedPort", 32: "SendSyncRequestLight",
    33: "SendSyncRequest", 34: "SendSyncRequestWithUserBuffer",
    35: "SendAsyncRequestWithUserBuffer", 36: "GetProcessId", 37: "GetThreadId",
    38: "Break", 39: "OutputDebugString", 40: "ReturnFromException", 41: "GetInfo",
    42: "FlushEntireDataCache", 43: "FlushDataCache", 44: "MapPhysicalMemory",
    45: "UnmapPhysicalMemory", 46: "GetFutureThreadInfo",
}


def load():
    d = open(NSO, "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = out
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    IMG = bytearray(dmo + dsz + bss)
    for mo, sz, raw in out:
        IMG[mo:mo + sz] = raw
    return IMG


def wrap_elf(text, vaddr):
    shstr = b"\0.shstrtab\0.text\0"
    ehsize, phentsize = 64, 56
    phoff = ehsize
    dataoff = (phoff + phentsize + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15
    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, vaddr, phoff, shoff, 0,
                     ehsize, phentsize, 56, 64, 3, 2)
    e += struct.pack("<IIQQQQQQ", 1, 5, dataoff, vaddr, vaddr, len(text), len(text), 0x1000)
    e += b"\0" * (dataoff - len(e))
    e += text
    e += shstr
    e += b"\0" * (shoff - len(e))
    e += bytes(64)
    e += struct.pack("<IIQQQQIIQQ", 1, 1, 6, vaddr, dataoff, len(text), 0, 0, 8, 0)
    e += struct.pack("<IIQQQQIIQQ", 2, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


def disasm(IMG, addr, length):
    piece = bytes(IMG[addr:addr + length])
    elf = wrap_elf(piece, addr)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    out = []
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("Disassembly") or s.startswith("/") or "ELF" in s or s.startswith("<"):
            continue
        out.append(s)
    return out


def main():
    IMG = load()
    svcs = []
    for off in range(0, TEXT_SZ, 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        if (w & 0xFFE0001F) == 0xD4000001:
            svcs.append((off, (w >> 5) & 0xFFFF))
    svcs.sort()
    # 只保留那一段连续的包装函数区
    lo = min(o for o, _ in svcs)
    hi = max(o for o, _ in svcs)
    print("包装函数区 %#x..%#x，共 %d 个 svc" % (lo, hi, len(svcs)))
    lines = disasm(IMG, lo - 0x10, hi - lo + 0x60)
    num = {o: n for o, n in svcs}
    for l in lines:
        # 标出 svc 行，附上服务号和名字
        try:
            a = l.split(":")[0].strip()
            off = int(a, 16)
        except Exception:
            print("   " + l)
            continue
        mark = ""
        if off in num:
            n = num[off]
            mark = "   <<<< svc #%d %s" % (n, NAMES.get(n, "?"))
        print("   %s%s" % (l, mark))


if __name__ == "__main__":
    main()
