#!/usr/bin/env python3
"""ONEPACK reader — Game Freak 的 TRPFS / TRPFD / TRPAK 三件套。

格式（据 psthrn42/SCVI_Extract 的 schemas 与 Scarlet/Violet 泄露版实测）：

  TRPFS (data.trpfs)
    [0:8]    b'ONEPACK\\0'
    [8:12]   u32 init_offset   —— FlatBuffers 区起点
    [12:init] 文件数据区（各文件按 file_offsets 定位）
    [init:init+size] FlatBuffer（root 在 buffer[0] 的 uoffset）
      table TRPFS { hashes: [uint64]; file_offsets: [uint64]; }

  TRPFD (data.trpfd)
    整个文件就是一个 FlatBuffer
      table TRPFD { file_hashes: [uint64]; paths: [string];
                    map: [MapTable{index:u32; u64s:EmptyTable}];
                    info: [InfoTable{size:u64; count:u64}]; }

  TRPAK (内嵌归档)
      table TRPAK { hashes: [uint64]; files: [File{unused:u8;
                   compression_type:u8; unk1:u8; decompressed_size:u64;
                   data:[u8]}]}; }

本脚本只做纯 Python 解析，不依赖 flatc / flatbuffers 包。
"""

import argparse
import json
import os
import struct
import sys

MASK64 = (1 << 64) - 1
FNV_PRIME = 1099511628211
FNV_OFFSET = 14695981039346656037


def fnv1a64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


class FB:
    """极简 FlatBuffers 读取器（够用即可：标量 / 向量 / 字符串 / 表向量）。"""

    def __init__(self, buf: bytes):
        self.b = buf

    # --- 原始读取 ---
    def u8(self, p):
        return self.b[p]

    def u16(self, p):
        return struct.unpack_from("<H", self.b, p)[0]

    def u32(self, p):
        return struct.unpack_from("<I", self.b, p)[0]

    def i32(self, p):
        return struct.unpack_from("<i", self.b, p)[0]

    def u64(self, p):
        return struct.unpack_from("<Q", self.b, p)[0]

    def root(self):
        return self.u32(0)

    # --- 表 ---
    def vtable(self, table_pos):
        soffset = self.i32(table_pos)
        vt = table_pos - soffset
        vtsize = self.u16(vt)
        n = max(0, (vtsize - 4) // 2)
        return [self.u16(vt + 4 + 2 * i) for i in range(n)]

    def field(self, table_pos, idx):
        """返回字段所在绝对位置；None = 字段缺省。"""
        vt = self.vtable(table_pos)
        if idx >= len(vt):
            return None
        off = vt[idx]
        if off == 0:
            return None
        return table_pos + off

    def scalar(self, table_pos, idx, kind, default=0):
        p = self.field(table_pos, idx)
        if p is None:
            return default
        return getattr(self, kind)(p)

    def vector(self, field_pos):
        """返回 (首元素绝对位置, 元素个数)。"""
        vp = field_pos + self.u32(field_pos)
        n = self.u32(vp)
        return vp + 4, n

    def vec_u64(self, table_pos, idx):
        p = self.field(table_pos, idx)
        if p is None:
            return []
        start, n = self.vector(p)
        return list(struct.unpack_from("<%dQ" % n, self.b, start))

    def vec_u32(self, table_pos, idx):
        p = self.field(table_pos, idx)
        if p is None:
            return []
        start, n = self.vector(p)
        return list(struct.unpack_from("<%dI" % n, self.b, start))

    def vec_u8(self, table_pos, idx):
        p = self.field(table_pos, idx)
        if p is None:
            return []
        start, n = self.vector(p)
        return self.b[start:start + n]

    def vec_string(self, table_pos, idx):
        p = self.field(table_pos, idx)
        if p is None:
            return []
        start, n = self.vector(p)
        out = []
        for i in range(n):
            sp = start + i * 4
            spos = sp + self.u32(sp)
            ln = self.u32(spos)
            out.append(self.b[spos + 4:spos + 4 + ln].decode("utf-8", "replace"))
        return out

    def vec_table(self, table_pos, idx):
        p = self.field(table_pos, idx)
        if p is None:
            return []
        start, n = self.vector(p)
        out = []
        for i in range(n):
            sp = start + i * 4
            out.append(sp + self.u32(sp))
        return out


class Trpfs:
    """data.trpfs：magic(8) + u64 init_offset，数据区 [12,init)，
    尾部 [init,EOF) 是 FlatBuffer { hashes:[u64], file_offsets:[u64] }。
    Z-A 里每个条目 = 一个 .trpak 内嵌归档（按路径分块），不是单文件。"""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        with open(path, "rb") as f:
            magic = f.read(8)
            if magic[:7] != b"ONEPACK":
                raise ValueError("不是 ONEPACK: %r" % magic)
            self.init_offset = struct.unpack("<Q", f.read(8))[0]
            f.seek(self.init_offset)
            buf = f.read(self.size - self.init_offset)
        self.fb = FB(buf)
        self.root = self.fb.root()
        self.hashes = self.fb.vec_u64(self.root, 0)
        self.offsets = self.fb.vec_u64(self.root, 1)
        self.f = open(path, "rb")

    def count(self):
        return len(self.hashes)

    def size_of(self, i):
        if i + 1 < len(self.offsets):
            return self.offsets[i + 1] - self.offsets[i]
        return self.init_offset - self.offsets[i]

    def read(self, i, max_bytes=None):
        off = self.offsets[i]
        ln = self.size_of(i)
        if max_bytes is not None:
            ln = min(ln, max_bytes)
        self.f.seek(off)
        return self.f.read(ln)

    def close(self):
        self.f.close()


class Trpfd:
    def __init__(self, path):
        data = open(path, "rb").read()
        self.fb = FB(data)
        root = self.fb.root()
        self.file_hashes = self.fb.vec_u64(root, 0)
        self.paths = self.fb.vec_string(root, 1)
        self.map = self.fb.vec_table(root, 2)
        self.info = self.fb.vec_table(root, 3)
        # MapTable.index -> paths 索引；u64s 子表里装的是每个文件的 u64 元数据
        self.map_index = [self.fb.scalar(t, 0, "u32") for t in self.map]
        self.map_u64s = []
        for t in self.map:
            p = self.fb.field(t, 1)
            if p is None:
                self.map_u64s.append([])
                continue
            sub = p + self.fb.u32(p)          # 子表位置
            vals = []
            for idx in range(8):
                q = self.fb.field(sub, idx)
                if q is None:
                    break
                vals.append(self.fb.u64(q))
            self.map_u64s.append(vals)
        self.info_rows = [
            (self.fb.scalar(t, 0, "u64"), self.fb.scalar(t, 1, "u64"))
            for t in self.info
        ]

    def hash_to_path(self):
        """建 hash -> path 映射。

        两种口径都试：
          A) map[i].index -> paths[map[i].index]，hash 取 file_hashes 对应项
          B) file_hashes[i] -> paths[i]
        返回 (映射, 口径名)
        """
        m = {}
        # 口径 A：map 的 index 指向 paths
        for i, t in enumerate(self.map):
            if i < len(self.file_hashes) and self.map_index[i] < len(self.paths):
                h = self.file_hashes[i]
                m.setdefault(h, self.paths[self.map_index[i]])
        if len(m) >= len(self.paths) * 0.5:
            return m, "map-index"
        # 口径 B：平行数组
        m2 = {}
        for i, h in enumerate(self.file_hashes):
            if i < len(self.paths):
                m2.setdefault(h, self.paths[i])
        return m2, "parallel"


def safe_join(root, rel):
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(root, *parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trpfs", required=True)
    ap.add_argument("--trpfd")
    ap.add_argument("--out")
    ap.add_argument("--list", type=int, default=20, help="列出前 N 条")
    ap.add_argument("--filter", help="路径子串过滤（配合 --extract）")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--max-file-size", type=int, default=64 << 20)
    ap.add_argument("--json")
    args = ap.parse_args()

    tfs = Trpfs(args.trpfs)
    n = tfs.count()
    print("TRPFS: %s" % args.trpfs)
    print("  文件大小: %d" % tfs.size)
    print("  init_offset: %d" % tfs.init_offset)
    print("  条目数: %d" % n)
    if len(tfs.offsets) != n:
        print("  [!] hashes=%d 但 file_offsets=%d" % (n, len(tfs.offsets)))

    h2p = {}
    mode = None
    if args.trpfd and os.path.exists(args.trpfd):
        tfd = Trpfd(args.trpfd)
        h2p, mode = tfd.hash_to_path()
        print("  TRPFD: file_hashes=%d paths=%d map=%d info=%d  口径=%s 映射=%d"
              % (len(tfd.file_hashes), len(tfd.paths), len(tfd.map), len(tfd.info), mode, len(h2p)))
        print("  info 前 5 行 (size,count): %s" % tfd.info_rows[:5])
        print("  路径样例: %s" % tfd.paths[:5])

    print("--- 前 %d 条 ---" % args.list)
    for i in range(min(args.list, n)):
        path = h2p.get(tfs.hashes[i])
        print("  [%6d] off=%12d size=%10d  %s"
              % (i, tfs.offsets[i], tfs.size_of(i), path or "<未映射>"))

    if args.extract:
        out = args.out or "out"
        os.makedirs(out, exist_ok=True)
        written = 0
        skipped = 0
        for i in range(n):
            path = h2p.get(tfs.hashes[i])
            if path is None:
                skipped += 1
                continue
            if args.filter and args.filter not in path:
                continue
            sz = tfs.size_of(i)
            if sz > args.max_file_size:
                skipped += 1
                continue
            dst = safe_join(out, path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as g:
                g.write(tfs.read(i))
            written += 1
            if written % 2000 == 0:
                print("  ... 已写出 %d" % written, flush=True)
        print("写出 %d 个文件，跳过 %d 个" % (written, skipped))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as g:
            json.dump({
                "count": n,
                "init_offset": tfs.init_offset,
                "entries": [
                    {"index": i, "offset": tfs.offsets[i], "size": tfs.size_of(i),
                     "path": h2p.get(tfs.hashes[i]),
                     "hash": "%016x" % tfs.hashes[i]}
                    for i in range(n)
                ],
            }, g, ensure_ascii=False, indent=1)
        print("索引已写出: %s" % args.json)

    tfs.close()


if __name__ == "__main__":
    main()
