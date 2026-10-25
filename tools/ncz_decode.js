// NCZ -> 明文块：用 Node 自带 zstd 暴力定位压缩流起点并解出 FS 段。
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

const NCZ = String.raw`D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.ncz`;
const OUT = String.raw`D:\feiniukexinhome\Code\pokeLegza-and\work\ncz-probe`;

// 从若干候选偏移尝试解一个 zstd frame，看哪个位置能出数据
function tryZstd(start, limit = 8 * 1024 * 1024) {
  return new Promise((resolve) => {
    const d = zlib.createZstdDecompress();
    let got = 0, done = false;
    d.on('data', (c) => { got += c.length; });
    d.on('error', (e) => { if (!done) { done = true; resolve({ ok: false, err: e.message, got }); } });
    d.on('end', () => { if (!done) { done = true; resolve({ ok: true, got }); } });
    const s = fs.createReadStream(NCZ, { start, end: start + limit });
    s.on('error', () => { if (!done) { done = true; resolve({ ok: false, err: 'read', got }); } });
    s.pipe(d);
    setTimeout(() => { if (!done) { done = true; d.destroy(); resolve({ ok: got > 0, got, note: 'timeout' }); } }, 8000);
  });
}

(async () => {
  const fd = fs.openSync(NCZ, 'r');
  const head = Buffer.alloc(0x4200);
  fs.readSync(fd, head, 0, 0x4200, 0);

  // 找 NCZSECTN
  const magic = head.indexOf('NCZSECTN');
  console.log('NCZSECTN at 0x' + magic.toString(16));
  console.log('file size', fs.statSync(NCZ).size);
  for (let o = magic; o < magic + 0x40; o += 8) {
    console.log('  +0x' + (o - magic).toString(16) + ' u64 = 0x' + head.readBigUInt64LE(o).toString(16));
  }
  // 之后按 0x44 步进打印若干条
  console.log('--- entries (0x44 stride from 0x44) ---');
  for (let i = 0; i < 6; i++) {
    const o = magic + 0x44 + i * 0x44;
    if (o + 0x44 > head.length) break;
    const u32 = [];
    for (let k = 0; k < 4; k++) u32.push(head.readUInt32LE(o + k * 4));
    const u64 = [];
    for (let k = 0; k < 5; k++) u64.push(head.readBigUInt64LE(o + 16 + k * 8));
    console.log(`  e${i} @0x${o.toString(16)} u32=[${u32}] u64=[${u64.map(x => '0x' + x.toString(16))}]`);
  }

  console.log('--- zstd frame probe ---');
  const cands = [];
  for (let o = magic + 0x100; o < magic + 0x200; o += 0x04) cands.push(o);
  let found = null;
  for (const c of cands) {
    const r = await tryZstd(c);
    if (r.ok && r.got > 1024) { console.log(`  HIT 0x${c.toString(16)} got=${r.got}`); found = c; break; }
  }
  if (found === null) {
    console.log('  no zstd frame found in 0x4000..0x4200 window');
  } else {
    fs.mkdirSync(OUT, { recursive: true });
    console.log('decoding from 0x' + found.toString(16) + ' ...');
    const d = zlib.createZstdDecompress();
    const out = fs.createWriteStream(path.join(OUT, 'fs.bin'));
    let total = 0;
    d.on('data', (c) => { total += c.length; });
    d.on('error', (e) => console.log('  zstd error:', e.message));
    d.on('end', () => { console.log('  decoded bytes =', total); });
    fs.createReadStream(NCZ, { start: found }).pipe(d).pipe(out);
  }
  fs.closeSync(fd);
})();
