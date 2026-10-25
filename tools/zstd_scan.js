// 用 zstd 帧魔数 0xFD2FB528 在 NCZ 里定位压缩流起点
const fs = require('fs');
const zlib = require('zlib');

const NCZ = String.raw`D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.ncz`;
const CHUNK = 16 * 1024 * 1024;
const MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]); // little-endian FD2FB528

const fd = fs.openSync(NCZ, 'r');
const size = fs.statSync(NCZ).size;
const buf = Buffer.alloc(CHUNK);
let pos = 0, hits = [];
while (pos < size) {
  const n = fs.readSync(fd, buf, 0, CHUNK, pos);
  if (n <= 0) break;
  let i = 0;
  while (true) {
    const j = buf.indexOf(MAGIC, i);
    if (j < 0 || j + 4 > n) break;
    hits.push(pos + j);
    i = j + 4;
    if (hits.length > 40) break;
  }
  if (hits.length > 40) break;
  pos += n - 3;
}
fs.closeSync(fd);
console.log('zstd frame magic hits:', hits.length);
console.log(hits.slice(0, 12).map(h => '0x' + h.toString(16)).join(', '));

async function probe(off) {
  return new Promise((res) => {
    const d = zlib.createZstdDecompress();
    let got = 0, done = false;
    d.on('data', c => { got += c.length; });
    d.on('error', e => { if (!done) { done = true; res({ off, got, err: e.message }); } });
    d.on('end', () => { if (!done) { done = true; res({ off, got, err: null }); } });
    fs.createReadStream(NCZ, { start: off, end: off + 4 * 1024 * 1024 }).pipe(d);
    setTimeout(() => { if (!done) { done = true; d.destroy(); res({ off, got, err: 'timeout' }); } }, 6000);
  });
}
(async () => {
  for (const h of hits.slice(0, 8)) {
    const r = await probe(h);
    console.log(`  probe 0x${h.toString(16)} -> got=${r.got} err=${r.err}`);
    if (r.got > 4096 && !r.err) { console.log('  >> first valid frame at 0x' + h.toString(16)); break; }
  }
})();
