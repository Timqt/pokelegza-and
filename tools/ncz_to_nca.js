// NCZ -> NCA 解码器（按 nsz 的 IndependentNczDecompressor 格式，用 Node 的 zstd + aes-128-ctr）
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');

const NCZ = String.raw`D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.ncz`;
const OUT = String.raw`D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.nca`;

const fd = fs.openSync(NCZ, 'r');
const size = fs.statSync(NCZ).size;

function readAt(off, len) {
  const b = Buffer.alloc(len);
  const n = fs.readSync(fd, b, 0, len, off);
  return b.subarray(0, n);
}

const NCA_HEADER_SIZE = 0x4000;
const header = readAt(0, NCA_HEADER_SIZE);

// 0x4000: "NCZSECTN"
let p = NCA_HEADER_SIZE;
const magic = readAt(p, 8); p += 8;
if (magic.toString('latin1') !== 'NCZSECTN') throw new Error('no NCZSECTN');
const sectionCount = Number(readAt(p, 8).readBigUInt64LE(0)); p += 8;
console.log('sectionCount =', sectionCount);

const sections = [];
for (let i = 0; i < sectionCount; i++) {
  const r = readAt(p, 64); p += 64;
  sections.push({
    offset: Number(r.readBigUInt64LE(0)),
    size: Number(r.readBigUInt64LE(8)),
    cryptoType: Number(r.readBigUInt64LE(16)),
    padding: Number(r.readBigUInt64LE(24)),
    cryptoKey: r.subarray(32, 48),
    cryptoCounter: r.subarray(48, 64),
  });
}
const total = sections.reduce((a, s) => a + s.size, 0);
console.log('sum(section.size) =', total, '(0x' + total.toString(16) + ')');
console.log('first section:', sections[0].offset, sections[0].size, 'cryptoType', sections[0].cryptoType);
console.log('last  section:', sections[sections.length - 1].offset, sections[sections.length - 1].size);

const blockMagic = readAt(p, 8);
console.log('block magic @0x' + p.toString(16) + ' =', JSON.stringify(blockMagic.toString('latin1')));
let dataStart = p + 8;
let blockHeader = null;
if (blockMagic.toString('latin1') === 'NCZBLOCK') {
  const b = readAt(dataStart, 32);
  blockHeader = {
    magic: b.subarray(0, 8).toString('latin1'),
    version: b[8], type: b[9], unused: b[10], blockSizeExponent: b[11],
    numberOfBlocks: b.readUInt32LE(12),
    decompressedSize: Number(b.readBigUInt64LE(16)),
  };
  console.log('BLOCK header:', blockHeader);
  const sizes = [];
  for (let i = 0; i < blockHeader.numberOfBlocks; i++) sizes.push(readAt(dataStart + 24 + i * 4, 4).readUInt32LE(0));
  console.log('compressed block sizes: first5=', sizes.slice(0, 5), 'count=', sizes.length);
  dataStart = dataStart + 24 + blockHeader.numberOfBlocks * 4;
}
console.log('compressed data starts @0x' + dataStart.toString(16));
fs.closeSync(fd);

// ---- 解压 + 逐段 AES-CTR 复原 ----
const outFd = fs.openSync(OUT, 'w');
fs.writeSync(outFd, header);

async function readExactly(stream, n) {
  const chunks = [];
  let got = 0;
  while (got < n) {
    const c = await new Promise((res, rej) => {
      const on = (x) => { cleanup(); res(x); };
      const err = (e) => { cleanup(); rej(e); };
      const cleanup = () => { stream.off('readable', on); stream.off('error', err); };
      stream.once('readable', on); stream.once('error', err);
    });
    chunks.push(c); got += c.length;
  }
  return Buffer.concat(chunks);
}

(async () => {
  let src;
  if (blockHeader) {
    // 分块 zstd：每块独立帧
    src = { read: async (n) => { throw new Error('block path not implemented'); } };
  } else {
    const d = zlib.createZstdDecompress();
    fs.createReadStream(NCZ, { start: dataStart }).pipe(d);
    src = { read: (n) => readExactly(d, n) };
  }
  let written = 0;
  for (const s of sections) {
    const plain = await src.read(s.size);
    let outBuf = plain;
    if (s.cryptoType === 3 || s.cryptoType === 4) {
      const iv = Buffer.concat([s.cryptoCounter.subarray(0, 8), (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(s.offset >> 4)); return b; })()]);
      const dec = crypto.createDecipheriv('aes-128-ctr', s.cryptoKey, iv);
      outBuf = Buffer.concat([dec.update(plain), dec.final()]);
    }
    fs.writeSync(outFd, outBuf);
    written += outBuf.length;
    if (written % (200 * 1024 * 1024) < s.size) console.log('  written', (written / 2**20).toFixed(0), 'MiB');
  }
  fs.closeSync(outFd);
  console.log('DONE. NCA bytes =', written + NCA_HEADER_SIZE);
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
