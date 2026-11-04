// Builds crates/vigil-core/data/geo.bin from the DB-IP "IP to Country Lite" CSV (CC BY 4.0).
// usage: node tools/build-geo.mjs dbip-country-lite-YYYY-MM.csv.gz
// Format: "VGEO1", u32 n4, n4*(u32 start, 2-byte cc), u32 n6, n6*(u32 start = top 32 bits, 2-byte cc);
// all big-endian, sorted; a range runs to the next start; cc "??" marks a gap.
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { isIPv4 } from 'node:net';

const v4 = (s) => s.split('.').reduce((a, o) => a * 256 + Number(o), 0);
const v6 = (s) => {
  const [h, t = ''] = s.split('::');
  const a = h ? h.split(':') : [];
  const b = t ? t.split(':') : [];
  const parts = s.includes('::') ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a;
  return (BigInt(`0x${parts[0]}`) << 48n) | (BigInt(`0x${parts[1]}`) << 32n) | (BigInt(`0x${parts[2]}`) << 16n) | BigInt(`0x${parts[3]}`);
};
const rows4 = [], rows6 = [];
for (const line of gunzipSync(readFileSync(process.argv[2])).toString().split('\n')) {
  const [a, b, cc] = line.trim().split(',');
  if (!cc || !/^[A-Z]{2}$/.test(cc)) continue;
  if (isIPv4(a)) rows4.push([v4(a), v4(b), cc]);
  else rows6.push([Number(v6(a) >> 32n), Number(v6(b) >> 32n), cc]);
}
function compact(rows, max) {
  rows.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  const out = [];
  for (let [s, e, cc] of rows) {
    const p = out[out.length - 1];
    if (p && s <= p.end) { s = p.end + 1; if (s > e) continue; }
    const last = out[out.length - 1];
    if (last && last.end + (typeof s === 'bigint' ? 1n : 1) < s) out.push({ s: last.end + (typeof s === 'bigint' ? 1n : 1), cc: '??', end: s - (typeof s === 'bigint' ? 1n : 1) });
    if (last && last.cc === cc && last.end + (typeof s === 'bigint' ? 1n : 1) === s) last.end = e;
    else out.push({ s, cc, end: e });
  }
  const tail = out[out.length - 1];
  if (tail && tail.end < max) out.push({ s: tail.end + (typeof max === 'bigint' ? 1n : 1), cc: '??', end: max });
  return out;
}
const r4 = compact(rows4, 0xffffffff), r6 = compact(rows6, 0xffffffff);
const buf = Buffer.alloc(5 + 4 + r4.length * 6 + 4 + r6.length * 6);
let o = buf.write('VGEO1');
o = buf.writeUInt32BE(r4.length, o);
for (const r of r4) { o = buf.writeUInt32BE(r.s, o); o += buf.write(r.cc, o); }
o = buf.writeUInt32BE(r6.length, o);
for (const r of r6) { o = buf.writeUInt32BE(r.s, o); o += buf.write(r.cc, o); }
writeFileSync('crates/vigil-core/data/geo.bin', buf);
console.log(`v4 ${r4.length} v6 ${r6.length} bytes ${buf.length}`);
