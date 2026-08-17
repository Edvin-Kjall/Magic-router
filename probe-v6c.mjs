import { seal, encodeEnvelope, generateRecipientKeypair } from './site/public/lib/envelope.js';
import { ARGON2ID_FAST } from './site/public/lib/kd.js';
import { b64uToBytes } from './site/public/lib/b64.js';

const kp = await generateRecipientKeypair();
const env = await seal({
  type: 'url', data: 'https://example.com/x',
  passwords: ['alpha'], embedded: 'beta', recipient: kp,
  threshold: 2, kdf: ARGON2ID_FAST,
});
console.log('wrap kinds:', env.wrap.map((w) => w.k + (w.direct ? 'D' : '') + (w.xi != null ? ':xi' + w.xi : '')));
const str = await encodeEnvelope(env);
const raw = b64uToBytes(str.slice(3));

// parse per spec, log offsets
let off = 0;
const u8 = () => raw[off++];
const bytes = (n) => { const s = raw.subarray(off, off + n); off += n; return s; };
const num = (n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + raw[off++]; return v; };

console.log('ver', u8());
const flags = u8();
console.log('flags', flags);
if (flags & 4) console.log('thr', u8(), u8());
const wc = u8();
console.log('wrapCount', wc);
for (let i = 0; i < wc; i++) {
  const start = off;
  const b = u8();
  const kind = ['pass', 'embed', 'prf', 'pub'][b & 3];
  console.log(`w${i} @${start} kind=${kind} direct=${!!(b & 128)}`);
  if (kind === 'pass' || kind === 'embed') {
    const kf = u8();
    console.log(`  kdfFlag=${kf}${kf === 2 ? ' i=' + num(4) : ''}`);
    bytes(16);
    if (!(b & 128)) bytes(48);
  } else if (kind === 'prf') {
    bytes(32); bytes(u8());
    if (!(b & 128)) bytes(32);
  } else {
    bytes(32); bytes(1088);
    if (!(b & 128)) bytes(48);
  }
  if (flags & 4) console.log('  xi=', u8());
}
const plen = num(2);
console.log('payload len', plen, 'remaining', raw.length - off, 'total', raw.length);
