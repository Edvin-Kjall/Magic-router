import { seal, encodeEnvelope, generateRecipientKeypair } from './site/public/lib/envelope.js';
import { ARGON2ID_FAST } from './site/public/lib/kd.js';
import { b64uToBytes } from './site/public/lib/b64.js';

const kp = await generateRecipientKeypair();
const env = await seal({
  type: 'url',
  data: 'https://example.com/x',
  passwords: ['alpha'],
  embedded: 'beta',
  recipient: kp,
  threshold: 2,
  kdf: ARGON2ID_FAST,
});
const str = await encodeEnvelope(env);
const raw = b64uToBytes(str.slice(3));
console.log('total bytes', raw.length);
const hex = (b, from, to) => [...b.subarray(from, to)].map((x) => x.toString(16).padStart(2, '0')).join(' ');
console.log('bytes 0-32 :', hex(raw, 0, 32));
console.log('bytes 32-96:', hex(raw, 32, 96));
console.log('bytes 96-140:', hex(raw, 96, 140));
