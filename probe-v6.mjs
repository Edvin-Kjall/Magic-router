import { seal, encodeEnvelope, decodeEnvelope, generateRecipientKeypair } from './site/public/lib/envelope.js';
import { ARGON2ID_FAST } from './site/public/lib/kd.js';

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
console.log('link len', str.length, 'prefix', str.slice(0, 4));
const parsed = await decodeEnvelope(str);
console.log('v', parsed.v, 'thr', JSON.stringify(parsed.thr), 'wrapCount', parsed.wrap.length);
for (const w of parsed.wrap) {
  console.log('w:', w.k, 'direct', w.direct, 'xi', w.xi, 'kd', JSON.stringify(w.kd), 'sLen', (w.s || '').length, 'ctLen', (w.ct || '').length);
}
