import { mkdirSync, writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import path from 'node:path';

const countArg = process.argv.find((a) => a.startsWith('--count='));
const count = countArg ? Number(countArg.split('=')[1]) : 3;

if (!Number.isInteger(count) || count <= 0) {
  throw new Error('count must be a positive integer');
}

for (let i = 1; i <= count; i += 1) {
  const nodeName = `node${i}`;
  const dir = path.join(process.cwd(), 'keys', nodeName);
  mkdirSync(dir, { recursive: true });

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

  const nodeId = createHash('sha256').update(pubPem).digest('hex');

  writeFileSync(path.join(dir, 'public.pem'), pubPem);
  writeFileSync(path.join(dir, 'private.pem'), privPem);
  writeFileSync(path.join(dir, 'node-id.txt'), `${nodeId}\n`);

  console.log(`${nodeName}: ${nodeId}`);
}
