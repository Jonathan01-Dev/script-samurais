import path from 'node:path';
import { mkdirSync } from 'node:fs';
import { promises as fsp } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { ArchipelNodeRuntime, waitForPeers } from '../src/node-runtime.js';

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(conditionFn, timeoutMs = 10000, pollMs = 200) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (conditionFn()) return true;
    await sleep(pollMs);
  }
  return false;
}

async function main() {
  const baseDir = path.join(process.cwd(), '.archipel', 's3-check');
  mkdirSync(baseDir, { recursive: true });
  const sourcePath = path.join(baseDir, 'source.bin');
  const out2 = path.join(baseDir, 'node2.bin');
  const out3 = path.join(baseDir, 'node3.bin');

  const source = randomBytes(3 * 1024 * 1024);
  await fsp.writeFile(sourcePath, source);
  const sourceHash = sha256Hex(source);

  const common = {
    discoveryPort: 6400,
    helloIntervalMs: 700,
    peerTimeoutMs: 10000,
    keepAliveIntervalMs: 1200
  };

  const node1 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node1'),
    tcpPort: 7971
  });
  const node2 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node2'),
    tcpPort: 7972
  });
  const node3 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node3'),
    tcpPort: 7973
  });

  try {
    await node1.start();
    await node2.start();
    await node3.start();

    const peersReady =
      (await waitForPeers(node1, 2, 60000)) &&
      (await waitForPeers(node2, 2, 60000)) &&
      (await waitForPeers(node3, 2, 60000));
    if (!peersReady) {
      throw new Error('S3 failed: peers not converged');
    }

    const manifest = await node1.shareFile(sourcePath, 128 * 1024);
    const fileId = manifest.file_id;
    if (fileId !== sourceHash) {
      throw new Error('S3 failed: source file_id mismatch');
    }

    const manifestSeen = await waitFor(
      () => !!node2.getKnownManifest(fileId) && !!node3.getKnownManifest(fileId),
      10000
    );
    if (!manifestSeen) {
      throw new Error('S3 failed: manifest not propagated');
    }

    await node3.downloadFile(fileId, out3, { preferredPeers: [node1.nodeIdHex] });
    const out3Hash = sha256Hex(await fsp.readFile(out3));
    if (out3Hash !== sourceHash) {
      throw new Error('S3 failed: node3 hash mismatch');
    }

    await node1.stop();
    await sleep(800);

    await node2.downloadFile(fileId, out2, { preferredPeers: [node1.nodeIdHex, node3.nodeIdHex] });
    const out2Hash = sha256Hex(await fsp.readFile(out2));
    if (out2Hash !== sourceHash) {
      throw new Error('S3 failed: node2 hash mismatch');
    }

    console.log('S3 validation passed');
  } finally {
    await node1.stop().catch(() => {});
    await node2.stop().catch(() => {});
    await node3.stop().catch(() => {});
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
