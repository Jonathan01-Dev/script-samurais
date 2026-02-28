import path from 'node:path';
import { execSync } from 'node:child_process';
import { ArchipelNodeRuntime } from '../src/node-runtime.js';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(conditionFn, timeoutMs = 60000, pollMs = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (conditionFn()) {
      return { ok: true, elapsedMs: Date.now() - start };
    }
    await sleep(pollMs);
  }
  return { ok: false, elapsedMs: Date.now() - start };
}

async function main() {
  execSync('node scripts/generate-keys.js --count=3', { stdio: 'ignore' });

  const common = {
    discoveryPort: 6300,
    helloIntervalMs: 800,
    peerTimeoutMs: 9000,
    keepAliveIntervalMs: 1000,
    trustDir: path.join(process.cwd(), '.archipel', 's2-check')
  };

  const node1 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node1'),
    tcpPort: 7871
  });
  const node2 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node2'),
    tcpPort: 7872
  });

  try {
    await node1.start();
    await node2.start();

    const discovery = await waitFor(() => node1.getPeers().length >= 1 && node2.getPeers().length >= 1);
    if (!discovery.ok) {
      throw new Error('S2 failed: node discovery not ready');
    }

    const node2Id = node2.nodeIdHex;
    const node1Id = node1.nodeIdHex;

    const secure = await waitFor(() => node1.hasSecureSession(node2Id) && node2.hasSecureSession(node1Id));
    if (!secure.ok) {
      throw new Error('S2 failed: secure handshake not established');
    }

    const plaintext = 'hello-sprint2-e2e';
    node1.sendEncryptedMessage(node2Id, plaintext);

    const delivery = await waitFor(
      () => node2.getInbox().some((msg) => msg.from === node1Id && msg.plaintext === plaintext),
      10000,
      200
    );
    if (!delivery.ok) {
      throw new Error('S2 failed: encrypted message was not delivered/decrypted');
    }

    console.log(`S2 secure session established in ${secure.elapsedMs} ms`);
    console.log('S2 validation passed');
  } finally {
    await node1.stop().catch(() => {});
    await node2.stop().catch(() => {});
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
