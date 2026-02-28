import path from 'node:path';
import { execSync } from 'node:child_process';
import { ArchipelNodeRuntime } from '../src/node-runtime.js';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(conditionFn, timeoutMs = 60000, pollMs = 500) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (conditionFn()) {
 feature/s1
      return { ok: true, elapsedMs: Date.now() - started };
    }
    await sleep(pollMs);
  }
  return { ok: false, elapsedMs: Date.now() - started };

      return { ok: true, elapsedMs: Math.max(0, Date.now() - started) };
    }
    await sleep(pollMs);
  }
  return { ok: false, elapsedMs: Math.max(0, Date.now() - started) };
 main
}

async function main() {
  execSync('node scripts/generate-keys.js --count=3', { stdio: 'ignore' });

  const common = {
    discoveryPort: 6200,
    helloIntervalMs: 1000,
    peerTimeoutMs: 9000,
    keepAliveIntervalMs: 1200,
    trustDir: path.join(process.cwd(), '.archipel', 's1-check')
  };

  const node1 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node1'),
    tcpPort: 7771
  });
  const node2 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node2'),
    tcpPort: 7772
  });
  const node3 = new ArchipelNodeRuntime({
    ...common,
    keyDir: path.join(process.cwd(), 'keys', 'node3'),
    tcpPort: 7773
  });

  const nodes = [node1, node2, node3];
  try {
    await node1.start();
    await node2.start();
    await node3.start();

    const result = await waitFor(() => nodes.every((n) => n.getPeers().length >= 2));
    if (!result.ok) {
      throw new Error('S1 check failed: 3 nodes did not discover each other in < 60 seconds');
    }

    console.log(`S1 discovery converged in ${result.elapsedMs} ms`);
    console.log('node1 peers:', node1.getPeers().length);
    console.log('node2 peers:', node2.getPeers().length);
    console.log('node3 peers:', node3.getPeers().length);
    console.log('S1 validation passed');
  } finally {
    for (const node of nodes) {
      await node.stop().catch(() => {});
    }
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
