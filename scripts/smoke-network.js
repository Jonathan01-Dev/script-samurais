import path from 'node:path';
import { ArchipelNodeRuntime } from '../src/node-runtime.js';

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const node1 = new ArchipelNodeRuntime({
    keyDir: path.join(process.cwd(), 'keys', 'node1'),
    tcpPort: 7771,
    discoveryPort: 6100,
    helloIntervalMs: 1000,
    peerTimeoutMs: 5000,
    keepAliveIntervalMs: 1200
  });

  const node2 = new ArchipelNodeRuntime({
    keyDir: path.join(process.cwd(), 'keys', 'node2'),
    tcpPort: 7772,
    discoveryPort: 6100,
    helloIntervalMs: 1000,
    peerTimeoutMs: 5000,
    keepAliveIntervalMs: 1200
  });

  await node1.start();
  await node2.start();
  await sleep(4000);

  const peers1 = node1.getPeers();
  const peers2 = node2.getPeers();

  console.log('node1 peers:', peers1.length);
  console.log('node2 peers:', peers2.length);

  await node1.stop();
  await node2.stop();

  if (peers1.length === 0 || peers2.length === 0) {
    throw new Error('smoke network test failed: peers not discovered');
  }

  console.log('smoke network test passed');
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
