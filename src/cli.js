#!/usr/bin/env node
import path from 'node:path';
import { ArchipelNodeRuntime } from './node-runtime.js';

function getArg(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function hasFlag(flag) {
  return process.argv.includes(flag);
}

function parseManifestArgs() {
  const manifest = { shared_files: [] };
  const idx = process.argv.indexOf('--file');
  if (idx === -1 || idx + 1 >= process.argv.length) return manifest;

  const raw = process.argv[idx + 1];
  manifest.shared_files = raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return manifest;
}

async function main() {
  const command = process.argv[2] || 'run';

  if (command !== 'run') {
    console.error('Usage: node src/cli.js run --node node1 [--tcp-port 7777] [--file a.txt,b.pdf]');
    process.exit(1);
  }

  const nodeName = getArg('--node', 'node1');
  const keyDir = path.join(process.cwd(), 'keys', nodeName);
  const tcpPort = Number(getArg('--tcp-port', process.env.TCP_PORT || 7777));
  const discoveryPort = Number(getArg('--discovery-port', process.env.DISCOVERY_MULTICAST_PORT || 6000));
  const discoveryAddress = getArg('--discovery-address', process.env.DISCOVERY_MULTICAST_ADDR || '239.255.42.99');
  const hmacKey = getArg('--hmac-key', process.env.HMAC_KEY || 'archipel-dev-key');
  const manifest = parseManifestArgs();

  const runtime = new ArchipelNodeRuntime({
    keyDir,
    tcpPort,
    discoveryPort,
    discoveryAddress,
    hmacKey,
    manifest
  });

  await runtime.start();
  console.log(
    `[archipel] ${nodeName} started tcp=${tcpPort} discovery=${discoveryAddress}:${discoveryPort}`
  );

  const interval = setInterval(() => {
    const peers = runtime.getPeers();
    console.log(`[peers] ${peers.length}`, peers);
  }, 10000);

  if (hasFlag('--manifest-pulse')) {
    setInterval(() => {
      runtime.broadcastManifest(manifest);
    }, 15000);
  }

  const shutdown = async () => {
    clearInterval(interval);
    await runtime.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error(`[fatal] ${err.message}`);
  process.exit(1);
});
