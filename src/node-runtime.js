import dgram from 'node:dgram';
import net from 'node:net';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { buildPacket, PACKET_TYPES, parsePacket } from './packet.js';
import { PeerTable } from './peer-table.js';
import { CONFIG } from './config.js';
import { createTlvDecoder, encodeTlv } from './tlv.js';

const ACK_STATUS = {
  OK: 0x00,
  HASH_MISMATCH: 0x01,
  NOT_FOUND: 0x02
};

function parseJsonPayload(payload) {
  try {
    return JSON.parse(payload.toString('utf8'));
  } catch {
    return null;
  }
}

function sha256Hex(bufferOrString) {
  return createHash('sha256').update(bufferOrString).digest('hex');
}

function chunkKey(fileId, chunkIdx) {
  return `${fileId}:${chunkIdx}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class ArchipelNodeRuntime {
  constructor(options = {}) {
    const keyDir = options.keyDir || path.join(process.cwd(), 'keys', 'node1');
    const nodeIdHex = readFileSync(path.join(keyDir, 'node-id.txt'), 'utf8').trim();
    if (nodeIdHex.length !== 64) {
      throw new Error(`invalid node-id format in ${keyDir}`);
    }

    this.nodeIdHex = nodeIdHex;
    this.nodeId = Buffer.from(nodeIdHex, 'hex');
    this.publicKeyPem = readFileSync(path.join(keyDir, 'public.pem'), 'utf8');

    this.hmacKey = Buffer.from(options.hmacKey || process.env.HMAC_KEY || 'archipel-dev-key');
    this.tcpPort = Number(options.tcpPort || CONFIG.tcpPort);
    this.discoveryAddress = options.discoveryAddress || CONFIG.discovery.address;
    this.discoveryPort = Number(options.discoveryPort || CONFIG.discovery.port);
    this.helloIntervalMs = Number(options.helloIntervalMs || CONFIG.discovery.helloIntervalMs);
    this.peerTimeoutMs = Number(options.peerTimeoutMs || CONFIG.discovery.peerTimeoutMs);
    this.keepAliveIntervalMs = Number(options.keepAliveIntervalMs || CONFIG.keepAliveIntervalMs);
    this.maxConnections = Number(options.maxConnections || CONFIG.maxConnections);
    this.chunkRequestTimeoutMs = Number(options.chunkRequestTimeoutMs || 3000);

    this.peerTable = new PeerTable();
    this.manifest = options.manifest || { shared_files: [] };
    this.sockets = new Set();
    this.peerSockets = new Map();

    this.manifests = new Map(); // file_id -> manifest
    this.localChunks = new Map(); // `${fileId}:${idx}` -> Buffer
    this.pendingChunkRequests = new Map(); // key -> { resolve, reject, timer }
    this.downloadedFiles = new Map(); // file_id -> outputPath

    this.dataDir = path.join(process.cwd(), '.archipel');
    this.chunksDir = path.join(this.dataDir, 'chunks');
    this.indexPath = path.join(this.dataDir, 'index.json');
    mkdirSync(this.chunksDir, { recursive: true });
    this.loadIndex();
  }

  loadIndex() {
    try {
      const raw = readFileSync(this.indexPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed?.manifests) {
        for (const [fileId, manifest] of Object.entries(parsed.manifests)) {
          this.manifests.set(fileId, manifest);
        }
      }
    } catch {
      // nothing to load
    }
  }

  saveIndex() {
    const manifests = {};
    for (const [fileId, manifest] of this.manifests.entries()) {
      manifests[fileId] = manifest;
    }
    const indexDoc = {
      node_id: this.nodeIdHex,
      updated_at: Date.now(),
      manifests
    };
    writeFileSync(this.indexPath, JSON.stringify(indexDoc, null, 2));
  }

  async start() {
    await this.startUdpDiscovery();
    await this.startTcpServer();

    this.helloTimer = setInterval(() => this.sendHello(), this.helloIntervalMs);
    this.pruneTimer = setInterval(
      () => this.peerTable.removeExpired(this.peerTimeoutMs),
      Math.max(1000, Math.floor(this.peerTimeoutMs / 3))
    );
    this.keepAliveTimer = setInterval(() => this.sendKeepAlive(), this.keepAliveIntervalMs);

    this.sendHello();
  }

  async stop() {
    clearInterval(this.helloTimer);
    clearInterval(this.pruneTimer);
    clearInterval(this.keepAliveTimer);

    for (const req of this.pendingChunkRequests.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('runtime stopped'));
    }
    this.pendingChunkRequests.clear();

    for (const socket of this.sockets) {
      socket.destroy();
    }
    this.sockets.clear();

    if (this.udpSocket) {
      this.udpSocket.close();
      this.udpSocket = null;
    }

    if (this.tcpServer) {
      await new Promise((resolve) => this.tcpServer.close(() => resolve()));
      this.tcpServer = null;
    }
  }

  getPeers() {
    return this.peerTable.list();
  }

  getKnownManifest(fileId) {
    return this.manifests.get(fileId) || null;
  }

  getAvailableFileIds() {
    return [...this.manifests.keys()];
  }

  async startUdpDiscovery() {
    this.udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.udpSocket.on('error', (err) => {
      console.error(`[udp] ${err.message}`);
    });
    this.udpSocket.on('message', (msg, rinfo) => this.handleUdpPacket(msg, rinfo));

    await new Promise((resolve, reject) => {
      this.udpSocket.once('listening', resolve);
      this.udpSocket.once('error', reject);
      this.udpSocket.bind(this.discoveryPort);
    });

    this.udpSocket.addMembership(this.discoveryAddress);
    this.udpSocket.setMulticastTTL(1);
    this.udpSocket.setMulticastLoopback(true);
  }

  async startTcpServer() {
    this.tcpServer = net.createServer((socket) => this.attachSocket(socket, false));
    this.tcpServer.maxConnections = this.maxConnections;
    await new Promise((resolve, reject) => {
      this.tcpServer.once('error', reject);
      this.tcpServer.listen(this.tcpPort, '0.0.0.0', resolve);
    });
  }

  sendHello() {
    const payload = Buffer.from(
      JSON.stringify({
        tcp_port: this.tcpPort,
        node_id: this.nodeIdHex,
        capabilities: ['discovery', 'tcp', 'manifest', 'chunk-transfer'],
        manifest: this.manifest,
        ts: Date.now()
      })
    );
    const packet = buildPacket(PACKET_TYPES.HELLO, this.nodeId, payload, this.hmacKey);
    this.udpSocket.send(packet, this.discoveryPort, this.discoveryAddress);
  }

  sendKeepAlive() {
    const payload = Buffer.from(JSON.stringify({ kind: 'ping', ts: Date.now() }));
    for (const socket of this.sockets) {
      this.sendPacket(socket, PACKET_TYPES.ACK, payload);
    }
  }

  async connectToPeer(ip, tcpPort) {
    if (!ip || !tcpPort) return;
    if (this.hasSocketTo(ip, tcpPort)) return;
    const socket = net.createConnection({ host: ip, port: tcpPort });
    socket.once('connect', () => this.attachSocket(socket, true));
    socket.once('error', (err) => {
      console.warn(`[tcp] connect ${ip}:${tcpPort} failed: ${err.message}`);
    });
  }

  attachSocket(socket, outbound) {
    if (socket.__archipelAttached) return;
    socket.__archipelAttached = true;
    this.sockets.add(socket);

    const decoder = createTlvDecoder(({ type, value }) => {
      try {
        const packet = parsePacket(value, this.hmacKey);
        if (packet.type !== type) return;
        this.handleTcpPacket(socket, packet);
      } catch (err) {
        console.warn(`[tcp] invalid packet: ${err.message}`);
      }
    });

    socket.on('data', decoder);
    socket.on('close', () => {
      this.sockets.delete(socket);
      if (socket.__peerIdHex && this.peerSockets.get(socket.__peerIdHex) === socket) {
        this.peerSockets.delete(socket.__peerIdHex);
      }
    });
    socket.on('error', (err) => {
      console.warn(`[tcp] socket error: ${err.message}`);
      this.sockets.delete(socket);
      if (socket.__peerIdHex && this.peerSockets.get(socket.__peerIdHex) === socket) {
        this.peerSockets.delete(socket.__peerIdHex);
      }
    });

    if (outbound) {
      const helloPayload = Buffer.from(
        JSON.stringify({ tcp_port: this.tcpPort, ts: Date.now(), mode: 'outbound-handshake' })
      );
      this.sendPacket(socket, PACKET_TYPES.HELLO, helloPayload);
      this.sendPeerList(socket);
    }
  }

  sendPacket(socket, type, payloadBuffer) {
    if (!socket || socket.destroyed) return;
    const packet = buildPacket(type, this.nodeId, payloadBuffer, this.hmacKey);
    socket.write(encodeTlv(type, packet));
  }

  sendPeerList(socket) {
    const payload = Buffer.from(JSON.stringify({ peers: this.peerTable.list() }));
    this.sendPacket(socket, PACKET_TYPES.PEER_LIST, payload);
  }

  hasSocketTo(ip, tcpPort) {
    for (const socket of this.sockets) {
      if (socket.destroyed) continue;
      const remoteAddress = String(socket.remoteAddress || '').replace('::ffff:', '');
      if (remoteAddress === ip && socket.remotePort === tcpPort) return true;
    }
    return false;
  }

  async shareFile(filePath, chunkSize = 524288) {
    const content = await fsp.readFile(filePath);
    const fileId = sha256Hex(content);
    const filename = path.basename(filePath);
    const chunks = [];
    const nbChunks = Math.ceil(content.length / chunkSize);

    for (let idx = 0; idx < nbChunks; idx += 1) {
      const start = idx * chunkSize;
      const end = Math.min(content.length, start + chunkSize);
      const chunk = content.subarray(start, end);
      const hash = sha256Hex(chunk);
      const key = chunkKey(fileId, idx);
      this.localChunks.set(key, chunk);
      await fsp.writeFile(path.join(this.chunksDir, `${fileId}.${idx}.bin`), chunk);
      chunks.push({ index: idx, hash, size: chunk.length });
    }

    const manifest = {
      file_id: fileId,
      filename,
      size: content.length,
      chunk_size: chunkSize,
      nb_chunks: nbChunks,
      chunks,
      sender_id: this.nodeIdHex,
      signature: `manifest-${this.nodeIdHex}-${Date.now()}`
    };

    this.manifests.set(fileId, manifest);
    if (!this.manifest.shared_files.includes(fileId)) {
      this.manifest.shared_files.push(fileId);
    }
    this.saveIndex();
    this.broadcastManifest(manifest);
    return manifest;
  }

  broadcastManifest(manifest) {
    this.manifest = {
      ...this.manifest,
      shared_files: [...new Set([...(this.manifest.shared_files || []), manifest.file_id])]
    };
    const payload = Buffer.from(JSON.stringify({ manifest, ts: Date.now() }));
    for (const socket of this.sockets) {
      this.sendPacket(socket, PACKET_TYPES.MANIFEST, payload);
    }
  }

  findPeerCandidatesForFile(fileId, preferredPeers = []) {
    const peerMap = new Map(this.peerTable.list().map((p) => [p.node_id, p]));
    const preferred = preferredPeers.filter((id) => peerMap.get(id)?.shared_files?.includes(fileId));
    const others = [...peerMap.values()]
      .filter((p) => p.shared_files?.includes(fileId) && !preferred.includes(p.node_id))
      .map((p) => p.node_id);
    return [...preferred, ...others];
  }

  async requestChunkFromPeer(peerIdHex, fileId, chunkIdx) {
    const socket = this.peerSockets.get(peerIdHex);
    if (!socket) throw new Error(`no socket for peer ${peerIdHex}`);
    const reqKey = chunkKey(fileId, chunkIdx);
    if (this.pendingChunkRequests.has(reqKey)) {
      throw new Error(`chunk request already pending ${reqKey}`);
    }

    const payload = Buffer.from(
      JSON.stringify({
        file_id: fileId,
        chunk_idx: chunkIdx,
        requester: this.nodeIdHex
      })
    );

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingChunkRequests.delete(reqKey);
        reject(new Error(`timeout chunk ${reqKey}`));
      }, this.chunkRequestTimeoutMs);

      this.pendingChunkRequests.set(reqKey, { resolve, reject, timer });
      this.sendPacket(socket, PACKET_TYPES.CHUNK_REQ, payload);
    });
  }

  async downloadFile(fileId, outputPath, options = {}) {
    const manifest = this.manifests.get(fileId);
    if (!manifest) {
      throw new Error(`unknown manifest ${fileId}`);
    }

    const chunks = new Array(manifest.nb_chunks);
    const requestedOrder = [...manifest.chunks].sort((a, b) => a.index - b.index);

    for (const chunkMeta of requestedOrder) {
      const local = this.localChunks.get(chunkKey(fileId, chunkMeta.index));
      if (local) {
        chunks[chunkMeta.index] = local;
        continue;
      }

      let done = false;
      const peerCandidates = this.findPeerCandidatesForFile(fileId, options.preferredPeers || []);
      for (const peerId of peerCandidates) {
        try {
          await this.requestChunkFromPeer(peerId, fileId, chunkMeta.index);
          const received = this.localChunks.get(chunkKey(fileId, chunkMeta.index));
          if (received) {
            chunks[chunkMeta.index] = received;
            done = true;
            break;
          }
        } catch {
          // fallback to next peer
        }
      }

      if (!done) {
        throw new Error(`failed to download chunk ${chunkMeta.index} for file ${fileId}`);
      }
    }

    const full = Buffer.concat(chunks);
    const fullHash = sha256Hex(full);
    if (fullHash !== fileId) {
      throw new Error(`file hash mismatch expected=${fileId} got=${fullHash}`);
    }
    await fsp.mkdir(path.dirname(outputPath), { recursive: true });
    await fsp.writeFile(outputPath, full);
    this.downloadedFiles.set(fileId, outputPath);

    if (!this.manifest.shared_files.includes(fileId)) {
      this.manifest.shared_files.push(fileId);
      this.saveIndex();
      const rebroadcast = {
        ...manifest,
        sender_id: this.nodeIdHex,
        signature: `manifest-${this.nodeIdHex}-${Date.now()}`
      };
      this.broadcastManifest(rebroadcast);
    }

    return { fileId, outputPath, size: full.length };
  }

  handleUdpPacket(msg, rinfo) {
    let packet;
    try {
      packet = parsePacket(msg, this.hmacKey);
    } catch {
      return;
    }

    if (packet.type !== PACKET_TYPES.HELLO) return;
    const peerIdHex = packet.nodeId.toString('hex');
    if (peerIdHex === this.nodeIdHex) return;

    const data = parseJsonPayload(packet.payload);
    if (!data || !data.tcp_port) return;

    this.peerTable.upsert(peerIdHex, {
      ip: rinfo.address,
      tcp_port: data.tcp_port,
      last_seen: Date.now(),
      shared_files: data.manifest?.shared_files || []
    });

    if (!this.hasSocketTo(rinfo.address, data.tcp_port)) {
      this.connectToPeer(rinfo.address, data.tcp_port);
    }
  }

  async handleChunkRequest(socket, peerIdHex, data) {
    if (!data?.file_id || !Number.isInteger(data.chunk_idx)) return;
    const key = chunkKey(data.file_id, data.chunk_idx);
    const chunk = this.localChunks.get(key);
    if (!chunk) {
      const ackPayload = Buffer.from(
        JSON.stringify({ file_id: data.file_id, chunk_idx: data.chunk_idx, status: ACK_STATUS.NOT_FOUND })
      );
      this.sendPacket(socket, PACKET_TYPES.ACK, ackPayload);
      return;
    }

    const payload = Buffer.from(
      JSON.stringify({
        file_id: data.file_id,
        chunk_idx: data.chunk_idx,
        data: chunk.toString('base64'),
        chunk_hash: sha256Hex(chunk)
      })
    );
    this.sendPacket(socket, PACKET_TYPES.CHUNK_DATA, payload);
  }

  async handleChunkData(socket, peerIdHex, data) {
    if (!data?.file_id || !Number.isInteger(data.chunk_idx) || !data?.data) return;
    const manifest = this.manifests.get(data.file_id);
    if (!manifest) return;
    const meta = manifest.chunks.find((c) => c.index === data.chunk_idx);
    if (!meta) return;

    const chunk = Buffer.from(data.data, 'base64');
    const actualHash = sha256Hex(chunk);
    const ok = actualHash === meta.hash;

    const ackPayload = Buffer.from(
      JSON.stringify({
        file_id: data.file_id,
        chunk_idx: data.chunk_idx,
        status: ok ? ACK_STATUS.OK : ACK_STATUS.HASH_MISMATCH
      })
    );
    this.sendPacket(socket, PACKET_TYPES.ACK, ackPayload);

    if (!ok) return;

    const key = chunkKey(data.file_id, data.chunk_idx);
    this.localChunks.set(key, chunk);
    await fsp.writeFile(path.join(this.chunksDir, `${data.file_id}.${data.chunk_idx}.bin`), chunk);

    const pending = this.pendingChunkRequests.get(key);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingChunkRequests.delete(key);
      pending.resolve({ ok: true });
    }
  }

  handleAck(data) {
    if (!data?.file_id || !Number.isInteger(data.chunk_idx)) return false;
    const key = chunkKey(data.file_id, data.chunk_idx);
    const pending = this.pendingChunkRequests.get(key);
    if (!pending) return false;

    if (data.status === ACK_STATUS.OK) {
      // resolved when CHUNK_DATA is received and validated
      return true;
    }

    clearTimeout(pending.timer);
    this.pendingChunkRequests.delete(key);
    pending.reject(new Error(`chunk ack status=${data.status} for ${key}`));
    return true;
  }

  handleTcpPacket(socket, packet) {
    const peerIdHex = packet.nodeId.toString('hex');
    if (peerIdHex === this.nodeIdHex) return;
    socket.__peerIdHex = peerIdHex;
    this.peerSockets.set(peerIdHex, socket);

    const data = parseJsonPayload(packet.payload);

    if (packet.type === PACKET_TYPES.HELLO && data) {
      this.peerTable.upsert(peerIdHex, {
        ip: String(socket.remoteAddress || '').replace('::ffff:', ''),
        tcp_port: data.tcp_port || socket.remotePort,
        last_seen: Date.now(),
        shared_files: data.manifest?.shared_files || []
      });
      this.sendPacket(socket, PACKET_TYPES.ACK, Buffer.from(JSON.stringify({ ok: true, ts: Date.now() })));
      this.sendPeerList(socket);
      return;
    }

    if (packet.type === PACKET_TYPES.PEER_LIST && data?.peers) {
      for (const peer of data.peers) {
        if (!peer?.node_id || peer.node_id === this.nodeIdHex) continue;
        this.peerTable.upsert(peer.node_id, {
          ip: peer.ip,
          tcp_port: peer.tcp_port,
          last_seen: Date.now(),
          shared_files: peer.shared_files || []
        });
        if (peer.ip && peer.tcp_port && !this.hasSocketTo(peer.ip, peer.tcp_port)) {
          this.connectToPeer(peer.ip, peer.tcp_port);
        }
      }
      return;
    }

    if (packet.type === PACKET_TYPES.MANIFEST && data?.manifest?.file_id) {
      this.manifests.set(data.manifest.file_id, data.manifest);
      this.saveIndex();

      const existing = this.peerTable.list().find((peer) => peer.node_id === peerIdHex);
      if (existing) {
        const updatedShared = [...new Set([...(existing.shared_files || []), data.manifest.file_id])];
        this.peerTable.upsert(peerIdHex, {
          ...existing,
          shared_files: updatedShared,
          last_seen: Date.now()
        });
      }
      return;
    }

    if (packet.type === PACKET_TYPES.CHUNK_REQ) {
      void this.handleChunkRequest(socket, peerIdHex, data);
      return;
    }

    if (packet.type === PACKET_TYPES.CHUNK_DATA) {
      void this.handleChunkData(socket, peerIdHex, data);
      return;
    }

    if (packet.type === PACKET_TYPES.ACK) {
      const wasChunkAck = this.handleAck(data);
      if (!wasChunkAck && data?.kind === 'ping') {
        const payload = Buffer.from(JSON.stringify({ kind: 'pong', ts: Date.now() }));
        this.sendPacket(socket, PACKET_TYPES.ACK, payload);
      }
      this.peerTable.markSeen(peerIdHex);
    }
  }
}

export async function waitForPeers(runtime, minPeers, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (runtime.getPeers().length >= minPeers) return true;
    await sleep(200);
  }
  return false;
}
