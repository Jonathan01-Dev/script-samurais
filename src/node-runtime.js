import dgram from 'node:dgram';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { buildPacket, PACKET_TYPES, parsePacket } from './packet.js';
import { PeerTable } from './peer-table.js';
import { CONFIG } from './config.js';
import { createTlvDecoder, encodeTlv } from './tlv.js';

function parseJsonPayload(payload) {
  try {
    return JSON.parse(payload.toString('utf8'));
  } catch {
    return null;
  }
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

    this.peerTable = new PeerTable();
    this.manifest = options.manifest || { shared_files: [] };
    this.sockets = new Set();
    this.peerSockets = new Map();
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
        capabilities: ['discovery', 'tcp', 'manifest'],
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

  broadcastManifest(manifest) {
    this.manifest = manifest;
    const payload = Buffer.from(JSON.stringify({ manifest, ts: Date.now() }));
    for (const socket of this.sockets) {
      this.sendPacket(socket, PACKET_TYPES.MANIFEST, payload);
    }
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

    const knownConnection = this.hasSocketTo(rinfo.address, data.tcp_port);
    if (!knownConnection) {
      this.connectToPeer(rinfo.address, data.tcp_port);
    }
  }

  handleTcpPacket(socket, packet) {
    const peerIdHex = packet.nodeId.toString('hex');
    if (peerIdHex === this.nodeIdHex) return;
    socket.__peerIdHex = peerIdHex;
    this.peerSockets.set(peerIdHex, socket);

    const data = parseJsonPayload(packet.payload);

    if (packet.type === PACKET_TYPES.HELLO && data) {
      this.peerTable.upsert(peerIdHex, {
        ip: socket.remoteAddress,
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

    if (packet.type === PACKET_TYPES.MANIFEST && data?.manifest) {
      const existing = this.peerTable.list().find((peer) => peer.node_id === peerIdHex);
      if (existing) {
        this.peerTable.upsert(peerIdHex, {
          ...existing,
          shared_files: data.manifest.shared_files || [],
          last_seen: Date.now()
        });
      }
      return;
    }

    if (packet.type === PACKET_TYPES.ACK) {
      if (data?.kind === 'ping') {
        const payload = Buffer.from(JSON.stringify({ kind: 'pong', ts: Date.now() }));
        this.sendPacket(socket, PACKET_TYPES.ACK, payload);
      }
      this.peerTable.markSeen(peerIdHex);
    }
  }
}
