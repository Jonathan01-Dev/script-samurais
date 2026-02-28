import dgram from 'node:dgram';
import net from 'node:net';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify
} from 'node:crypto';
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

function normalizeIp(value) {
  return String(value || '').replace('::ffff:', '');
}

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
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
    this.privateKeyPem = readFileSync(path.join(keyDir, 'private.pem'), 'utf8');
    this.publicKey = createPublicKey(this.publicKeyPem);
    this.privateKey = createPrivateKey(this.privateKeyPem);

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

    this.sessions = new Map();
    this.pendingHandshakes = new Map();
    this.inbox = [];

    const trustDir = options.trustDir || path.join(process.cwd(), '.archipel');
    mkdirSync(trustDir, { recursive: true });
    this.trustStorePath = path.join(trustDir, 'trust-store.json');
    this.trustStore = this.loadTrustStore();
  }

  loadTrustStore() {
    try {
      const raw = readFileSync(this.trustStorePath, 'utf8');
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  saveTrustStore() {
    writeFileSync(this.trustStorePath, JSON.stringify(this.trustStore, null, 2));
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

  getInbox() {
    return [...this.inbox];
  }

  hasSecureSession(peerIdHex) {
    return this.sessions.has(peerIdHex);
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
        capabilities: ['discovery', 'tcp', 'manifest', 'e2e'],
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
      this.startHandshakeAsInitiator(socket);
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
      if (normalizeIp(socket.remoteAddress) === ip && socket.remotePort === tcpPort) return true;
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

  startHandshakeAsInitiator(socket) {
    const eph = generateKeyPairSync('x25519');
    socket.__localEphPrivate = eph.privateKey;
    socket.__localEphPublicPem = eph.publicKey.export({ type: 'spki', format: 'pem' });

    const payload = Buffer.from(
      JSON.stringify({
        tcp_port: this.tcpPort,
        ts: Date.now(),
        e_pub: socket.__localEphPublicPem
      })
    );
    this.sendPacket(socket, PACKET_TYPES.HELLO, payload);
  }

  trustPeer(peerIdHex, identityPubPem) {
    const fingerprint = sha256Hex(identityPubPem);
    const known = this.trustStore[peerIdHex];
    if (!known) {
      this.trustStore[peerIdHex] = {
        fingerprint,
        identity_pub_pem: identityPubPem,
        first_seen: Date.now()
      };
      this.saveTrustStore();
      return true;
    }
    return known.fingerprint === fingerprint;
  }

  deriveSession(localPrivateKey, remotePublicPem) {
    const shared = diffieHellman({
      privateKey: localPrivateKey,
      publicKey: createPublicKey(remotePublicPem)
    });
    const sessionKey = hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from('archipel-v1'), 32);
    const sharedHash = createHash('sha256').update(shared).digest();
    return { sessionKey, sharedHash };
  }

  onHello(socket, peerIdHex, data) {
    if (!data?.e_pub) return;
    const responderEph = generateKeyPairSync('x25519');
    const responderEphPubPem = responderEph.publicKey.export({ type: 'spki', format: 'pem' });
    const { sessionKey, sharedHash } = this.deriveSession(responderEph.privateKey, data.e_pub);
    const sig = sign(null, sharedHash, this.privateKey).toString('base64');

    this.pendingHandshakes.set(peerIdHex, {
      socket,
      sessionKey,
      sharedHash
    });

    const payload = Buffer.from(
      JSON.stringify({
        e_pub: responderEphPubPem,
        sig,
        identity_pub: this.publicKeyPem,
        ts: Date.now()
      })
    );
    this.sendPacket(socket, PACKET_TYPES.HELLO_REPLY, payload);
  }

  onHelloReply(socket, peerIdHex, data) {
    if (!data?.e_pub || !data?.sig || !data?.identity_pub || !socket.__localEphPrivate) return;

    if (!this.trustPeer(peerIdHex, data.identity_pub)) {
      console.warn(`[security] TOFU mismatch for ${peerIdHex}`);
      socket.destroy();
      return;
    }

    const { sessionKey, sharedHash } = this.deriveSession(socket.__localEphPrivate, data.e_pub);
    const remoteIdentity = createPublicKey(data.identity_pub);
    const sigOk = verify(null, sharedHash, remoteIdentity, Buffer.from(data.sig, 'base64'));
    if (!sigOk) {
      console.warn(`[security] invalid HELLO_REPLY signature from ${peerIdHex}`);
      socket.destroy();
      return;
    }

    this.pendingHandshakes.set(peerIdHex, {
      socket,
      sessionKey,
      sharedHash
    });

    const authSig = sign(null, sharedHash, this.privateKey).toString('base64');
    const payload = Buffer.from(
      JSON.stringify({
        sig: authSig,
        identity_pub: this.publicKeyPem,
        ts: Date.now()
      })
    );
    this.sendPacket(socket, PACKET_TYPES.AUTH, payload);
  }

  onAuth(socket, peerIdHex, data) {
    const pending = this.pendingHandshakes.get(peerIdHex);
    if (!pending || !data?.sig || !data?.identity_pub) return;

    if (!this.trustPeer(peerIdHex, data.identity_pub)) {
      console.warn(`[security] TOFU mismatch for ${peerIdHex}`);
      socket.destroy();
      return;
    }

    const remoteIdentity = createPublicKey(data.identity_pub);
    const sigOk = verify(null, pending.sharedHash, remoteIdentity, Buffer.from(data.sig, 'base64'));
    if (!sigOk) {
      console.warn(`[security] invalid AUTH signature from ${peerIdHex}`);
      socket.destroy();
      return;
    }

    this.sessions.set(peerIdHex, {
      key: pending.sessionKey,
      establishedAt: Date.now()
    });
    this.sendPacket(socket, PACKET_TYPES.AUTH_OK, Buffer.from(JSON.stringify({ ok: true, ts: Date.now() })));
    this.sendPeerList(socket);
  }

  onAuthOk(peerIdHex) {
    const pending = this.pendingHandshakes.get(peerIdHex);
    if (!pending) return;
    this.sessions.set(peerIdHex, {
      key: pending.sessionKey,
      establishedAt: Date.now()
    });
    this.sendPeerList(pending.socket);
  }

  sendEncryptedMessage(peerIdHex, plaintext) {
    const session = this.sessions.get(peerIdHex);
    const socket = this.peerSockets.get(peerIdHex);
    if (!session || !socket) {
      throw new Error(`no secure session with ${peerIdHex}`);
    }

    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', session.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();

    const payload = Buffer.from(
      JSON.stringify({
        nonce: nonce.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        ts: Date.now()
      })
    );
    this.sendPacket(socket, PACKET_TYPES.MSG, payload);
  }

  onEncryptedMessage(peerIdHex, data) {
    const session = this.sessions.get(peerIdHex);
    if (!session || !data?.nonce || !data?.tag || !data?.ciphertext) return;

    try {
      const nonce = Buffer.from(data.nonce, 'base64');
      const tag = Buffer.from(data.tag, 'base64');
      const ciphertext = Buffer.from(data.ciphertext, 'base64');

      const decipher = createDecipheriv('aes-256-gcm', session.key, nonce);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      this.inbox.push({ from: peerIdHex, plaintext, ts: Date.now() });
    } catch {
      console.warn(`[security] decrypt failed from ${peerIdHex}`);
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

    if (!this.hasSocketTo(rinfo.address, data.tcp_port)) {
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
        ip: normalizeIp(socket.remoteAddress),
        tcp_port: data.tcp_port || socket.remotePort,
        last_seen: Date.now(),
        shared_files: data.manifest?.shared_files || []
      });
      this.onHello(socket, peerIdHex, data);
      return;
    }

    if (packet.type === PACKET_TYPES.HELLO_REPLY) {
      this.onHelloReply(socket, peerIdHex, data);
      return;
    }

    if (packet.type === PACKET_TYPES.AUTH) {
      this.onAuth(socket, peerIdHex, data);
      return;
    }

    if (packet.type === PACKET_TYPES.AUTH_OK) {
      this.onAuthOk(peerIdHex);
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

    if (packet.type === PACKET_TYPES.MSG) {
      this.onEncryptedMessage(peerIdHex, data);
      this.peerTable.markSeen(peerIdHex);
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
