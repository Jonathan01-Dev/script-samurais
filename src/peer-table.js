export class PeerTable {
  constructor() {
    this.peers = new Map();
  }

  upsert(nodeId, data) {
    this.peers.set(nodeId, {
      node_id: nodeId,
      ip: data.ip,
      tcp_port: data.tcp_port,
      last_seen: data.last_seen || Date.now(),
      shared_files: data.shared_files || [],
      reputation: data.reputation ?? 1.0
    });
  }

  markSeen(nodeId) {
    const peer = this.peers.get(nodeId);
    if (!peer) return;
    peer.last_seen = Date.now();
  }

  removeExpired(timeoutMs) {
    const now = Date.now();
    for (const [nodeId, peer] of this.peers.entries()) {
      if (now - peer.last_seen > timeoutMs) this.peers.delete(nodeId);
    }
  }

  list() {
    return [...this.peers.values()];
  }
}
