export const CONFIG = {
  tcpPort: Number(process.env.TCP_PORT || 7777),
  maxConnections: Number(process.env.TCP_MAX_CONNECTIONS || 50),
  discovery: {
    address: process.env.DISCOVERY_MULTICAST_ADDR || '239.255.42.99',
    port: Number(process.env.DISCOVERY_MULTICAST_PORT || 6000),
    helloIntervalMs: Number(process.env.DISCOVERY_HELLO_INTERVAL_MS || 30000),
    peerTimeoutMs: Number(process.env.DISCOVERY_PEER_TIMEOUT_MS || 90000)
  },
  keepAliveIntervalMs: Number(process.env.TCP_PING_INTERVAL_MS || 15000)
};
