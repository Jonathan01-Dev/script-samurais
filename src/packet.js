import { createHmac } from 'node:crypto';

export const PACKET_TYPES = {
  HELLO: 0x01,
  PEER_LIST: 0x02,
  MSG: 0x03,
  CHUNK_REQ: 0x04,
  CHUNK_DATA: 0x05,
  MANIFEST: 0x06,
  ACK: 0x07
};

export const MAGIC = Buffer.from('ARCP');

export function buildPacket(type, nodeId32, payloadBuffer, hmacKey) {
  if (!Buffer.isBuffer(nodeId32) || nodeId32.length !== 32) {
    throw new Error('nodeId32 must be a 32-byte Buffer');
  }
  const payload = Buffer.isBuffer(payloadBuffer)
    ? payloadBuffer
    : Buffer.from(payloadBuffer || '');

  const header = Buffer.alloc(4 + 1 + 32 + 4);
  MAGIC.copy(header, 0);
  header.writeUInt8(type, 4);
  nodeId32.copy(header, 5);
  header.writeUInt32BE(payload.length, 37);

  const signed = Buffer.concat([header, payload]);
  const mac = createHmac('sha256', hmacKey).update(signed).digest();
  return Buffer.concat([signed, mac]);
}

export function parsePacket(raw, hmacKey) {
  if (!Buffer.isBuffer(raw) || raw.length < 73) {
    throw new Error('invalid packet');
  }

  const magic = raw.subarray(0, 4);
  if (!magic.equals(MAGIC)) throw new Error('invalid magic');

  const type = raw.readUInt8(4);
  const nodeId = raw.subarray(5, 37);
  const payloadLen = raw.readUInt32BE(37);

  const payloadStart = 41;
  const payloadEnd = payloadStart + payloadLen;
  const macStart = payloadEnd;

  if (raw.length !== macStart + 32) throw new Error('invalid length');

  const payload = raw.subarray(payloadStart, payloadEnd);
  const mac = raw.subarray(macStart);
  const expected = createHmac('sha256', hmacKey)
    .update(raw.subarray(0, macStart))
    .digest();

  if (!mac.equals(expected)) throw new Error('invalid hmac');

  return { type, nodeId, payload };
}
