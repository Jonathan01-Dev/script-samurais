export function encodeTlv(type, value) {
  if (!Number.isInteger(type) || type < 0 || type > 0xff) {
    throw new Error('tlv type must be uint8');
  }
  if (!Buffer.isBuffer(value)) {
    throw new Error('tlv value must be a Buffer');
  }

  const out = Buffer.alloc(1 + 4 + value.length);
  out.writeUInt8(type, 0);
  out.writeUInt32BE(value.length, 1);
  value.copy(out, 5);
  return out;
}

export function createTlvDecoder(onMessage) {
  let pending = Buffer.alloc(0);

  return (chunk) => {
    pending = Buffer.concat([pending, chunk]);

    while (pending.length >= 5) {
      const type = pending.readUInt8(0);
      const len = pending.readUInt32BE(1);
      const frameSize = 5 + len;
      if (pending.length < frameSize) break;

      const value = pending.subarray(5, frameSize);
      onMessage({ type, value });
      pending = pending.subarray(frameSize);
    }
  };
}
