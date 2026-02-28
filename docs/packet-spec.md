# Archipel Packet v1

## Header

- `MAGIC` (4 bytes): `ARCP`
- `TYPE` (1 byte)
- `NODE_ID` (32 bytes): cle publique Ed25519 hachee (SHA-256)
- `PAYLOAD_LEN` (4 bytes, uint32 big-endian)

## Body

- `PAYLOAD` (variable)
- `HMAC_SHA256` (32 bytes)

## Types

- `0x01` `HELLO`
- `0x02` `PEER_LIST`
- `0x03` `MSG`
- `0x04` `CHUNK_REQ`
- `0x05` `CHUNK_DATA`
- `0x06` `MANIFEST`
- `0x07` `ACK`

## Encodage TLV sur TCP

Chaque message TCP est encode en TLV:

- `T` (1 byte): type
- `L` (4 bytes, uint32 big-endian): longueur
- `V` (`L` bytes): valeur

## Notes Sprint 1-ready

- `HELLO` emis toutes les 30 secondes
- timeout pair mort: 90 secondes
- keepalive TCP ping/pong: 15 secondes
