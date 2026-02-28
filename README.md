# Archipel

Protocole P2P chiffre et decentralise a zero-connexion (LAN only).

## Sprint 0 - Decisions d'architecture

- Langage principal: **Node.js (JavaScript)**
- Justification:
  - API reseau native (UDP/TCP) simple et rapide a iterer en hackathon
  - Crypto native (`node:crypto`) pour Ed25519/X25519/AES-GCM/HMAC
  - Bon compromis vitesse de dev/debug pour une equipe mixte
- Transport local retenu:
  - **UDP Multicast** pour la decouverte (`HELLO`)
  - **TCP** pour les echanges point-a-point (`PEER_LIST`, transferts chunks)

## Contraintes non-negociables

- Zero internet pendant execution
- Zero serveur central
- Zero autorite de certification externe

## Architecture (Sprint 0)

```text
                    +----------------------+
                    |   UDP Multicast LAN  |
                    | 239.255.42.99:6000   |
                    +----------+-----------+
                               |
             HELLO every 30s   |   presence broadcast
                               |
        +----------------------+----------------------+
        |                                             |
+-------v--------+                             +------v---------+
|   Node A       |<------- TCP (TLV) --------->|    Node B      |
| client+server  |                             | client+server   |
| Ed25519 ID     |                             | Ed25519 ID      |
| Peer Table     |                             | Peer Table      |
+-------+--------+                             +------+----------+
        |                                             |
        +----------------------+----------------------+
                               |
                         +-----v------+
                         |   Node C    |
                         | client+srv  |
                         +------------+
```

## Format paquet binaire v1

Details dans [docs/packet-spec.md](docs/packet-spec.md).

## Structure projet

```text
.
├── src/
│   ├── config.js
│   ├── packet.js
│   └── peer-table.js
├── scripts/
│   └── generate-keys.js
├── docs/
│   └── packet-spec.md
├── keys/
├── .env.example
├── .gitignore
└── package.json
```

## Initialisation

```bash
npm run init:keys
```

Commande par defaut (3 noeuds): genere `keys/node1`, `keys/node2`, `keys/node3`.

## Livrable Sprint 0

- [x] Stack choisie et justifiee
- [x] Schema d'architecture
- [x] Specification de paquet
- [x] Generation des cles PKI (Ed25519)
- [ ] Tag Git `sprint-0` (a faire apres commit)
