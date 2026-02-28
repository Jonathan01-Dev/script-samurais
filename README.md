# Archipel

Protocole P2P chiffre et decentralise a zero-connexion (LAN only).

## Portee actuelle

Ce depot est actuellement aligne sur:
- Sprint 0: Bootstrap & architecture
- Sprint 1: Couche reseau P2P (decouverte de pairs)

## Sprint 0 - Decisions d'architecture

- Langage principal: **Node.js (JavaScript)**
- Transport local retenu:
  - **UDP Multicast** pour la decouverte (`HELLO`)
  - **TCP** pour les echanges point-a-point (`HELLO`, `PEER_LIST`, `ACK`)
- Contrainte: zero internet, zero serveur central

## Architecture reseau (S0/S1)

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
+----------------+                             +-----------------+
```

## Format paquet binaire v1

Details dans [docs/packet-spec.md](docs/packet-spec.md).

## Structure projet

```text
.
├── src/
│   ├── cli.js
│   ├── config.js
│   ├── node-runtime.js
│   ├── packet.js
│   ├── peer-table.js
│   └── tlv.js
├── scripts/
│   ├── generate-keys.js
│   └── smoke-network.js
├── docs/
│   └── packet-spec.md
├── keys/
└── package.json
```

## Initialisation

```bash
npm run init:keys
```

Genere par defaut 3 noeuds (`keys/node1`, `keys/node2`, `keys/node3`).

## Execution Sprint 1

Terminal 1:
```bash
npm run node:run
```

Terminal 2:
```bash
npm run node:run:2
```

Chaque noeud:
- diffuse sa presence en UDP multicast (`HELLO`)
- demarre un serveur TCP
- ouvre un handshake TCP (`HELLO`/`ACK`)
- echange une `PEER_LIST`

## Test rapide local (S1)

```bash
npm run smoke:network
```

Ce test demarre 2 noeuds locaux et valide la decouverte de pairs.

Validation sprint 1 (critere doc: 3 noeuds en moins de 60 secondes):

```bash
npm run check:s1
```

## Livrables S0/S1

- [x] Stack choisie et justifiee
- [x] Schema d'architecture
- [x] Specification de paquet
- [x] Generation des cles PKI (Ed25519)
- [x] Decouverte UDP multicast
- [x] Couche TCP avec framing TLV
- [x] Handshake de base (`HELLO` + `ACK` + `PEER_LIST`)

# script-samurais

Projet Archipel - Hackathon 24h.

## Objectif
Construire un protocole P2P local, chiffré de bout en bout, sans serveur central.

## Sprint 0 (bootstrap)
- Structure projet
- Spec protocole v1
- Script bootstrap
- Workflow Git equipe

## Lancer les checks Sprint 0
```bash
bash scripts/bootstrap_s0.sh
bash demo/check_s0.sh
```

## Lancer le check Sprint 1
```bash
npm run check:s1
```
