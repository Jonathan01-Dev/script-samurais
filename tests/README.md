## Sprint 1 - Reseau P2P

Checks automatiques:

```bash
npm run smoke:network
npm run check:s1
```

Ou via script de validation:

```bash
bash demo/check_s1.sh
```

Critere de validation S1 (document):
- 3 noeuds se decouvrent en moins de 60 secondes.

## Sprint 2 - Crypto/Auth

Check automatique:

```bash
npm run check:s2
```

Critere de validation S2 (document):
- Handshake securise etabli entre pairs.
- Message chiffre transmis et dechiffre correctement.
