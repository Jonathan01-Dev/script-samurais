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

## Sprint 3 - Chunking et transfert

Checks automatiques:

```bash
npm run check:s3
```

Ou via script:

```bash
bash demo/check_s3.sh
```

Critere de validation S3 (document):
- Manifest diffuse et recu par les pairs.
- Chunks verifies par SHA-256.
- Reassemblage final avec hash identique au fichier source.
