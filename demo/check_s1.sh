#!/usr/bin/env bash
set -euo pipefail

test -f package.json
test -f src/node-runtime.js
test -f src/packet.js
test -f src/tlv.js
test -f scripts/smoke-network.js
test -f scripts/check-sprint1.js

npm run smoke:network
npm run check:s1

echo "[OK] check Sprint 1"
