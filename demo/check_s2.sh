#!/usr/bin/env bash
set -euo pipefail

test -f src/node-runtime.js
test -f src/packet.js
test -f scripts/check-sprint2.js

npm run check:s2

echo "[OK] check Sprint 2"
