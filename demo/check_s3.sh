#!/usr/bin/env bash
set -euo pipefail

test -f src/node-runtime.js
test -f scripts/check-sprint3.js

npm run check:s3

echo "[OK] check Sprint 3"
