#!/usr/bin/env bash
set -euo pipefail

for f in README.md .gitignore .env.example docs/protocol-spec.md docs/architecture.md docs/workflow_git.md docs/repartition_equipe.md src/cli/main.py scripts/bootstrap_s0.sh; do
  test -f "$f"
done

echo "[OK] check Sprint 0"
