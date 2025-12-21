#!/usr/bin/env bash
set -euo pipefail
docker compose exec api pytest -q
