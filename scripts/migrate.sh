#!/usr/bin/env bash
set -euo pipefail
docker compose exec -T db psql -U unebrasil -d unebrasil < scripts/migrate.sql
