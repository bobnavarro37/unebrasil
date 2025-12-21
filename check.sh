#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Subindo containers..."
docker compose up -d

echo "[2/4] Healthcheck (aguardando API ficar pronta)..."
for i in {1..30}; do
  if curl -fsS http://localhost:8000/health >/dev/null; then
    echo "OK: /health"
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    echo "ERRO: /health não respondeu após 30s"
    exit 1
  fi
done

echo "[3/4] DB ok (listando tabelas)..."
docker compose exec -T db psql -U unebrasil -d unebrasil -c "\dt" >/dev/null
echo "OK: DB"

echo "[4/4] Rodando testes..."
./test.sh
echo "OK: tests"
