#!/usr/bin/env bash
set -euo pipefail

: "${TOKEN:?ERRO: export TOKEN=...}"

BAL_BEFORE="$(curl -s http://127.0.0.1:8000/wallet/balance \
  -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["balance"])')"

DECISION_ID="$(curl -s -X POST http://127.0.0.1:8000/decisions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source\":\"test\",\"external_id\":\"$(date +%s)\",\"title\":\"Teste FULL MAKE $(date +%s)\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"

echo "DECISION_ID=$DECISION_ID"
echo "== balance antes =="; echo "$BAL_BEFORE"

echo "== 1) created (200 +10) =="
curl -s -i -X POST http://127.0.0.1:8000/vote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"decision_id\":$DECISION_ID,\"choice\":\"concordo\"}" | sed -n "1,25p" || true

BAL_AFTER_CREATED="$(curl -s http://127.0.0.1:8000/wallet/balance \
  -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["balance"])')"
echo "== balance depois do created =="; echo "$BAL_AFTER_CREATED"

python3 - <<PY
b=int("$BAL_BEFORE"); a=int("$BAL_AFTER_CREATED")
assert a==b+10, f"ERRO: balance não somou +10 (antes={b} depois={a})"
print("OK: wallet somou +10 no created")
PY

echo "== 2) troca IMEDIATA (tem que 429) =="
curl -s -i -X POST http://127.0.0.1:8000/vote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"decision_id\":$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p" || true

echo "== espera 61s =="
sleep 61

echo "== 3) troca após esperar (200 updated) =="
curl -s -i -X POST http://127.0.0.1:8000/vote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"decision_id\":$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p" || true

BAL_FINAL="$(curl -s http://127.0.0.1:8000/wallet/balance \
  -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["balance"])')"
echo "== balance final =="; echo "$BAL_FINAL"

python3 - <<PY
b=int("$BAL_BEFORE"); c=int("$BAL_AFTER_CREATED"); f=int("$BAL_FINAL")
assert c==b+10, f"ERRO: balance não somou +10 (antes={b} depois_created={c})"
assert f==c, f"ERRO: balance mudou após trocar voto (created={c} final={f})"
print("OK: wallet (+10 uma vez só)")
PY

echo "== rewards no DB (tem que 1 / total_amount 10) =="
docker compose exec -T db psql -U unebrasil -d unebrasil -c \
"select decision_id, count(*) rewards, sum(amount) total_amount
 from wallet_txs
 where user_id=1 and kind='vote_reward' and decision_id=$DECISION_ID
 group by decision_id;"

echo "OK: testfull passou"
