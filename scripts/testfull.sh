#!/usr/bin/env bash
set -euo pipefail

# TOKEN aqui é do APP (Bearer), NÃO é github_pat
: "${TOKEN:?ERRO: defina TOKEN do APP (ex: export TOKEN=user:1 ou export TOKEN=eyJhbGci...)}"

get_balance () {
  curl -s http://127.0.0.1:8000/wallet/balance \
    -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); b=d.get("balance") or (d.get("data") or {}).get("balance") or (d.get("result") or {}).get("balance"); import sys; print(int(b)) if b is not None else (print("ERRO: JSON sem balance:", d) or sys.exit(2))'
}

BAL_BEFORE="$(get_balance)"
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

BAL_AFTER_CREATED="$(get_balance)"
echo "== balance depois do created =="; echo "$BAL_AFTER_CREATED"

python3 -c "b=int('$BAL_BEFORE'); a=int('$BAL_AFTER_CREATED'); assert a==b+10, f'ERRO: balance não somou +10 (antes={b} depois={a})'; print('OK: wallet somou +10 no created')"
echo "== 2) troca IMEDIATA (429 esperado) =="
curl -s -i -X POST http://127.0.0.1:8000/vote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"decision_id\":$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p" || true

echo "== espera 61s =="; sleep 61

echo "== 3) troca após esperar (200 updated) =="
curl -s -i -X POST http://127.0.0.1:8000/vote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"decision_id\":$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p" || true

BAL_FINAL="$(get_balance)"
echo "== balance final =="; echo "$BAL_FINAL"

python3 -c "a=int('$BAL_AFTER_CREATED'); f=int('$BAL_FINAL'); assert f==a, f'ERRO: balance mudou após update (não podia somar +10). after_created={a} final={f}'; print('OK: wallet (+10 uma vez só)')"

echo "== rewards no DB (tem que 1 / total_amount 10) =="
docker compose exec -T db psql -U unebrasil -d unebrasil -c \
"select decision_id, count(*) rewards, sum(amount) total_amount
 from wallet_txs
 where user_id=1 and kind='vote_reward' and decision_id=$DECISION_ID
 group by decision_id;"

echo "OK: testfull passou"
