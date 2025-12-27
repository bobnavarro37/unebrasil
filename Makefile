SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: up migrate logs ps test
.SILENT: test

up:
	docker compose up -d

migrate:
	docker compose exec -T db psql -U unebrasil -d unebrasil -f /work/scripts/migrate.sql

logs:
	docker compose logs --tail 120 api

ps:
	docker compose ps

test:
	: "$${TOKEN:?ERRO: export TOKEN=...}"
	DECISION_JSON="$$(curl -s -X POST http://127.0.0.1:8000/decisions \
	  -H "Authorization: Bearer $$TOKEN" \
	  -H "Content-Type: application/json" \
	  -d "{\"source\":\"test\",\"external_id\":\"$$(date +%s)\",\"title\":\"Teste MAKE $$(date +%s)\"}")"
	DECISION_ID="$$(printf "%s" "$$DECISION_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
	echo "DECISION_ID=$$DECISION_ID"
	echo "1) created (200)"
	curl -s -i -X POST http://127.0.0.1:8000/vote \
	  -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"decision_id\":$$DECISION_ID,\"choice\":\"concordo\"}" | sed -n "1,25p"
	echo
	echo "2) troca imediata (429 esperado)"
	curl -s -i -X POST http://127.0.0.1:8000/vote \
	  -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"decision_id\":$$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p"
