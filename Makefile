SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: up migrate logs ps token test testfull help
.SILENT:

help:
	@echo "Targets:"
	@echo "  make up       - sobe containers"
	@echo "  make migrate  - roda migração no db"
	@echo "  make logs     - logs do api"
	@echo "  make ps       - status dos containers"
	@echo "  make token    - imprime um JWT de dev (user_id=1)"
	@echo "  make test     - teste rápido de cooldown"
	@echo "  make testfull - teste completo (cooldown + wallet)"

up:
	docker compose up -d

migrate:
	docker compose exec -T db psql -U unebrasil -d unebrasil -f /work/scripts/migrate.sql

logs:
	docker compose logs --tail 120 api

ps:
	docker compose ps

token:
	docker compose exec -T api python3 -c 'import os,time; from jose import jwt; s=os.environ.get("JWT_SECRET"); assert s, "JWT_SECRET não está no ambiente do container"; now=int(time.time()); print(jwt.encode({"sub":"1","iat":now,"exp":now+86400}, s, algorithm="HS256"))'

test:
	APP_TOKEN="$${APP_TOKEN:-$$(make -s token)}"; TOKEN="$$APP_TOKEN"
	: "$${TOKEN:?ERRO: sem TOKEN}"
	DECISION_JSON="$$(curl -s -X POST http://127.0.0.1:8000/decisions \
	  -H "Authorization: Bearer $$TOKEN" \
	  -H "Content-Type: application/json" \
	  -d "{\"source\":\"test\",\"external_id\":\"$$(date +%s)\",\"title\":\"Teste MAKE $$(date +%s)\"}")"
	DECISION_ID="$$(printf "%s" "$$DECISION_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
	echo "DECISION_ID=$$DECISION_ID"
	echo "1) created (200)"
	curl -s -i -X POST http://127.0.0.1:8000/vote \
	  -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"decision_id\":$$DECISION_ID,\"choice\":\"concordo\"}" | sed -n "1,25p" || true
	echo
	echo "2) troca imediata (429 esperado)"
	curl -s -i -X POST http://127.0.0.1:8000/vote \
	  -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"decision_id\":$$DECISION_ID,\"choice\":\"discordo\"}" | sed -n "1,25p" || true

testfull:
	APP_TOKEN="$${APP_TOKEN:-$$(make -s token)}"; TOKEN="$$APP_TOKEN" ./scripts/testfull.sh
