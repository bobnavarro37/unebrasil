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
