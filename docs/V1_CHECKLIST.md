# Unebrasil — Checklist rumo à V1

## Passo 1 — Base dev + testes (OK)
- [x] `make help` mostra targets
- [x] `make login` salva `APP_TOKEN` no `.env`
- [x] Makefile carrega `.env` automaticamente (`-include .env`)
- [x] `make test` valida cooldown (429 na troca imediata)
- [x] `make testfull` valida cooldown + wallet (+10 só no primeiro voto)
- [x] Seed dev: `user1@local` e `user2@local` com senha `123`

## Passo 2 — Votos oficiais (sync) + listagem básica (a fazer)
- [ ] Definir fonte “Câmara” (stub ou sync real)
- [ ] Endpoint para listar decisões (paginado)
- [ ] Endpoint para listar votos oficiais por decisão
- [ ] Smoke test do fluxo “decisão -> voto oficial -> voto cidadão”

## Passo 3 — UI mínima (a fazer)
- [ ] Tela login
- [ ] Lista de decisões
- [ ] Tela da decisão (votos oficiais + botões concordo/discordo)

## Passo 4 — V1 (a fazer)
- [ ] Docker/compose ok
- [ ] README com “como rodar”
- [ ] Release tag v1.0.0
