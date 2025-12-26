# STATUS Unebrasil

- Gerado em: 2025-12-25T14:41:18-03:00

## Git
## master
 M app/__pycache__/main.cpython-311.pyc
 M app/main.py
 M docker-compose.yml
 M requirements.txt
?? app/main.py.bak
?? app/main.py.bak2
?? app/main.py.bak3
?? app/main.py.bak_add_admin_audit_20251224_182310
?? app/main.py.bak_add_audit_sql_20251224_181049
?? app/main.py.bak_add_count_20251224_152617
?? app/main.py.bak_add_hash_20251224_151441
?? app/main.py.bak_add_login_20251224_151201
?? app/main.py.bak_add_post_decisions_20251224_152427
?? app/main.py.bak_add_ratevote_20251224_152705
?? app/main.py.bak_add_verify_20251224_151256
?? app/main.py.bak_add_vote_20251224_152537
?? app/main.py.bak_admin_guard_20251224_185224
?? app/main.py.bak_admin_guard_20251225_105243
?? app/main.py.bak_admin_router2_20251225_140306
?? app/main.py.bak_admin_router_20251225_134621
?? app/main.py.bak_admin_users_20251225_141239
?? app/main.py.bak_align_updatedat
?? app/main.py.bak_align_updatedat2
?? app/main.py.bak_audit_vote_20251224_174511
?? app/main.py.bak_auth
?? app/main.py.bak_badblock
?? app/main.py.bak_changevote
?? app/main.py.bak_countfix
?? app/main.py.bak_detab_updatedat
?? app/main.py.bak_eofnt
?? app/main.py.bak_existing_fix
?? app/main.py.bak_existing_full
?? app/main.py.bak_final_fix
?? app/main.py.bak_fix_admin_block_20251225_142503
?? app/main.py.bak_fix_admin_block_20251225_142649
?? app/main.py.bak_fix_admin_guard_20251225_130403
?? app/main.py.bak_fix_admin_imports_20251225_121911
?? app/main.py.bak_fix_audit_sql_20251224_174938
?? app/main.py.bak_fix_import_text_20251224_183112
?? app/main.py.bak_fix_indent_updatedat
?? app/main.py.bak_fix_indent_vote_20251224_175256
?? app/main.py.bak_fix_myvote_host_20251224_150120
?? app/main.py.bak_fix_ratevote_20251224_152748
?? app/main.py.bak_fix_register_20251224_145203
?? app/main.py.bak_fix_unique
?? app/main.py.bak_fix_updatedat_place
?? app/main.py.bak_fix_voteaudit_pos_20251224_174659
?? app/main.py.bak_force_indent
?? app/main.py.bak_force_verify_20251224_151333
?? app/main.py.bak_harden_admin_audit_20251224_184100
?? app/main.py.bak_indent
?? app/main.py.bak_indent2
?? app/main.py.bak_indent_final
?? app/main.py.bak_kill429
?? app/main.py.bak_myvote
?? app/main.py.bak_myvote2
?? app/main.py.bak_norl
?? app/main.py.bak_pbkdf2
?? app/main.py.bak_pwd
?? app/main.py.bak_pwdfix_ep
?? app/main.py.bak_racefix
?? app/main.py.bak_raceindent
?? app/main.py.bak_rewrite_vote2_20251224_180335
?? app/main.py.bak_rewrite_vote_20251224_180000
?? app/main.py.bak_rl
?? app/main.py.bak_rl2
?? app/main.py.bak_rl3
?? app/main.py.bak_rl4
?? app/main.py.bak_rl_fix
?? app/main.py.bak_rl_indent2
?? app/main.py.bak_rl_indent3
?? app/main.py.bak_rl_indent_fix
?? app/main.py.bak_rl_indent_fix2
?? app/main.py.bak_rl_indent_fix3
?? app/main.py.bak_rm_touch
?? app/main.py.bak_tabs
?? app/main.py.bak_touch_updatedat
?? app/main.py.bak_vote_full
?? app/main.py.bak_wallet
?? app/main.py.bak_wallet_rm
?? docker-compose.yml.bak_admintoken_20251224_185224
?? docker-compose.yml.bak_admintoken_20251225_105243
?? docker-compose.yml.bak_env_20251224_173806
?? docker-compose.yml.bak_fix_envmap_20251224_182048
?? docker-compose.yml.bak_fix_yaml_20251224_174016
?? docker-compose.yml.bak_pyc2_20251224_181708
?? docker-compose.yml.bak_pyc_20251224_181411
?? docs/

## Containers
NAME                      IMAGE              COMMAND                  SERVICE       CREATED       STATUS             PORTS
unebrasil-api-1           python:3.11-slim   "bash -c ' pip insta…"   api           2 hours ago   Up About an hour   0.0.0.0:8000->8000/tcp, [::]:8000->8000/tcp
unebrasil-db-1            postgres:15        "docker-entrypoint.s…"   db            2 hours ago   Up 2 hours         0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp
unebrasil-sync_camara-1   python:3.11-slim   "bash -c ' pip insta…"   sync_camara   2 hours ago   Up 2 hours         

## Health
HTTP/1.1 200 OK
date: Thu, 25 Dec 2025 17:41:18 GMT
server: uvicorn
content-length: 15
content-type: application/json

{"status":"ok"}
## OpenAPI (debug)
HTTP_CODE=200 bytes=9107
HEAD_200_BYTES:
{"openapi":"3.1.0","info":{"title":"Unebrasil","version":"0.1.0"},"paths":{"/health":{"get":{"summary":"Health","operationId":"health_health_get","responses":{"200":{"description":"Successful Response

## Rotas (OpenAPI)
GET    /admin/vote-audit
POST   /auth/login
POST   /auth/register
POST   /decisions
GET    /decisions/latest
GET    /decisions/{decision_id}/live
GET    /decisions/{decision_id}/stream
GET    /decisions/{decision_id}/summary
GET    /health
GET    /me
GET    /ranking/decisions
GET    /ranking/users
POST   /vote
GET    /wallet/balance
GET    /wallet/transactions

## DB: tabelas
              List of relations
 Schema |      Name      | Type  |   Owner   
--------+----------------+-------+-----------
 public | citizen_votes  | table | unebrasil
 public | decisions      | table | unebrasil
 public | official_votes | table | unebrasil
 public | politicians    | table | unebrasil
 public | users          | table | unebrasil
 public | vote_audit     | table | unebrasil
 public | wallet_txs     | table | unebrasil
(7 rows)


## DB: contagens
 users | decisions | citizen_votes | wallet_txs | vote_audit 
-------+-----------+---------------+------------+------------
     5 |      1007 |             9 |          9 |         12
(1 row)


## Logs api (tail 40)
api-1  | INFO:     172.18.0.1:56576 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:56590 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 401 Unauthorized
api-1  | INFO:     172.18.0.1:56604 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:54462 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 401 Unauthorized
api-1  | INFO:     172.18.0.1:54468 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:50860 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 401 Unauthorized
api-1  | INFO:     172.18.0.1:50868 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:45042 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:45044 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 401 Unauthorized
api-1  | INFO:     172.18.0.1:45056 - "GET /admin/vote-audit?decision_id=1003&user_id=4&limit=2 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:52668 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:43930 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:43940 - "GET /admin/vote-audit?limit=2 HTTP/1.1" 401 Unauthorized
api-1  | INFO:     172.18.0.1:43948 - "GET /admin/vote-audit?limit=2 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:39588 - "POST /auth/register HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:39602 - "POST /auth/login HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:39612 - "GET /me HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:39618 - "POST /decisions HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:39624 - "POST /vote HTTP/1.1" 422 Unprocessable Entity
api-1  | INFO:     172.18.0.1:39636 - "GET /admin/vote-audit?decision_id=&user_id=5&limit=10 HTTP/1.1" 422 Unprocessable Entity
api-1  | INFO:     172.18.0.1:47038 - "POST /auth/login HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:47044 - "GET /me HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:47048 - "POST /decisions HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:47050 - "POST /vote HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:47056 - "GET /admin/vote-audit?decision_id=1005&user_id=5&limit=10 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:59236 - "POST /auth/login HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:59244 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:59258 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:59264 - "GET /admin/vote-audit?decision_id=1005&user_id=5&limit=10 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:35656 - "POST /auth/login HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:35670 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:35680 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:36966 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:36972 - "POST /vote HTTP/1.1" 429 Too Many Requests
api-1  | INFO:     172.18.0.1:36978 - "POST /vote HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:36992 - "GET /admin/vote-audit?decision_id=1005&user_id=5&limit=20 HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:36350 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:36360 - "GET /openapi.json HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:57976 - "GET /health HTTP/1.1" 200 OK
api-1  | INFO:     172.18.0.1:57984 - "GET /openapi.json HTTP/1.1" 200 OK

## 2025-12-26T16:02:25Z
- ✅ /vote idempotente (created/unchanged/updated) sem cooldown
- ✅ vote_reward 1x por (user, decision)
- ✅ /admin/vote-audit protegido por X-Admin-Token e aparece no OpenAPI
- ✅ /decisions/{id}/my-vote retorna updated_at + created_at
- ✅ DB: citizen_votes.created_at (timestamptz NOT NULL DEFAULT now) + model mapeado
