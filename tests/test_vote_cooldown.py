import subprocess,time,httpx

def sh(cmd:str)->str:
    return subprocess.check_output(cmd,shell=True,text=True).strip()

def token()->str:
    t=sh("make -s token 2>/dev/null || true")
    assert len(t)>20
    return t

def eligible()->int:
    q="WITH rep AS (SELECT politician_id FROM citizen_reps WHERE user_id=1 AND election_id=2026 AND role='dep_federal' AND ended_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1), pool AS (SELECT d.id FROM decisions d JOIN official_votes ov ON ov.decision_id=d.id JOIN rep r ON r.politician_id=ov.politician_id LEFT JOIN citizen_votes cv ON cv.decision_id=d.id AND cv.voter_id='1' WHERE d.archived=false AND lower(coalesce(d.source,''))='camara' AND cv.id IS NULL) SELECT coalesce((SELECT id::text FROM pool ORDER BY id DESC LIMIT 1),'');" 
    out=sh(f'docker compose exec -T db psql -U unebrasil -d unebrasil -tA -c "{q}"'); assert out.isdigit(); return int(out)

def rewards(did:int)->int:
    out=sh(f"docker compose exec -T db psql -U unebrasil -d unebrasil -tA -c \"select count(*) from wallet_txs where user_id=1 and decision_id={did} and kind='vote_reward';\"")
    return int(out)

def post(c,tk,did,ch):
    return c.post('http://127.0.0.1:8000/vote',headers={'Authorization':f'Bearer {tk}'},json={'decision_id':did,'choice':ch})

def test_vote_cooldown():
    tk=token(); did=eligible()
    with httpx.Client(timeout=5) as c:
        r1=post(c,tk,did,'concordo'); assert r1.status_code==200 and r1.json()['action']=='created'
        r2=post(c,tk,did,'discordo'); assert r2.status_code==200 and r2.json()['action']=='updated'
        r3=post(c,tk,did,'concordo'); assert r3.status_code==429
        time.sleep(10)
        r4=post(c,tk,did,'concordo'); assert r4.status_code==200 and r4.json()['action']=='updated'
    assert rewards(did)==1
