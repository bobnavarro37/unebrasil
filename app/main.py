import os
from jose import jwt, JWTError
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, APIRouter
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import case, func, text
from sqlalchemy.exc import IntegrityError
import json
import asyncio
import datetime
from typing import Dict, Set
from contextlib import asynccontextmanager
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from app.donate import donate_router
from app.database import SessionLocal, engine, Base
from app.models import User, Politician, Decision, CitizenVote, OfficialVote, WalletTx, ElectionLimit
import time
import os, smtplib
from email.message import EmailMessage
import hashlib, secrets
from datetime import datetime, timedelta, timezone

def _verify_code_hash(email:str, code:str)->str:
    return hashlib.sha256((email.strip().lower()+":"+code.strip()).encode()).hexdigest()

def _new_verify_code()->str:
    return f"{secrets.randbelow(1000000):06d}"

def _smtp_send(to_email:str, subject:str, body:str)->bool:
    stub=(os.getenv("SMTP_STUB") or "").strip().lower()
    if stub in ("1","true","yes"):
        return True
    host=(os.getenv("SMTP_HOST") or "").strip()
    if not host:
        return False
    port=int(os.getenv("SMTP_PORT") or "587")
    user=(os.getenv("SMTP_USER") or "").strip()
    password=os.getenv("SMTP_PASS") or ""
    from_email=(os.getenv("SMTP_FROM") or user or "no-reply@unebrasil.com.br").strip()
    msg=EmailMessage(); msg["From"]=from_email; msg["To"]=to_email; msg["Subject"]=subject; msg.set_content(body)
    s=smtplib.SMTP_SSL(host, port, timeout=10) if port==465 else smtplib.SMTP(host, port, timeout=10)
    if port!=465 and (os.getenv("SMTP_TLS","1")!="0"): s.starttls()
    if user: s.login(user, password)
    s.send_message(msg); s.quit()
    return True


# guard admin (centralizado)
def require_admin(request: Request):
    expected = os.getenv('ADMIN_TOKEN', '')
    token = request.headers.get('X-Admin-Token', '')
    if not expected or token != expected:
        raise HTTPException(status_code=401, detail='admin token inválido')
    return True

# router admin: qualquer rota /admin/* fica protegida automaticamente
admin_router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


@asynccontextmanager
async def lifespan(app: FastAPI):
    import app.models  # garante que todos os models registram no Base antes do create_all
    Base.metadata.create_all(bind=engine)

    from app.models import User
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
        pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

        for u in [

            dict(id=1, email="user1@local", password_hash=pwd.hash("123"), display_name="User 1", is_active=True),

            dict(id=2, email="user2@local", password_hash=pwd.hash("123"), display_name="User 2", is_active=True),

        ]:
            if not db.query(User).filter_by(id=u["id"]).first():
                db.add(User(**u))
        db.commit()
    finally:
        db.close()

    yield
    
app = FastAPI(title="Unebrasil", lifespan=lifespan)
app.include_router(donate_router)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ===== JWT auth =====
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 24h
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET não definido (coloque no .env)")

def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

from fastapi import Header

def get_current_user_id(authorization: str | None = Header(default=None)) -> int:
    # Espera: "Bearer <JWT>"
    if not authorization:
        raise HTTPException(status_code=401, detail="faltou Authorization")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization inválido")

    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="token inválido")
        user_id = int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="token inválido")
    except Exception:
        raise HTTPException(status_code=401, detail="token inválido")

    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if (not u) or (not u.is_active):
            raise HTTPException(status_code=401, detail="token inválido")
    finally:
        db.close()

    return user_id





def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===== Elections: limites automáticos por ano =====
OFFICES_DEFAULT = {
    "presidente": 1,
    "governador": 1,
    "dep_federal": 1,
    "dep_estadual": 1,
}

def _senador_limit_for_year(year: int) -> int:
    r = year % 8
    if r == 2:
        return 2
    if r == 6:
        return 1
    return 1

def get_or_create_election_limits(db: Session, year: int, election_type: str = "geral") -> dict:
    year = int(year)
    rows = db.query(ElectionLimit).filter(
        ElectionLimit.election_year == year,
        ElectionLimit.election_type == election_type,
    ).all()
    by_office = {r.office: r for r in rows}

    desired = dict(OFFICES_DEFAULT)
    desired["senador"] = _senador_limit_for_year(year)

    changed = False
    for office, max_reps in desired.items():
        r = by_office.get(office)
        if r and (r.source or "").startswith("manual"):
            continue
        if r:
            if r.max_reps != max_reps:
                r.max_reps = max_reps
                r.source = "rule:year%8" if office == "senador" else "auto"
                changed = True
        else:
            db.add(ElectionLimit(
                election_year=year,
                election_type=election_type,
                office=office,
                max_reps=max_reps,
                source=("rule:year%8" if office == "senador" else "auto"),
            ))
            changed = True

    if changed:
        db.commit()
        rows = db.query(ElectionLimit).filter(
            ElectionLimit.election_year == year,
            ElectionLimit.election_type == election_type,
        ).all()
        by_office = {r.office: r for r in rows}

    return {k: int(v.max_reps) for k, v in by_office.items()}

@app.get("/elections/{year}/limits")
def election_limits(year: int, db: Session = Depends(get_db)):
    limits = get_or_create_election_limits(db, year)
    return {"year": int(year), "type": "geral", "limits": limits}
@app.get("/health")
def health():
    return {"status": "ok"}


@admin_router.get("/vote-audit")
def admin_vote_audit(
    request: Request,
    decision_id: int | None = None,
    user_id: int | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    # admin_router já está protegido por Depends(require_admin)
    limit = max(1, min(limit, 200))

    where = []
    params = {"limit": limit}
    if decision_id is not None:
        where.append("decision_id = :d")
        params["d"] = decision_id
    if user_id is not None:
        where.append("user_id = :u")
        params["u"] = user_id

    sql = "SELECT id, decision_id, user_id, choice, action, ip, user_agent, created_at FROM vote_audit"
    if where:
        sql += " WHERE " + " AND ".join(where)

@admin_router.get("/users")
def admin_users(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    rows = (
        db.query(User)
        .order_by(User.id.desc())
        .limit(limit)
        .all()
    )
    return {"items": [{"id": u.id, "email": u.email, "is_active": getattr(u, "is_active", True)} for u in rows]}


app.include_router(admin_router)
class CreateDecisionIn(BaseModel):
    title: str
    source: str | None = None
    external_id: str | None = None
    url: str | None = None

class RegisterIn(BaseModel):
    email: str
    password: str
    display_name: str | None = None
    instagram: str | None = None
    facebook: str | None = None

class LoginIn(BaseModel):
    email: str
    password: str

class VoteIn(BaseModel):
    decision_id: int
    choice: str  # concordo | discordo

class RepIn(BaseModel):
    politician_id: int
    role: str          # presidente|governador|senador|dep_federal|dep_estadual
    election_id: int   # ano (ex: 2026)

class RepQuery(BaseModel):
    include_history: bool = False
    election_id: int | None = None
@app.get("/wallet/balance")
def wallet_balance(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    bal = db.query(func.coalesce(func.sum(WalletTx.amount), 0)).filter(WalletTx.user_id == user_id).scalar() or 0
    return {"balance": int(bal)}

@app.get("/wallet/transactions")
def wallet_transactions(user_id: int = Depends(get_current_user_id), limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    txs = (
        db.query(WalletTx)
        .filter(WalletTx.user_id == user_id)
        .order_by(WalletTx.id.desc())
        .limit(limit)
        .all()
    )
    return [
        {"id": t.id, "amount": t.amount, "kind": t.kind, "decision_id": t.decision_id, "created_at": str(t.created_at)}
        for t in txs
    ]

@app.get("/me")
def me(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u or not u.is_active:
        raise HTTPException(status_code=401, detail="token inválido")
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "instagram": u.instagram, "facebook": u.facebook, "is_verified": bool(getattr(u,"is_verified",False))}



def require_verified_user(user_id: int, db: Session):
    u = db.query(User).filter_by(id=user_id).first()
    if not u:
        raise HTTPException(status_code=401, detail="usuário inválido")
    if not getattr(u, "is_verified", False):
        raise HTTPException(status_code=403, detail="conta não verificada")
    return u

def _role_limit(db: Session, election_id: int, role: str) -> int:
    row = db.execute(
        text("select max_reps from election_role_limits where election_id=:e and role=:r"),
        {"e": election_id, "r": role},
    ).fetchone()
    return int(row[0]) if row else 1

def _politician_active(db: Session, politician_id: int) -> bool:
    row = db.execute(
        text("select mandate_active from politicians where id=:p"),
        {"p": politician_id},
    ).fetchone()
    return bool(row[0]) if row else False


def _attach_decision_stats(db: Session, items: list[dict]):
    for it in items:
        did = it.get("id") or (it.get("decision") or {}).get("id")
        if not did:
            continue
        citizen = _count_citizen(db, int(did))
        official = _count_official(db, int(did))
        it["citizen"] = citizen
        it["official"] = official
        it["has_official_votes"] = bool((official or {}).get("total", 0) > 0)


@app.get("/me/votes")
def my_votes(page:int=1,page_size:int=20,user_id:int=Depends(get_current_user_id),db:Session=Depends(get_db)):
    page=max(1,page); page_size=max(1,min(page_size,200))
    q=(db.query(CitizenVote,Decision).join(Decision,Decision.id==CitizenVote.decision_id)
       .filter(CitizenVote.voter_id==str(user_id)).order_by(CitizenVote.id.desc()))
    total=q.count()
    rows=q.offset((page-1)*page_size).limit(page_size).all()
    items=[{"decision":{"id":d.id,"title":d.title},"my_choice":v.choice,"citizen":_count_citizen(db,d.id)} for v,d in rows]
    return {"page":page,"page_size":page_size,"total":total,"items":items}
@app.get("/decisions/latest")
@app.get("/latest/decisions")
def decisions_latest(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    rows = db.query(Decision).order_by(Decision.id.desc()).limit(limit).all()
    items = []
    for dec in rows:
        items.append({
            "id": dec.id,
            "title": dec.title,
            "occurred_at": getattr(dec, "occurred_at", None),
            "source": getattr(dec, "source", None),
            "external_id": getattr(dec, "external_id", None),
            "url": getattr(dec, "url", None),
            "has_official_votes": getattr(dec, "has_official_votes", False),
        })
    return {"items": items}


# ===== Public snapshots (download) =====
def _snap_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "public_snapshots"))
@app.get("/public/snapshots")
@app.head("/public/snapshots", include_in_schema=False)
def public_snapshots_head(limit: int = 50):
    return public_snapshots(limit)

def public_snapshots(limit: int = 50):
    limit=max(1,min(limit,200)); d=_snap_dir()
    if not os.path.isdir(d): return {"total":0,"items":[]}
    files=[f for f in os.listdir(d) if f.endswith((".json",".txt",".csv"))]; files.sort(reverse=True)
    items=[]
    for f in files[:limit]:
        p=os.path.join(d,f)
        if not os.path.isfile(p): continue
        try: items.append({"name":f,"bytes":int(os.stat(p).st_size)})
        except Exception: items.append({"name":f,"bytes":None})
    from fastapi.responses import JSONResponse
    return JSONResponse({"total":len(files),"items":items}, headers={"Cache-Control":"public, max-age=60"})


@app.get("/public/manifest")
def public_manifest(limit: int = 50):
    import hashlib
    limit=max(1,min(limit,200)); d=_snap_dir()
    if not os.path.isdir(d): return {"total":0,"items":[]}
    files=[f for f in os.listdir(d) if f.endswith((".json",".txt",".csv"))]; files.sort(reverse=True)
    items=[]
    for f in files[:limit]:
        pth=os.path.join(d,f)
        if not os.path.isfile(pth): continue
        h=hashlib.sha256()
        with open(pth,"rb") as fp:
            for ch in iter(lambda: fp.read(1024*1024), b""): h.update(ch)
        items.append({"name":f,"bytes":int(os.stat(pth).st_size),"sha256":h.hexdigest()})
    return {"total":len(files),"items":items}
@app.get("/public/snapshots/{name}")
@app.head("/public/snapshots/{name}", include_in_schema=False)
def public_snapshot_get_head(name: str):
    return public_snapshot_get(name)

def public_snapshot_get(name: str):
    from fastapi.responses import FileResponse
    if "/" in name or "\\" in name or ".." in name: raise HTTPException(status_code=400, detail="nome inválido")
    if not name.endswith((".json",".txt",".csv")): raise HTTPException(status_code=404, detail="snapshot não encontrado")
    d=_snap_dir(); p=os.path.abspath(os.path.join(d,name))
    if not p.startswith(d+os.sep) or not os.path.isfile(p): raise HTTPException(status_code=404, detail="snapshot não encontrado")
    ext=name.rsplit(".",1)[1]; mt={"json":"application/json","txt":"text/plain; charset=utf-8","csv":"text/csv; charset=utf-8"}.get(ext,"application/octet-stream")
    headers={"Cache-Control":"public, max-age=31536000, immutable","X-Content-Type-Options":"nosniff"}
    import hashlib
    h=hashlib.sha256(open(p,"rb").read()).hexdigest()
    headers["X-Checksum-SHA256"]=h
    headers["ETag"]="\""+h+"\""
    return FileResponse(p, media_type=mt, filename=name, headers=headers)

@app.get("/decisions/{decision_id}")
def get_decision(decision_id:int, include_stats:bool=True, db:Session=Depends(get_db)):
    d=db.query(Decision).filter(Decision.id==decision_id).first()
    if not d: raise HTTPException(status_code=404, detail="decisão não encontrada")
    iso=lambda dt: None if dt is None else getattr(dt,"isoformat",lambda: str(dt))()
    item={"id":d.id,"title":d.title,"occurred_at":iso(d.occurred_at),"source":d.source,"external_id":d.external_id,"url":d.url,"has_official_votes":bool(d.has_official_votes),"archived":bool(d.archived),"created_at":iso(d.created_at)}
    if include_stats: _attach_decision_stats(db,[item])
    return item



@app.get("/decisions/{decision_id}/my-vote")
def my_vote(decision_id: int, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    v = (
        db.query(CitizenVote)
        .filter(CitizenVote.decision_id == decision_id, CitizenVote.voter_id == str(user_id))
        .first()
    )
    if not v:
        return {"decision_id": decision_id, "user_id": user_id, "choice": None}

    return {
        "decision_id": decision_id,
        "user_id": user_id,
        "choice": v.choice,
        "updated_at": str(getattr(v, "updated_at", "")),
        "created_at": str(getattr(v, "created_at", "")),
    }
@app.get("/decisions/{decision_id}/rep-vote")
def decision_rep_vote(decision_id: int, election_id: int | None = None, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    dec = db.query(Decision).filter_by(id=decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="decisão não encontrada")

    e = int(election_id or os.getenv("ELECTION_YEAR_DEFAULT","0") or "0")
    if e <= 0:
        raise HTTPException(status_code=409, detail="ELECTION_YEAR_DEFAULT não configurado")

    source = (getattr(dec, "source", None) or "").strip().lower()
    role = "dep_federal" if source == "camara" else ("senador" if source == "senado" else None)
    if not role:
        raise HTTPException(status_code=409, detail="decisão com source desconhecido (não dá pra validar cargo)")

    row = db.execute(text(
        "SELECT cr.politician_id, ov.choice "
        "FROM citizen_reps cr "
        "LEFT JOIN official_votes ov "
        "  ON ov.decision_id = :d AND ov.politician_id = cr.politician_id "
        "WHERE cr.user_id = :u "
        "  AND cr.role = :r "
        "  AND cr.election_id = :e "
        "  AND cr.ended_at IS NULL "
        "ORDER BY cr.created_at DESC, cr.id DESC "
        "LIMIT 1"
    ), {"d": decision_id, "u": user_id, "r": role, "e": e}).first()

    if not row:
        return {"decision_id": decision_id, "election_id": e, "rep": {"politician_id": None, "status": "sem_representante", "official_choice": None}}

    rep_pid, rep_choice = row[0], row[1]
    status = "votou" if rep_choice else "ausente"
    return {"decision_id": decision_id, "election_id": e, "rep": {"politician_id": int(rep_pid), "status": status, "official_choice": rep_choice}}



@app.get("/politicians/{politician_id}/base-score")
def politician_base_score(politician_id: int, election_id: int | None = None, db: Session = Depends(get_db)):
    e = int(election_id or os.getenv("ELECTION_YEAR_DEFAULT","0") or "0")
    if e <= 0: raise HTTPException(status_code=409, detail="ELECTION_YEAR_DEFAULT não configurado")
    sql = "SELECT COUNT(*)::int AS total_votes, SUM(CASE WHEN ov.choice='Sim' AND cv.choice='concordo' THEN 1 WHEN ov.choice='Não' AND cv.choice='discordo' THEN 1 ELSE 0 END)::int AS aligned, SUM(CASE WHEN ov.choice IN ('Sim','Não') AND NOT((ov.choice='Sim' AND cv.choice='concordo') OR (ov.choice='Não' AND cv.choice='discordo')) THEN 1 ELSE 0 END)::int AS divergent, SUM(CASE WHEN ov.choice IS NULL THEN 1 ELSE 0 END)::int AS absent, SUM(CASE WHEN ov.choice IN ('Abstenção','Obstrução') THEN 1 ELSE 0 END)::int AS neutral FROM citizen_reps cr JOIN citizen_votes cv ON cv.voter_id = cr.user_id::text JOIN decisions d ON d.id=cv.decision_id LEFT JOIN official_votes ov ON ov.decision_id=cv.decision_id AND ov.politician_id=cr.politician_id WHERE cr.politician_id=:p AND cr.election_id=:e AND cr.ended_at IS NULL AND d.has_official_votes=true"
    row = db.execute(text(sql), {"p": int(politician_id), "e": int(e)}).mappings().first() or {}
    total=int(row.get("total_votes") or 0); aligned=int(row.get("aligned") or 0); divergent=int(row.get("divergent") or 0); absent=int(row.get("absent") or 0); neutral=int(row.get("neutral") or 0)
    score = aligned - divergent - absent
    pct = (lambda x: (round((x*100.0)/total,2) if total else 0.0))
    return {"politician_id": int(politician_id), "election_id": int(e), "total_votes": total, "aligned": aligned, "divergent": divergent, "absent": absent, "neutral": neutral, "score": score, "aligned_pct": pct(aligned), "divergent_pct": pct(divergent), "absent_pct": pct(absent)}


@app.get("/politicians/{politician_id}/official-absence")
def politician_official_absence(politician_id:int, db:Session=Depends(get_db)):
    sql="SELECT COUNT(*)::int AS total, SUM(CASE WHEN ov.id IS NULL THEN 1 ELSE 0 END)::int AS absent FROM decisions d LEFT JOIN official_votes ov ON ov.decision_id=d.id AND ov.politician_id=:p WHERE d.has_official_votes=true"
    row=db.execute(text(sql),{"p":int(politician_id)}).mappings().first() or {}
    total=int(row.get("total") or 0); absent=int(row.get("absent") or 0); present=total-absent
    pct=(round((absent*100.0)/total,2) if total else 0.0)
    return {"politician_id":int(politician_id),"total":total,"present":present,"absent":absent,"absent_pct":pct}


@app.get("/rankings/official-absence")
def ranking_official_absence(limit:int=50, min_present:int=10, source:str|None=None, db:Session=Depends(get_db)):
    limit=max(1,min(limit,200))
    total=db.execute(text("SELECT COUNT(*)::int FROM decisions WHERE has_official_votes=true")).scalar() or 0
    if total==0: return {"total_decisions":0,"items":[]}
    where=""; params={"limit":limit,"min_present":max(0,min_present)}
    if source: where=" WHERE p.source=:src"; params["src"]=source
    sql=("SELECT p.id AS politician_id, p.name, p.source, "
         "COALESCE(COUNT(DISTINCT CASE WHEN d.id IS NOT NULL THEN ov.decision_id END),0)::int AS present, "
         "(:total - COALESCE(COUNT(DISTINCT CASE WHEN d.id IS NOT NULL THEN ov.decision_id END),0))::int AS absent "
         "FROM politicians p "
         "LEFT JOIN official_votes ov ON ov.politician_id=p.id "
         "LEFT JOIN decisions d ON d.id=ov.decision_id AND d.has_official_votes=true "
         + where + " GROUP BY p.id,p.name,p.source HAVING COALESCE(COUNT(DISTINCT CASE WHEN d.id IS NOT NULL THEN ov.decision_id END),0) >= :min_present "
         "ORDER BY absent DESC, p.id ASC LIMIT :limit")
    params["total"]=int(total)
    rows=db.execute(text(sql),params).mappings().all()
    items=[]
    for r in rows:
        absent=int(r["absent"]); present=int(r["present"])
        pct=round((absent*100.0)/total,2) if total else 0.0
        items.append({"politician_id":int(r["politician_id"]),"name":r["name"],"source":r["source"],"total":int(total),"present":present,"absent":absent,"absent_pct":pct})
    items.sort(key=lambda x:(-x["absent_pct"],-x["absent"],x["politician_id"]))
    return {"total_decisions":int(total),"items":items}

@app.get("/decisions/{decision_id}/official-votes")
def decision_official_votes(decision_id: int, page: int = 1, page_size: int = 50, choice: str | None = None, db: Session = Depends(get_db)):
    page = max(1, page); page_size = max(1, min(page_size, 200))
    q = (db.query(OfficialVote, Politician)
         .join(Politician, Politician.id == OfficialVote.politician_id)
         .filter(OfficialVote.decision_id == decision_id))
    if choice is not None:
        q = q.filter(OfficialVote.choice == choice)
    total = q.count()
    rows = (q.order_by(Politician.name.asc(), Politician.id.asc())
              .offset((page - 1) * page_size)
              .limit(page_size)
              .all())
    items = []
    for v, pol in rows:
        items.append({
            "id": v.id,
            "choice": v.choice,
            "politician": {
                "id": pol.id,
                "name": pol.name,
                "role": pol.role,
                "scope": pol.scope,
                "uf": pol.uf,
                "source": pol.source,
                "external_id": pol.external_id,
            },
        })
    return {"decision_id": decision_id, "page": page, "page_size": page_size, "total": total, "items": items}


@app.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()

    ig = (payload.instagram or "").strip()
    fb = (payload.facebook or "").strip()
    if (not ig) and (not fb):
        raise HTTPException(status_code=400, detail="informe instagram ou facebook")
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="email já cadastrado")
    u = User(email=email, password_hash=hash_password(payload.password), display_name=payload.display_name, instagram=(ig or None), facebook=(fb or None), is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "instagram": u.instagram, "facebook": u.facebook, "is_verified": bool(getattr(u,"is_verified",False))}

@app.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    u = db.query(User).filter(User.email == email).first()
    if (not u) or (not u.is_active):
        raise HTTPException(status_code=401, detail="credenciais inválidas")
    if not verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=401, detail="credenciais inválidas")
    return {"access_token": create_access_token(u.id), "token_type": "bearer", "user": {"id": u.id, "email": u.email, "display_name": u.display_name, "instagram": getattr(u,"instagram",None), "facebook": getattr(u,"facebook",None), "is_verified": bool(getattr(u,"is_verified",False))}}


@app.post("/auth/verify/request")
def auth_verify_request(email: str, db: Session = Depends(get_db)):
    email=(email or "").strip().lower()
    u=db.query(User).filter(User.email==email).first()
    if not u: return {"status":"ok"}  # não vaza se existe
    if getattr(u,"is_verified",False): return {"status":"ok","already_verified":True}
    env2=(os.getenv("ENV","local") or "local").lower()
    dev_no_smtp=(env2!="prod") and (not (os.getenv("SMTP_HOST") or "").strip())
    now=datetime.now(timezone.utc)
    last=getattr(u,"verify_code_sent_at",None)
    if (not dev_no_smtp) and last and ((now-last) < timedelta(seconds=60)):
        return {"status":"ok","sent":True}
    code=_new_verify_code()
    u.verify_code_hash=_verify_code_hash(email,code)
    u.verify_code_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15)
    u.verify_code_sent_at=datetime.now(timezone.utc)
    db.commit()
    sent=_smtp_send(email,"Unebrasil - Código de verificação",
                   f"Seu código: {code}\n\nEle expira em 15 minutos.\nSe não achar, verifique o spam.")
    if sent: return {"status":"ok","sent":True}
    env=(os.getenv("ENV","local") or "local").lower()
    if env=="prod":
        raise HTTPException(status_code=500, detail="falha ao enviar email")
    if not (os.getenv("SMTP_HOST") or "").strip():
        return {"status":"ok","sent":False,"dev_code":code}
    raise HTTPException(status_code=500, detail="falha ao enviar email")

@app.post("/auth/verify/confirm")
def auth_verify_confirm(email: str, code: str, db: Session = Depends(get_db)):
    email=(email or "").strip().lower(); code=(code or "").strip()
    u=db.query(User).filter(User.email==email).first()
    if not u: raise HTTPException(status_code=400, detail="código inválido")
    exp=getattr(u,"verify_code_expires_at",None)
    if (not exp) or (exp < datetime.now(timezone.utc)):
        raise HTTPException(status_code=400, detail="código expirado")
    if _verify_code_hash(email,code)!=getattr(u,"verify_code_hash",None):
        raise HTTPException(status_code=400, detail="código inválido")
    u.is_verified=True; u.verified_at=datetime.now(timezone.utc)
    u.verify_code_hash=None; u.verify_code_expires_at=None; u.verify_code_sent_at=None
    db.commit()
    return {"status":"ok","verified":True}




# ===== SSE broker (simples) =====
_subscribers: Dict[int, Set[asyncio.Queue]] = {}

async def _publish(decision_id: int, payload: dict):
    qs = _subscribers.get(decision_id, set())
    if not qs:
        return
    msg = json.dumps(payload, ensure_ascii=False)
    dead = []
    for q in qs:
        try:
            q.put_nowait(msg)
        except Exception:
            dead.append(q)
    for q in dead:
        qs.discard(q)
async def _publish_safe(decision_id: int, payload: dict):
    try:
        await _publish(decision_id, payload)
    except Exception as e:
        print(f"[publish] decision_id={decision_id} err={e}")

def _sse_format(data: str) -> str:
    return f"data: {data}\n\n"

@app.get("/decisions/{decision_id}/stream")
async def decision_stream(decision_id: int, user_id: int = Depends(get_current_user_id)):
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.setdefault(decision_id, set()).add(q)

    async def gen():
        try:
            # ping inicial
            yield _sse_format(json.dumps({"type": "hello", "decision_id": decision_id}, ensure_ascii=False))
            while True:
                data = await q.get()
                yield _sse_format(data)
        finally:
            _subscribers.get(decision_id, set()).discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream")

@app.post("/decisions", dependencies=[Depends(require_admin)])
def create_decision(payload: CreateDecisionIn, db: Session = Depends(get_db)):
    # 1) se já existe (source, external_id), atualiza ao invés de inserir de novo
    existing = None
    if payload.source and payload.external_id:
        existing = (
            db.query(Decision)
            .filter_by(source=payload.source, external_id=payload.external_id)
            .first()
        )

    if existing:
        existing.title = payload.title
        existing.url = payload.url
        db.commit()
        db.refresh(existing)
        return {"id": existing.id, "title": existing.title, "status": "updated"}

    # 2) senão, cria novo
    d = Decision(
        title=payload.title,
        source=payload.source,
        external_id=payload.external_id,
        url=payload.url,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id, "title": d.title, "status": "created"}



@app.get("/decisions")
def list_decisions(page:int=1,page_size:int=20,q:str|None=None,source:str|None=None,has_official_votes:bool|None=None,archived:bool|None=False,include_stats:bool=False,sort:str="recent",db:Session=Depends(get_db)):
    page=max(1,page); page_size=max(1,min(page_size,200))
    qry=db.query(Decision)
    if archived is not None: qry=qry.filter(Decision.archived==archived)
    if source: qry=qry.filter(Decision.source==source)
    if has_official_votes is not None: qry=qry.filter(Decision.has_official_votes==has_official_votes)
    if q: qry=qry.filter(Decision.title.ilike(f"%{q.strip()}%"))
    total=qry.count(); sort = sort if sort in ("recent","priority") else "recent"
    sort_dt=func.coalesce(Decision.occurred_at, Decision.created_at)
    if sort=="priority": qry=qry.order_by(sort_dt.desc(), Decision.has_official_votes.desc(), Decision.created_at.desc(), Decision.id.desc())
    else: qry=qry.order_by(sort_dt.desc(), Decision.created_at.desc(), Decision.id.desc())
    rows=qry.offset((page-1)*page_size).limit(page_size).all()
    iso=lambda dt: None if dt is None else getattr(dt,"isoformat",lambda: str(dt))()
    items=[{"id":r.id,"title":r.title,"occurred_at":iso(r.occurred_at),"source":r.source,"external_id":r.external_id,"url":r.url,"has_official_votes":bool(r.has_official_votes),"archived":bool(r.archived),"created_at":iso(r.created_at)} for r in rows]
    if include_stats and items: _attach_decision_stats(db, items)
    return {"page":page,"page_size":page_size,"total":total,"items":items}

def _audit_vote(db: Session, decision_id: int, user_id: int, choice: str, action: str, request: Request | None = None):
    ip = None
    ua = None
    if request is not None:
        ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip() or (request.client.host if request.client else None)
        ua = request.headers.get("user-agent")

    db.execute(
        text("INSERT INTO vote_audit (decision_id, user_id, choice, action, ip, user_agent) VALUES (:d, :u, :c, :a, :ip, :ua)"),
        {"d": decision_id, "u": user_id, "c": choice, "a": action, "ip": ip, "ua": ua},
    )


@app.get("/me/representantes")
def me_representantes(
    include_history: bool = False,
    election_id: int | None = None,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    where = ["user_id = :u"]
    params = {"u": user_id}
    if not include_history:
        where.append("ended_at IS NULL")
    if election_id is not None:
        where.append("election_id = :e")
        params["e"] = int(election_id)

    sql = """
    SELECT id, user_id, politician_id, role, election_id, created_at, ended_at
    FROM citizen_reps
    WHERE """ + " AND ".join(where) + """
    ORDER BY election_id DESC, role ASC, created_at DESC, id DESC
    """
    rows = db.execute(text(sql), params).mappings().all()
    return {"items": [dict(r) for r in rows]}

@app.post("/me/representantes")
def me_representantes_add(
    payload: RepIn,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    require_verified_user(user_id, db)
    role = (payload.role or "").strip()
    if role not in ("presidente", "governador", "senador", "dep_federal", "dep_estadual"):
        raise HTTPException(status_code=400, detail="role inválido")

    election_id = int(payload.election_id)
    limits = get_or_create_election_limits(db, election_id)
    max_allowed = int(limits.get(role, 0))
    if max_allowed <= 0:
        raise HTTPException(status_code=400, detail="sem limite configurado para este cargo/eleição")

    active_count = db.execute(text(
        "SELECT count(*) FROM citizen_reps WHERE user_id=:u AND role=:r AND election_id=:e AND ended_at IS NULL"
    ), {"u": user_id, "r": role, "e": election_id}).scalar() or 0

    already = db.execute(text(
        "SELECT id FROM citizen_reps WHERE user_id=:u AND role=:r AND election_id=:e AND politician_id=:p AND ended_at IS NULL LIMIT 1"
    ), {"u": user_id, "r": role, "e": election_id, "p": int(payload.politician_id)}).first()
    if already:
        return {"status": "ok", "action": "noop"}

    if active_count >= max_allowed:
        db.execute(text(
            "UPDATE citizen_reps SET ended_at=now() "
            "WHERE id IN (SELECT id FROM citizen_reps WHERE user_id=:u AND role=:r AND election_id=:e AND ended_at IS NULL "
            "ORDER BY created_at ASC, id ASC LIMIT 1)"
        ), {"u": user_id, "r": role, "e": election_id})

    db.execute(text(
        "INSERT INTO citizen_reps (user_id, politician_id, role, election_id) VALUES (:u,:p,:r,:e)"
    ), {"u": user_id, "p": int(payload.politician_id), "r": role, "e": election_id})

    db.commit()
    return {"status": "ok", "action": "set", "role": role, "election_id": election_id}

@app.delete("/me/representantes")
def me_representantes_remove(
    role: str,
    election_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    require_verified_user(user_id, db)
    role = (role or "").strip()
    election_id = int(election_id)
    res = db.execute(text(
        "UPDATE citizen_reps SET ended_at=now() "
        "WHERE user_id=:u AND role=:r AND election_id=:e AND ended_at IS NULL"
    ), {"u": user_id, "r": role, "e": election_id})
    db.commit()
    return {"status": "ok", "updated": int(getattr(res, "rowcount", 0) or 0)}
@app.post("/vote")
async def vote(payload: VoteIn, request: Request, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    require_verified_user(user_id, db)
    if payload.choice not in ("concordo", "discordo"):
        raise HTTPException(status_code=400, detail="choice deve ser 'concordo' ou 'discordo'")

    dec = db.query(Decision).filter_by(id=payload.decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="decisão não encontrada")

    u = db.query(User).filter_by(id=user_id).first()
    if not u or not getattr(u, "is_verified", False):
        raise HTTPException(status_code=403, detail="conta não verificada")

    election_id = int(os.getenv("ELECTION_YEAR_DEFAULT","0") or "0") or 0
    if election_id <= 0:
        raise HTTPException(status_code=409, detail="ELECTION_YEAR_DEFAULT não configurado")

    source = (dec.source or "").strip().lower()
    required_role = "dep_federal" if source == "camara" else ("senador" if source == "senado" else None)
    if not required_role:
        raise HTTPException(status_code=409, detail="decisão com source desconhecido (não dá pra validar cargo)")
    rep_ok = db.execute(text("SELECT 1 FROM official_votes WHERE decision_id=:d AND politician_id IN (SELECT politician_id FROM citizen_reps WHERE user_id=:u AND role=:r AND election_id=:e AND ended_at IS NULL) LIMIT 1"), {"d": payload.decision_id, "u": user_id, "r": required_role, "e": election_id}).first()
    if not rep_ok:
        raise HTTPException(status_code=403, detail="voto permitido apenas para decisões do(s) seu(s) representante(s)")
    # sem cooldown: voto único por decisão, pode mudar quando quiser
    existing = db.query(CitizenVote).filter_by(decision_id=payload.decision_id, voter_id=str(user_id)).first()
    if existing:
        # idempotente: mesmo voto -> noop
        if existing.choice == payload.choice:
            counts = _count_citizen(db, payload.decision_id)
            asyncio.create_task(_publish_safe(payload.decision_id, dict(
                type='citizen_vote', status='ok', action='noop',
                decision_id=payload.decision_id, choice=payload.choice,
                user_id=user_id, counts=counts,
            )))
            _audit_vote(db, payload.decision_id, user_id, payload.choice, 'noop', request)
            db.commit()
            return dict(status='ok', action='noop', decision_id=payload.decision_id,
                        choice=payload.choice, user_id=user_id, counts=counts)

        # cooldown (evita spam de troca de voto)
        # só aplica quando for TROCAR (noop passa direto)
        cooldown = int(os.getenv("VOTE_COOLDOWN_SEC", "60") or "60")
        if cooldown > 0:
            now = datetime.now(timezone.utc)
            last_eff = getattr(existing, "last_changed_at", None)
            ca = getattr(existing, "created_at", None)
            ua = getattr(existing, "updated_at", None)
            # ignora somente o "lixo" de insert (quando last_changed_at ficou igual ao create e ainda nao houve update real)
            if last_eff is not None and ca is not None and ua is not None:
                if last_eff == ca and ua == ca:
                    last_eff = None
            if last_eff is not None:
                if last_eff.tzinfo is None:
                    last_eff = last_eff.replace(tzinfo=timezone.utc)
                delta = (now - last_eff).total_seconds()
                if delta < cooldown:
                    raise HTTPException(status_code=429, detail=f"aguarde {int(cooldown-delta)}s")

        existing.choice = payload.choice

        existing.last_changed_at = datetime.now(timezone.utc)

        already_rewarded = (
            db.query(WalletTx)
            .filter_by(user_id=user_id, decision_id=payload.decision_id, kind="vote_reward")
            .first()
        )
        if not already_rewarded:
            db.add(WalletTx(user_id=user_id, amount=10, kind="vote_reward", decision_id=payload.decision_id))


        counts = _count_citizen(db, payload.decision_id)
        asyncio.create_task(_publish_safe(payload.decision_id, {
            "type": "citizen_vote",
            "status": "ok",
            "action": "updated",
            "decision_id": payload.decision_id,
            "choice": payload.choice,
            "user_id": user_id,
            "counts": counts,
        }))
        _audit_vote(db, payload.decision_id, user_id, payload.choice, "updated", request)
        db.commit()
        return {"status": "ok", "action": "updated", "decision_id": payload.decision_id, "choice": payload.choice, "user_id": user_id, "counts": counts}

    try:
        v = CitizenVote(decision_id=payload.decision_id, voter_id=str(user_id), choice=payload.choice, last_changed_at=datetime.now(timezone.utc))
        db.add(v)
        db.flush()
        db.execute(text("UPDATE citizen_votes SET last_changed_at=NULL WHERE id=:id"), {"id": v.id})
        db.add(WalletTx(user_id=user_id, amount=10, kind="vote_reward", decision_id=payload.decision_id))

        counts = _count_citizen(db, payload.decision_id)
        asyncio.create_task(_publish_safe(payload.decision_id, {
            "type": "citizen_vote",
            "status": "ok",
            "action": "created",
            "decision_id": payload.decision_id,
            "choice": payload.choice,
            "user_id": user_id,
            "counts": counts,
        }))
        _audit_vote(db, payload.decision_id, user_id, payload.choice, "created", request)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="conflito ao salvar voto")
        return {"status": "ok", "action": "created", "decision_id": payload.decision_id, "choice": payload.choice, "user_id": user_id, "counts": counts}

    except IntegrityError:
        db.rollback()

        existing2 = db.query(CitizenVote).filter_by(decision_id=payload.decision_id, voter_id=str(user_id)).first()
        if not existing2:
            raise HTTPException(status_code=409, detail="conflito ao salvar voto (IntegrityError)")
        if existing2:
            existing2.choice = payload.choice

            already_rewarded2 = (
                db.query(WalletTx)
                .filter_by(user_id=user_id, decision_id=payload.decision_id, kind="vote_reward")
                .first()
            )
            if not already_rewarded2:
                db.add(WalletTx(user_id=user_id, amount=10, kind="vote_reward", decision_id=payload.decision_id))

            try:
                db.commit()
            except IntegrityError:
                db.rollback()

        counts = _count_citizen(db, payload.decision_id)
        return {"status": "ok", "action": "updated", "decision_id": payload.decision_id, "choice": payload.choice, "user_id": user_id, "counts": counts}

def _count_citizen(db: Session, decision_id: int):
    total = db.query(func.count(CitizenVote.id)).filter(CitizenVote.decision_id == decision_id).scalar() or 0
    concordo = db.query(func.count(CitizenVote.id)).filter(
        CitizenVote.decision_id == decision_id,
        CitizenVote.choice == "concordo"
    ).scalar() or 0
    discordo = db.query(func.count(CitizenVote.id)).filter(
        CitizenVote.decision_id == decision_id,
        CitizenVote.choice == "discordo"
    ).scalar() or 0
    return {"total": total, "concordo": concordo, "discordo": discordo}

def _count_official(db: Session, decision_id: int):
    total = db.query(func.count(OfficialVote.id)).filter(OfficialVote.decision_id == decision_id).scalar() or 0
    sim = db.query(func.count(OfficialVote.id)).filter(
        OfficialVote.decision_id == decision_id,
        OfficialVote.choice == "Sim"
    ).scalar() or 0
    nao = db.query(func.count(OfficialVote.id)).filter(
        OfficialVote.decision_id == decision_id,
        OfficialVote.choice == "Não"
    ).scalar() or 0
    abst = db.query(func.count(OfficialVote.id)).filter(
        OfficialVote.decision_id == decision_id,
        OfficialVote.choice == "Abstenção"
    ).scalar() or 0
    obst = db.query(func.count(OfficialVote.id)).filter(
        OfficialVote.decision_id == decision_id,
        OfficialVote.choice == "Obstrução"
    ).scalar() or 0
    return {"total": total, "sim": sim, "nao": nao, "abstencao": abst, "obstrucao": obst}

@app.get("/decisions/{decision_id}/summary")
def decision_summary(decision_id: int, db: Session = Depends(get_db)):
    dec = db.query(Decision).filter_by(id=decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="decisão não encontrada")
    official = _count_official(db, decision_id)
    citizen = _count_citizen(db, decision_id)

    return {
        "decision": {
            "id": dec.id,
            "title": dec.title,
            "source": getattr(dec, "source", None),
            "external_id": getattr(dec, "external_id", None),
            "url": getattr(dec, "url", None),
            "has_official_votes": (official["total"] > 0),
        },
        "official": official,
        "citizen": citizen,
    }

@app.get("/decisions/{decision_id}/live")
async def decision_live(decision_id: int, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    # garante que a decisão existe
    dec = db.query(Decision).filter_by(id=decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="decisão não encontrada")

    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(decision_id, set()).add(q)

    async def gen():
        try:
            # 1) manda um snapshot inicial (útil pra UI já abrir com números)
            official = _count_official(db, decision_id)
            citizen = _count_citizen(db, decision_id)
            payload = {
                "type": "snapshot",
                "ts": int(time.time()),
                "decision": {
                    "id": dec.id,
                    "title": dec.title,
                    "source": getattr(dec, "source", None),
                    "external_id": getattr(dec, "external_id", None),
                    "url": getattr(dec, "url", None),
                    "has_official_votes": (official["total"] > 0),
                },
                "official": official,
                "citizen": citizen,
            }
            yield _sse_format(json.dumps(payload, ensure_ascii=False))

            # 2) depois só repassa eventos publicados (sem polling)
            while True:
                msg = await q.get()
                yield _sse_format(msg)
        finally:
            _subscribers.get(decision_id, set()).discard(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


from sqlalchemy import desc


@app.get("/rank/users")
@app.get("/ranking/users")
def ranking_users(page: int = 1, page_size: int = 50, limit: int | None = None, db: Session = Depends(get_db)):
    if limit is not None: page_size = limit
    page = max(1, page); page_size = max(1, min(page_size, 200))

    total = db.query(User.id).filter(User.is_active == True).count()  # noqa: E712

    rows = (
        db.query(
            User.id, User.email, User.display_name, User.instagram, User.facebook,
            func.coalesce(func.sum(WalletTx.amount), 0).label("balance"),
        )
        .outerjoin(WalletTx, WalletTx.user_id == User.id)
        .filter(User.is_active == True)  # noqa: E712
        .group_by(User.id, User.email, User.display_name, User.instagram, User.facebook)
        .order_by(func.coalesce(func.sum(WalletTx.amount), 0).desc(), User.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    start_rank = (page - 1) * page_size
    items = [{"rank": start_rank + i + 1, "user": {"id": r.id, "email": r.email, "display_name": r.display_name, "instagram": getattr(r,"instagram",None), "facebook": getattr(r,"facebook",None)}, "balance": int(r.balance or 0)} for i, r in enumerate(rows)]
    return {"page": page, "page_size": page_size, "total": total, "items": items}
@app.get("/rank/decisions")
@app.get("/ranking/decisions")
def ranking_decisions(page: int = 1, page_size: int = 50, limit: int | None = None, db: Session = Depends(get_db)):
    if limit is not None: page_size = limit
    page = max(1, page); page_size = max(1, min(page_size, 200))

    total = db.query(Decision.id).filter(Decision.archived == False).count()  # noqa: E712

    rows = (
        db.query(
            Decision.id.label("id"),
            Decision.title.label("title"),
            func.count(CitizenVote.id).label("total"),
            func.coalesce(func.sum(case((CitizenVote.choice == "concordo", 1), else_=0)), 0).label("concordo"),
            func.coalesce(func.sum(case((CitizenVote.choice == "discordo", 1), else_=0)), 0).label("discordo"),
        )
        .outerjoin(CitizenVote, CitizenVote.decision_id == Decision.id)
        .filter(Decision.archived == False)  # noqa: E712
        .group_by(Decision.id, Decision.title)
        .order_by(func.count(CitizenVote.id).desc(), Decision.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    start_rank = (page - 1) * page_size
    out = []
    for i, r in enumerate(rows):
        t = int(r.total or 0); c = int(r.concordo or 0); d = int(r.discordo or 0)
        out.append({
            "rank": start_rank + i + 1,
            "decision": {"id": r.id, "title": r.title},
            "citizen": {
                "total": t, "concordo": c, "discordo": d,
                "pct_concordo": round((c * 100.0 / t), 2) if t else 0.0,
                "pct_discordo": round((d * 100.0 / t), 2) if t else 0.0,
                "score": c - d,
            }
        })

    return {"page": page, "page_size": page_size, "total": total, "items": out}


@app.get("/politicians")
def list_politicians(page:int=1, page_size:int=50, q:str|None=None, source:str|None=None, role:str|None=None, uf:str|None=None, db:Session=Depends(get_db)):
    page=max(1,page); page_size=max(1,min(page_size,200))
    qry=db.query(Politician)
    if source: qry=qry.filter(Politician.source==source)
    if role: qry=qry.filter(Politician.role==role)
    if uf: qry=qry.filter(Politician.uf==uf)
    if q: qry=qry.filter(Politician.name.ilike(f"%{q}%"))
    total=qry.count()
    rows=qry.order_by(Politician.name.asc(), Politician.id.asc()).offset((page-1)*page_size).limit(page_size).all()
    items=[{"id":p.id,"name":p.name,"role":p.role,"scope":p.scope,"uf":p.uf,"source":p.source,"external_id":p.external_id} for p in rows]
    return {"page":page,"page_size":page_size,"total":total,"items":items}
