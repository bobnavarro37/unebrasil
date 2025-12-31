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
from app.database import SessionLocal, engine, Base
from app.models import User, Decision, CitizenVote, OfficialVote, WalletTx
import time

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

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ===== JWT auth =====
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 24h
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET não definido (coloque no .env)")

def create_access_token(user_id: int) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
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
    sql += " ORDER BY id DESC LIMIT :limit"

    rows = db.execute(text(sql), params).mappings().all()
    return {"items": [dict(r) for r in rows]}


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

class LoginIn(BaseModel):
    email: str
    password: str

class VoteIn(BaseModel):
    decision_id: int
    choice: str  # concordo | discordo

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
    return {"id": u.id, "email": u.email, "display_name": u.display_name}


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
@app.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="email já cadastrado")
    u = User(email=email, password_hash=hash_password(payload.password), display_name=payload.display_name, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return {"id": u.id, "email": u.email, "display_name": u.display_name}

@app.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    u = db.query(User).filter(User.email == email).first()
    if (not u) or (not u.is_active):
        raise HTTPException(status_code=401, detail="credenciais inválidas")
    if not verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=401, detail="credenciais inválidas")
    return {"access_token": create_access_token(u.id), "token_type": "bearer", "user": {"id": u.id, "email": u.email, "display_name": u.display_name}}



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

@app.post("/decisions")
def create_decision(payload: CreateDecisionIn, db: Session = Depends(get_db)):
    # 1) se já existe (source, external_id), atualiza ao invés de inserir de novo
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


@app.post("/vote")
async def vote(payload: VoteIn, request: Request, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    if payload.choice not in ("concordo", "discordo"):
        raise HTTPException(status_code=400, detail="choice deve ser 'concordo' ou 'discordo'")

    dec = db.query(Decision).filter_by(id=payload.decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="decisão não encontrada")
    # sem cooldown: voto único por decisão, pode mudar quando quiser
    existing = db.query(CitizenVote).filter_by(decision_id=payload.decision_id, voter_id=str(user_id)).first()
    if existing:
        # idempotente: mesmo voto -> unchanged
        if existing.choice == payload.choice:
            counts = _count_citizen(db, payload.decision_id)
            asyncio.create_task(_publish_safe(payload.decision_id, dict(
                type='citizen_vote', status='ok', action='unchanged',
                decision_id=payload.decision_id, choice=payload.choice,
                user_id=user_id, counts=counts,
            )))
            _audit_vote(db, payload.decision_id, user_id, payload.choice, 'unchanged', request)
            db.commit()
            return dict(status='ok', action='unchanged', decision_id=payload.decision_id,
                        choice=payload.choice, user_id=user_id, counts=counts)

        # cooldown (evita spam de troca de voto)
        # só aplica quando for TROCAR (unchanged passa direto)
        cooldown = int(os.getenv("VOTE_COOLDOWN_SEC", "60") or "60")
        if cooldown > 0:
            now = datetime.datetime.now(datetime.timezone.utc)
            last = getattr(existing, 'last_changed_at', None) or existing.updated_at or existing.created_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=datetime.timezone.utc)
                delta = (now - last).total_seconds()
                if delta < cooldown:
                    raise HTTPException(status_code=429, detail=f"aguarde {int(cooldown-delta)}s")

        # troca real -> aplica cooldown e atualiza marcador

        existing.choice = payload.choice

        existing.last_changed_at = datetime.datetime.now(datetime.timezone.utc)

        already_rewarded = (
            db.query(WalletTx)
            .filter_by(user_id=user_id, decision_id=payload.decision_id, kind="vote_reward")
            .first()
        )
        if not already_rewarded:
            db.add(WalletTx(user_id=user_id, amount=10, kind="vote_reward", decision_id=payload.decision_id))

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="conflito ao salvar voto")

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
        v = CitizenVote(decision_id=payload.decision_id, voter_id=str(user_id), choice=payload.choice,
            last_changed_at=datetime.datetime.now(datetime.timezone.utc))
        db.add(v)
        db.add(WalletTx(user_id=user_id, amount=10, kind="vote_reward", decision_id=payload.decision_id))
        db.commit()

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
        db.commit()
        return {"status": "ok", "action": "created", "decision_id": payload.decision_id, "choice": payload.choice, "user_id": user_id, "counts": counts}

    except IntegrityError:
        db.rollback()

        existing2 = db.query(CitizenVote).filter_by(decision_id=payload.decision_id, voter_id=str(user_id)).first()
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
        return {"status": "updated", "decision_id": payload.decision_id, "choice": payload.choice, "user_id": user_id, "counts": counts}
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

@app.get("/decisions/latest")
def decisions_latest(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))

    decs = (
        db.query(Decision)
        .order_by(desc(Decision.id))
        .limit(limit)
        .all()
    )

    out = []
    for dec in decs:
        out.append({
            "decision": {
                "id": dec.id,
                "title": dec.title,
                "source": getattr(dec, "source", None),
                "external_id": getattr(dec, "external_id", None),
                "url": getattr(dec, "url", None),
                "has_official_votes": getattr(dec, "has_official_votes", False),
            },
            "official": _count_official(db, dec.id),
            "citizen": _count_citizen(db, dec.id),
        })
    return out


# ===== Ranking (C1) =====

@app.get("/ranking/users")
def ranking_users(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))

    rows = (
        db.query(
            User.id,
            User.email,
            User.display_name,
            func.coalesce(func.sum(WalletTx.amount), 0).label("balance"),
        )
        .outerjoin(WalletTx, WalletTx.user_id == User.id)
        .filter(User.is_active == True)  # noqa: E712
        .group_by(User.id)
        .order_by(func.coalesce(func.sum(WalletTx.amount), 0).desc(), User.id.asc())
        .limit(limit)
        .all()
    )

    return [
        {
            "user": {"id": r.id, "email": r.email, "display_name": r.display_name},
            "balance": int(r.balance or 0),
        }
        for r in rows
    ]


@app.get("/ranking/decisions")
def ranking_decisions(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))

    rows = (
        db.query(
            Decision.id.label("id"),
            Decision.title.label("title"),
            func.count(CitizenVote.id).label("total"),
            func.coalesce(func.sum(case((CitizenVote.choice == "concordo", 1), else_=0)), 0).label("concordo"),
            func.coalesce(func.sum(case((CitizenVote.choice == "discordo", 1), else_=0)), 0).label("discordo"),
        )
        .outerjoin(CitizenVote, CitizenVote.decision_id == Decision.id)
        .group_by(Decision.id, Decision.title)
        .order_by(func.count(CitizenVote.id).desc(), Decision.id.desc())
        .limit(limit)
        .all()
    )

    out = []
    for r in rows:
        total = int(r.total or 0)
        concordo = int(r.concordo or 0)
        discordo = int(r.discordo or 0)

        pct_concordo = round((concordo * 100.0 / total), 2) if total else 0.0
        pct_discordo = round((discordo * 100.0 / total), 2) if total else 0.0

        score = concordo - discordo

        out.append({
            "decision": {"id": r.id, "title": r.title},
            "citizen": {
                "total": total,
                "concordo": concordo,
                "discordo": discordo,
                "pct_concordo": pct_concordo,
                "pct_discordo": pct_discordo,
                "score": score,
            }
        })

    return out
