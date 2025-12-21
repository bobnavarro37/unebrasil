import os
import sys
import requests
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Decision, Politician, OfficialVote

BASE = "https://dadosabertos.camara.leg.br/api/v2"

def _set_if_column(obj, **values):
    cols = set(obj.__table__.columns.keys())
    for k, v in values.items():
        if k in cols and v is not None:
            setattr(obj, k, v)

def upsert_politician(db: Session, dep: dict):
    """
    dep é o objeto deputado_ vindo da API da Câmara.
    Garante que existe um Politician e retorna ele.
    """
    ext_id = str(dep.get("id") or "").strip()
    if not ext_id:
        return None

    p = db.query(Politician).filter_by(source="camara", external_id=ext_id).first()
    created = False
    if not p:
        p = Politician(source="camara", external_id=ext_id)
        created = True

    # atualiza campos comuns (só seta se a coluna existir no seu model)
    _set_if_column(
        p,
        name=dep.get("nome"),
        full_name=dep.get("nome"),
        party=dep.get("siglaPartido"),
        uf=dep.get("siglaUf"),
        photo_url=dep.get("urlFoto"),
        email=dep.get("email"),
        legislatura_id=dep.get("idLegislatura"),
        external_uri=dep.get("uri"),
        role="deputado",
        scope="federal",
    )

    if created:
        db.add(p)

    db.commit()
    db.refresh(p)
    return p



def fetch_votes(votacao_id: str):
    # Esse endpoint costuma aceitar sem pagina/itens (evita 400)
    url = f"{BASE}/votacoes/{votacao_id}/votos"
    r = requests.get(url, headers={"Accept": "application/json"}, timeout=60)
    if r.status_code != 200:
        return []
    j = r.json() or {}
    return j.get("dados", []) or []

def iso_date(days_back: int):
    d = datetime.now(timezone.utc) - timedelta(days=days_back)
    return d.date().isoformat()

def get_all(url, params=None):
    params = dict(params or {})
    params.setdefault("ordem", "DESC")
    params.setdefault("itens", 100)
    page = 1
    out = []
    while True:
        params["pagina"] = page
        r = requests.get(url, params=params, timeout=60, headers={"Accept": "application/json"})
        r.raise_for_status()
        j = r.json()
    r = requests.get(url, params=params, timeout=60, headers={"Accept": "application/json"})
    r.raise_for_status()
    j = r.json() or {}
    dados = j.get("dados", []) or []
    return dados

def get_all_pages(url, params=None, max_pages=50):
    """Paginação por pagina/itens (serve para /votacoes)."""
    params = dict(params or {})
    params.setdefault("ordem", "DESC")
    params.setdefault("itens", 100)

    out = []
    for page in range(1, max_pages + 1):
        params["pagina"] = page
        r = requests.get(url, params=params, timeout=60, headers={"Accept": "application/json"})
        r.raise_for_status()
        j = r.json() or {}
        dados = j.get("dados", []) or []
        if not dados:
            break
        out.extend(dados)

        # se não tiver "next" nos links, acabou
        links = {l.get("rel"): l.get("href") for l in (j.get("links", []) or [])}
        if "next" not in links:
            break

    return out

def _safe_set(model_cls, data: dict):
    """
    Filtra chaves que existem na tabela do SQLAlchemy.
    Assim o sync não quebra se o schema tiver nomes diferentes.
    """
    cols = set(model_cls.__table__.columns.keys())
    return {k: v for k, v in data.items() if k in cols}

def _extract_deputado_fields(ov: dict):
    # dependendo do payload, pode vir "deputado_" ou "deputado"
    dep = ov.get("deputado_") or ov.get("deputado") or {}
    return {
        "politician_external_id": str(dep.get("id") or ""),
        "politician_name": dep.get("nome") or "",
        "party": dep.get("siglaPartido") or "",
        "state": dep.get("siglaUf") or "",
    }

def upsert_decision(db: Session, v: dict) -> Decision:
    ext_id = str(v.get("id"))
    url = v.get("uri")
    title = v.get("descricao") or f"Votação Câmara {ext_id}"
    occurred_at = None
    try:
        # v["data"] vem tipo "2025-12-11"
        if v.get("data"):
            occurred_at = datetime.fromisoformat(v["data"]).replace(tzinfo=timezone.utc)
    except Exception:
        occurred_at = None

    dec = db.query(Decision).filter_by(source="camara", external_id=ext_id).first()
    if not dec:
        dec = Decision(
            title=title,
            occurred_at=occurred_at,
            source="camara",
            external_id=ext_id,
            url=url,
            archived=False,
        )
        db.add(dec)
        db.commit()
        db.refresh(dec)
    else:
        # atualiza campos básicos
        dec.title = title
        dec.url = url
        if occurred_at:
            dec.occurred_at = occurred_at
        db.commit()

    return dec

def sync_official_votes_for_decision(db: Session, dec: Decision, votacao_id: str):
    votos = fetch_votes(votacao_id)

    dec.has_official_votes = bool(votos)
    db.commit()

    if not votos:
        return 0, 0  # (inseridos, atualizados)

    # limpa votos anteriores dessa decisão
    db.query(OfficialVote).filter(OfficialVote.decision_id == dec.id).delete()
    db.commit()

    inserted = 0
    skipped = 0

    VALID = {"Sim", "Não", "Abstenção", "Obstrução"}

    for ov in votos:
        dep = ov.get("deputado_")
        if not dep or not dep.get("id"):
            skipped += 1
            continue

        choice = (ov.get("tipoVoto") or "").strip()
        if choice not in VALID:
            skipped += 1
            continue

        pol = upsert_politician(db, dep)
        if not pol:
            skipped += 1
            continue

        vote = OfficialVote(
            decision_id=dec.id,
            politician_id=pol.id,
            choice=choice
        )
        db.add(vote)
        inserted += 1

    db.commit()
    return inserted, skipped

def main():
    days = int(os.getenv("DAYS_BACK", "30"))
    max_pages = int(os.getenv("MAX_PAGES", "10"))  # 10 páginas * 100 = 1000 votações (ajuste se quiser)

    print(f"camara_sync: baixando votações (últimos {days} dias)...", flush=True)
    url = f"{BASE}/votacoes"

    # /votacoes aceita pagina/itens/ordem.
    votacoes = get_all_pages(
        url,
        params={"dataInicio": iso_date(days), "ordem": "DESC", "itens": 100},
        max_pages=max_pages,
    )

    print(f"camara_sync: votações recebidas = {len(votacoes)}", flush=True)
    if not votacoes:
        return

    db: Session = SessionLocal()

    processed = 0
    inserted_votes_total = 0

    try:
        # processa as mais recentes primeiro
        for v in votacoes:
            processed += 1
            vid = str(v.get("id"))
            if not vid:
                continue

            dec = upsert_decision(db, v)
            inserted, _ = sync_official_votes_for_decision(db, dec, vid)
            inserted_votes_total += inserted

            if processed % 25 == 0:
                print(f"camara_sync: processadas={processed} votos_inseridos={inserted_votes_total}", flush=True)

        print(f"camara_sync: finalizado. processadas={processed} votos_inseridos={inserted_votes_total}", flush=True)

    except Exception as e:
        print("camara_sync error:", e, file=sys.stderr, flush=True)
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()



def get_all_no_params(url):
    out = []
    next_url = url
    while next_url:
        r = requests.get(next_url, timeout=60, headers={"Accept": "application/json"})
        r.raise_for_status()
        j = r.json()
        out.extend(j.get("dados", []) or [])
        links = {l.get("rel"): l.get("href") for l in (j.get("links") or [])}
        next_url = links.get("next")
    return out

    def upsert_politician(db: Session, dep: dict):
       ext_id = str(dep.get("id") or "")
    if not ext_id:
        return None

    p = db.query(Politician).filter_by(
        source="camara",
        external_id=ext_id
    ).first()

    if not p:
        p = Politician(
            source="camara",
            external_id=ext_id,
            name=dep.get("nome"),
            party=dep.get("siglaPartido"),
            uf=dep.get("siglaUf"),
            photo_url=dep.get("urlFoto"),
        )
        db.add(p)
        db.flush()  # garante p.id

    return p

def upsert_decision(db: Session, vot):
    ext_id = str(vot.get("id"))
    d = db.query(Decision).filter_by(source="camara", external_id=ext_id).first()
    if not d:
        d = Decision(
            title=vot.get("descricao") or f"Votação Câmara {ext_id}",
            source="camara",
            external_id=ext_id,
            url=vot.get("uri"),
        )
        db.add(d)
        db.flush()
    return d

def map_choice(raw):
    s = (raw or "").lower()
    if s in ("sim", "s"):
        return "concordo"
    if s in ("não", "nao", "n"):
        return "discordo"
    if "absten" in s:
        return "abstencao"
    return "ausente"

def main():
    db: Session = SessionLocal()
    try:
        deps = get_all(f"{BASE}/deputados")
        dep_by_id = {}
        for dep in deps:
            p = upsert_politician(db, dep)
            dep_by_id[str(dep["id"])] = p
        db.commit()

        votacoes = get_all(
            f"{BASE}/votacoes",
            params={"dataInicio": iso_date(30), "dataFim": iso_date(0)}
        )[:50]

        for v in votacoes:
            decision = upsert_decision(db, v)
            db.commit()

            votos = fetch_votes(v['id'])

            for vt in votos:
                dep_id = str(vt.get("idDeputado")) if vt.get("idDeputado") else None
                if dep_id not in dep_by_id:
                    continue
                pol = dep_by_id[dep_id]
                choice = map_choice(vt.get("voto"))
                if not db.query(OfficialVote).filter_by(
                    decision_id=decision.id,
                    politician_id=pol.id
                ).first():
                    db.add(OfficialVote(
                        decision_id=decision.id,
                        politician_id=pol.id,
                        choice=choice
                    ))
            db.commit()

        print("camara_sync: ok", flush=True)

    except Exception as e:
        print("camara_sync error:", e, file=sys.stderr, flush=True)
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()
