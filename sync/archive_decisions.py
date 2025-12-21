import json
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import case, func

from app.database import SessionLocal
from app.models import Decision, CitizenVote, OfficialVote, Politician

ARCHIVE_DAYS = 30

def utcnow():
    return datetime.now(timezone.utc)

def run():
    db: Session = SessionLocal()
    cutoff = utcnow() - timedelta(days=ARCHIVE_DAYS)

    decisions = (
        db.query(Decision)
        .filter(Decision.archived == False)  # noqa: E712
        .filter(Decision.created_at <= cutoff)
        .all()
    )

    for d in decisions:
        total = db.query(CitizenVote).filter_by(decision_id=d.id).count()
        concordo = db.query(CitizenVote).filter_by(decision_id=d.id, choice="concordo").count()
        discordo = db.query(CitizenVote).filter_by(decision_id=d.id, choice="discordo").count()

        # Ranking geral (não por eleitor individual): % de cidadãos que concordaram com o voto oficial do político
        rows = (
            db.query(
                Politician.id.label("politician_id"),
                Politician.name.label("name"),
                Politician.role.label("role"),
                Politician.scope.label("scope"),
                Politician.uf.label("uf"),
                Politician.city.label("city"),
                OfficialVote.choice.label("official_vote"),
                func.count(CitizenVote.id).label("total_compared"),
                func.sum(
                    case((CitizenVote.choice == OfficialVote.choice, 1), else_=0)
                ).label("matches"),
            )
            .join(OfficialVote, OfficialVote.politician_id == Politician.id)
            .join(CitizenVote, CitizenVote.decision_id == OfficialVote.decision_id)
            .filter(OfficialVote.decision_id == d.id)
            .filter(OfficialVote.choice.in_(("concordo", "discordo")))
            .group_by(Politician.id, OfficialVote.choice)
            .all()
        )

        politicians = []
        for r in rows:
            total_cmp = int(r.total_compared)
            matches = int(r.matches or 0)
            politicians.append({
                "politician_id": int(r.politician_id),
                "name": r.name,
                "role": r.role,
                "scope": r.scope,
                "uf": r.uf,
                "city": r.city,
                "official_vote": r.official_vote,
                "citizen_concordance": (matches / total_cmp) if total_cmp else 0.0,
                "total_compared": total_cmp
            })

        payload = {
            "decision_id": d.id,
            "title": d.title,
            "created_at": d.created_at.isoformat(),
            "archived_at": utcnow().isoformat(),
            "totals": {
                "citizens": {"total": total, "concordo": concordo, "discordo": discordo}
            },
            "politicians": politicians
        }

        with open(f"archives/decision_{d.id}.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))

        d.archived = True
        db.commit()

    db.close()

if __name__ == "__main__":
    run()
