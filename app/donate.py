import json
from app.database import SessionLocal
from fastapi import Request

import os
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

donate_router = APIRouter()

MP_ACCESS_TOKEN = (os.getenv("MP_ACCESS_TOKEN") or "").strip()
MP_DONATE_MIN = float(os.getenv("MP_DONATE_MIN","5") or "5")
MP_DONATE_MAX = float(os.getenv("MP_DONATE_MAX","500000") or "500000")

class DonateCreateIn(BaseModel):
    amount: float
    name: str | None = None
    email: str | None = None
    message: str | None = None


@donate_router.get("/donate/config")
def donate_config():
    return {"min": MP_DONATE_MIN, "max": MP_DONATE_MAX, "currency": "BRL", "title": "Doação Unebrasil"}


@donate_router.post("/donate/create")
def donate_create(payload: DonateCreateIn):
    if not MP_ACCESS_TOKEN:
        raise HTTPException(status_code=400, detail="MP_ACCESS_TOKEN não definido")
    amount = float(payload.amount)
    if amount < MP_DONATE_MIN:
        raise HTTPException(status_code=400, detail=f"amount mínimo é {MP_DONATE_MIN:g}")
    if amount > MP_DONATE_MAX:
        raise HTTPException(status_code=400, detail=f"amount máximo é {MP_DONATE_MAX:g}")
    if amount <= 0:
        raise HTTPException(status_code=400, detail="amount inválido")
    body = {
        "items": [{"title": "Doação Unebrasil", "quantity": 1, "unit_price": amount}],
        # "payer": (não enviar por privacidade),
        # "metadata": (não enviar por privacidade),
    }
    r = requests.post("https://api.mercadopago.com/checkout/preferences", headers={"Authorization": f"Bearer {MP_ACCESS_TOKEN}"}, json=body, timeout=15)
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail={"mp_status": r.status_code, "mp_body": r.text[:500]})
    d = r.json()
    return {"preference_id": d.get("id"), "init_point": d.get("init_point"), "sandbox_init_point": d.get("sandbox_init_point")}


