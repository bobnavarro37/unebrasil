import os
from tests.test_vote_cooldown import token

def auth_headers():
    return {"Authorization": f"Bearer {token()}"}

import os
import uuid
def test_create_decision_then_vote(client):
    # 1) cria uma decisão nova (source+external_id únicos)
    r = client.post(
        "/decisions",
            headers={"X-Admin-Token": os.environ.get("ADMIN_TOKEN","")},
        json={
            "source": "camara",
            "external_id": f"dec-test-{uuid.uuid4()}",
            "title": "Decisão de teste",
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "id" in data
    decision_id = data["id"]

    # 2) vota nela
    v = client.post(
        "/vote",
        headers=auth_headers(),
        json={"decision_id": decision_id, "choice": "concordo"},
    )
    assert v.status_code == 403, v.text
    assert 'detail' in v.json()
    assert 'representante' in v.json()['detail'].lower()

    # 3) saldo deve ser >= 10 (não depende de estado anterior por causa do rollback fixture)
    b = client.get("/wallet/balance", headers=auth_headers())
    assert b.status_code == 200, b.text
    bdata = b.json()
    assert bdata["balance"] >= 10
