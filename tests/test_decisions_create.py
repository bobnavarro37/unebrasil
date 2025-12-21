import uuid
def test_create_decision_then_vote(client):
    # 1) cria uma decisão nova (source+external_id únicos)
    r = client.post(
        "/decisions",
        json={
            "source": "test",
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
        headers={"Authorization": "Bearer user:1"},
        json={"decision_id": decision_id, "choice": "concordo"},
    )
    assert v.status_code == 200, v.text
    vdata = v.json()
    assert vdata["status"] == "ok"
    assert vdata["action"] == "created"
    assert vdata["decision_id"] == decision_id
    assert vdata["user_id"] == 1

    # 3) saldo deve ser >= 10 (não depende de estado anterior por causa do rollback fixture)
    b = client.get("/wallet/balance", headers={"Authorization": "Bearer user:1"})
    assert b.status_code == 200, b.text
    bdata = b.json()
    assert bdata["balance"] >= 10

