import os
import pytest
import datetime
from fastapi.testclient import TestClient

# Importa o app FastAPI
from app.main import app


@pytest.fixture(scope="session")
def client():
    return TestClient(app)

class _FakeDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        # "agora" bem no futuro para nunca cair no rate-limit de 5s
        return datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)

def test_vote_create_then_update(client: TestClient):
    """
    Fluxo esperado:
    - 1º voto em uma decisão existente: created
    - 2º voto na mesma decisão (mesmo user): updated
    """
    decision_id = 1003  # usa uma decisão que sabemos que existe no seu banco
    import app.main as main
    main.datetime.datetime = _FakeDateTime

    # 1) voto inicial
    r1 = client.post(
        "/vote",
        headers={"Authorization": "Bearer user:1"},
        json={"decision_id": decision_id, "choice": "concordo"},
    )
    assert r1.status_code == 200, r1.text
    data1 = r1.json()
    assert data1["status"] == "ok"
    assert data1["action"] in ("created", "updated")  # pode já existir voto antigo
    assert data1["decision_id"] == decision_id
    assert data1["choice"] == "concordo"
    assert data1["user_id"] == 1
    assert "counts" in data1 and "total" in data1["counts"]
    # 2) update do voto
    r2 = client.post(
        "/vote",
        headers={"Authorization": "Bearer user:1"},
        json={"decision_id": decision_id, "choice": "discordo"},
    )
    assert r2.status_code == 200, r2.text
    data2 = r2.json()
    assert data2["status"] == "ok"
    assert data2["action"] == "updated"
    assert data2["decision_id"] == decision_id
    assert data2["choice"] == "discordo"
    assert data2["user_id"] == 1
    assert data2["counts"]["total"] == 1
    assert data2["counts"]["discordo"] == 1
