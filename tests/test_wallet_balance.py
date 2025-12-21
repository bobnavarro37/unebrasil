import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    return TestClient(app)


def test_wallet_balance_ok(client: TestClient):
    r = client.get(
        "/wallet/balance",
        headers={"Authorization": "Bearer user:1"},
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Checagens mínimas e estáveis (sem depender do valor exato do saldo)
    assert "balance" in data
    assert isinstance(data["balance"], int)
    assert data["balance"] >= 0
