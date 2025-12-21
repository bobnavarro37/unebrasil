import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    return TestClient(app)


def test_wallet_transactions_ok(client: TestClient):
    r = client.get(
        "/wallet/transactions",
        headers={"Authorization": "Bearer user:1"},
    )
    assert r.status_code == 200, r.text
    data = r.json()

    assert isinstance(data, list)

    # Se tiver transações, valida formato mínimo do primeiro item
    if data:
        tx = data[0]
        assert "id" in tx
        assert "amount" in tx and isinstance(tx["amount"], int)
        assert "kind" in tx and isinstance(tx["kind"], str)
        assert "decision_id" in tx  # pode ser None em outros kinds no futuro
        assert "created_at" in tx and isinstance(tx["created_at"], str)
