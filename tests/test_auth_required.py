import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    return TestClient(app)


@pytest.mark.parametrize("path,method", [
    ("/wallet/balance", "GET"),
    ("/wallet/transactions", "GET"),
    ("/vote", "POST"),
])
def test_auth_required(client: TestClient, path: str, method: str):
    if method == "GET":
        r = client.get(path)
    else:
        r = client.post(path, json={"decision_id": 1003, "choice": "concordo"})

    assert r.status_code == 401, r.text
