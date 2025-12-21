import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import app.main as main
from app.database import engine


@pytest.fixture()
def client():
    """
    Cada teste roda dentro de uma transação que é revertida (rollback) no final.
    Assim, os testes não sujam o banco e não dependem do estado anterior.
    """
    connection = engine.connect()
    transaction = connection.begin()

    # Cria uma sessão ligada a essa conexão/transaction
    test_session = main.SessionLocal(bind=connection)

    # Override do dependency get_db do FastAPI para usar nossa sessão de teste
    def override_get_db():
        try:
            yield test_session
        finally:
            pass

    main.app.dependency_overrides[main.get_db] = override_get_db

    with TestClient(main.app) as c:
        yield c

    # Cleanup
    main.app.dependency_overrides.clear()
    test_session.close()
    transaction.rollback()
    connection.close()
