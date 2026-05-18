import pytest

from app import create_app, db as _db
from app.models import User


@pytest.fixture
def app():
    """App Flask configurée pour les tests : SQLite en mémoire, mail supprimé, rate limit désactivé."""
    test_app = create_app()
    test_app.config.update(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "MAIL_SUPPRESS_SEND": True,
            "RATELIMIT_ENABLED": False,
            "SECRET_KEY": "test-secret-key",
        }
    )
    with test_app.app_context():
        _db.create_all()
        yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app):
    """Crée un utilisateur de base et retourne son ID."""
    u = User(username="testuser", email="test@example.com")
    u.set_password("password123")
    _db.session.add(u)
    _db.session.commit()
    return u.id


@pytest.fixture
def logged_in_client(client, user):
    """Client avec session authentifiée (pas de MFA)."""
    client.post(
        "/auth/login",
        data={"identifier": "testuser", "password": "password123"},
        follow_redirects=True,
    )
    return client
