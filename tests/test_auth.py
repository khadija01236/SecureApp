"""Tests d'inscription, connexion, déconnexion et verrouillage de compte."""
from datetime import datetime, timedelta, timezone

from app import db
from app.models import User


# ---------------------------------------------------------------------------
# Inscription
# ---------------------------------------------------------------------------


class TestRegister:
    def test_get(self, client):
        assert client.get("/auth/register").status_code == 200

    def test_success(self, client):
        resp = client.post(
            "/auth/register",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "securepass1",
                "confirm_password": "securepass1",
            },
            follow_redirects=True,
        )
        assert "Compte créé" in resp.data.decode()

    def test_duplicate_username(self, client, user):
        resp = client.post(
            "/auth/register",
            data={
                "username": "testuser",
                "email": "other@example.com",
                "password": "securepass1",
                "confirm_password": "securepass1",
            },
            follow_redirects=True,
        )
        assert "déjà pris" in resp.data.decode()

    def test_duplicate_email(self, client, user):
        resp = client.post(
            "/auth/register",
            data={
                "username": "otherusername",
                "email": "test@example.com",
                "password": "securepass1",
                "confirm_password": "securepass1",
            },
            follow_redirects=True,
        )
        assert "déjà utilisé" in resp.data.decode()

    def test_invalid_email(self, client):
        resp = client.post(
            "/auth/register",
            data={
                "username": "newuser",
                "email": "not-an-email",
                "password": "securepass1",
                "confirm_password": "securepass1",
            },
            follow_redirects=True,
        )
        assert "invalide" in resp.data.decode()

    def test_password_too_short(self, client):
        resp = client.post(
            "/auth/register",
            data={
                "username": "newuser",
                "email": "new@example.com",
                "password": "short",
                "confirm_password": "short",
            },
            follow_redirects=True,
        )
        assert "8 caractères" in resp.data.decode()

    def test_password_mismatch(self, client):
        resp = client.post(
            "/auth/register",
            data={
                "username": "newuser",
                "email": "new@example.com",
                "password": "securepass1",
                "confirm_password": "different",
            },
            follow_redirects=True,
        )
        assert "correspondent pas" in resp.data.decode()

    def test_missing_fields(self, client):
        resp = client.post(
            "/auth/register",
            data={"username": "", "email": "", "password": "", "confirm_password": ""},
            follow_redirects=True,
        )
        assert "obligatoires" in resp.data.decode()


# ---------------------------------------------------------------------------
# Connexion
# ---------------------------------------------------------------------------


class TestLogin:
    def test_get(self, client):
        assert client.get("/auth/login").status_code == 200

    def test_success_by_username(self, client, user):
        resp = client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "password123"},
            follow_redirects=True,
        )
        assert "Bienvenue" in resp.data.decode()

    def test_success_by_email(self, client, user):
        resp = client.post(
            "/auth/login",
            data={"identifier": "test@example.com", "password": "password123"},
            follow_redirects=True,
        )
        assert "Bienvenue" in resp.data.decode()

    def test_wrong_password(self, client, user):
        resp = client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "wrongpassword"},
            follow_redirects=True,
        )
        assert "incorrect" in resp.data.decode()

    def test_unknown_user(self, client):
        resp = client.post(
            "/auth/login",
            data={"identifier": "nobody", "password": "password123"},
            follow_redirects=True,
        )
        assert "incorrect" in resp.data.decode()

    def test_failed_attempt_increments_counter(self, client, user, app):
        client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "wrong"},
        )
        with app.app_context():
            assert db.session.get(User, user).failed_login_attempts == 1

    def test_lockout_after_10_failures(self, client, user, app):
        for _ in range(10):
            client.post(
                "/auth/login",
                data={"identifier": "testuser", "password": "wrong"},
            )
        with app.app_context():
            assert db.session.get(User, user).is_locked()

    def test_locked_account_shows_message(self, client, user, app):
        with app.app_context():
            u = db.session.get(User, user)
            u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.session.commit()
        resp = client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "password123"},
            follow_redirects=True,
        )
        assert "verrouillé" in resp.data.decode()

    def test_success_resets_failed_attempts(self, client, user, app):
        client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "wrong"},
        )
        client.post(
            "/auth/login",
            data={"identifier": "testuser", "password": "password123"},
            follow_redirects=True,
        )
        with app.app_context():
            assert db.session.get(User, user).failed_login_attempts == 0


# ---------------------------------------------------------------------------
# Déconnexion
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout(self, logged_in_client):
        resp = logged_in_client.get("/auth/logout", follow_redirects=True)
        assert "déconnecté" in resp.data.decode()

    def test_logout_requires_auth(self, client):
        resp = client.get("/auth/logout")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]
