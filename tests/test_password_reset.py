"""Tests du flux de réinitialisation de mot de passe."""
from itsdangerous import URLSafeTimedSerializer

from app import db
from app.models import User


def _make_token(app, email):
    """Génère un token de reset valide signé avec la clé secrète de l'app de test."""
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="password-reset")


# ---------------------------------------------------------------------------
# Étape 1 — Demande de réinitialisation
# ---------------------------------------------------------------------------


class TestForgotPassword:
    def test_get(self, client):
        assert client.get("/auth/forgot-password").status_code == 200

    def test_known_email_shows_generic_message(self, client, user):
        resp = client.post(
            "/auth/forgot-password",
            data={"email": "test@example.com"},
            follow_redirects=True,
        )
        assert "lien de réinitialisation" in resp.data.decode()

    def test_unknown_email_shows_same_message(self, client):
        """Anti-énumération : même réponse que pour un email connu."""
        resp = client.post(
            "/auth/forgot-password",
            data={"email": "nobody@example.com"},
            follow_redirects=True,
        )
        assert "lien de réinitialisation" in resp.data.decode()

    def test_invalid_email_format(self, client):
        resp = client.post(
            "/auth/forgot-password",
            data={"email": "not-an-email"},
            follow_redirects=True,
        )
        assert "invalide" in resp.data.decode()


# ---------------------------------------------------------------------------
# Étape 2 — Nouveau mot de passe
# ---------------------------------------------------------------------------


class TestResetPassword:
    def test_get_valid_token(self, client, user, app):
        token = _make_token(app, "test@example.com")
        assert client.get(f"/auth/reset-password/{token}").status_code == 200

    def test_success(self, client, user, app):
        token = _make_token(app, "test@example.com")
        resp = client.post(
            f"/auth/reset-password/{token}",
            data={"password": "newpassword123", "confirm_password": "newpassword123"},
            follow_redirects=True,
        )
        assert "réinitialisé" in resp.data.decode()

    def test_password_actually_updated(self, client, user, app):
        token = _make_token(app, "test@example.com")
        client.post(
            f"/auth/reset-password/{token}",
            data={"password": "newpassword123", "confirm_password": "newpassword123"},
        )
        with app.app_context():
            u = User.query.get(user)
            assert u.check_password("newpassword123")
            assert not u.check_password("password123")

    def test_resets_lockout(self, client, user, app):
        """Le reset doit effacer le lockout éventuel."""
        from datetime import datetime, timedelta, timezone

        with app.app_context():
            u = User.query.get(user)
            u.failed_login_attempts = 10
            u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.session.commit()

        token = _make_token(app, "test@example.com")
        client.post(
            f"/auth/reset-password/{token}",
            data={"password": "newpassword123", "confirm_password": "newpassword123"},
        )
        with app.app_context():
            u = User.query.get(user)
            assert u.failed_login_attempts == 0
            assert not u.is_locked()

    def test_password_mismatch(self, client, user, app):
        token = _make_token(app, "test@example.com")
        resp = client.post(
            f"/auth/reset-password/{token}",
            data={"password": "newpassword123", "confirm_password": "different"},
            follow_redirects=True,
        )
        assert "correspondent pas" in resp.data.decode()

    def test_password_too_short(self, client, user, app):
        token = _make_token(app, "test@example.com")
        resp = client.post(
            f"/auth/reset-password/{token}",
            data={"password": "short", "confirm_password": "short"},
            follow_redirects=True,
        )
        assert "8 caractères" in resp.data.decode()

    def test_invalid_token(self, client):
        resp = client.get(
            "/auth/reset-password/invalid-token", follow_redirects=True
        )
        assert "invalide" in resp.data.decode()

    def test_wrong_salt_token(self, client, app):
        """Token signé avec un mauvais sel → invalide."""
        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        bad_token = s.dumps("test@example.com", salt="wrong-salt")
        resp = client.get(
            f"/auth/reset-password/{bad_token}", follow_redirects=True
        )
        assert "invalide" in resp.data.decode()
