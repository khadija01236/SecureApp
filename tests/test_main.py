"""Tests du dashboard et des routes de profil (MFA, backup codes)."""
import pyotp

from app import db
from app.models import User


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    def test_requires_auth(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_authenticated(self, logged_in_client):
        assert logged_in_client.get("/").status_code == 200


# ---------------------------------------------------------------------------
# Profil
# ---------------------------------------------------------------------------


class TestProfile:
    def test_requires_auth(self, client):
        resp = client.get("/profile")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_authenticated(self, logged_in_client):
        assert logged_in_client.get("/profile").status_code == 200


# ---------------------------------------------------------------------------
# Désactivation TOTP
# ---------------------------------------------------------------------------


class TestDisableTotp:
    def test_wrong_password(self, logged_in_client):
        resp = logged_in_client.post(
            "/profile/mfa/totp/disable",
            data={"password": "wrongpassword"},
            follow_redirects=True,
        )
        assert "incorrect" in resp.data.decode()

    def test_success(self, logged_in_client, user, app):
        u = db.session.get(User, user)
        u.totp_secret = pyotp.random_base32()
        u.totp_enabled = True
        db.session.commit()

        resp = logged_in_client.post(
            "/profile/mfa/totp/disable",
            data={"password": "password123"},
            follow_redirects=True,
        )
        assert "désactivée" in resp.data.decode()

        db.session.expire_all()
        u = db.session.get(User, user)
        assert not u.totp_enabled
        assert u.totp_secret is None


# ---------------------------------------------------------------------------
# Toggle Email OTP
# ---------------------------------------------------------------------------


class TestToggleEmailOtp:
    def test_wrong_password(self, logged_in_client):
        resp = logged_in_client.post(
            "/profile/mfa/email/toggle",
            data={"password": "wrongpassword"},
            follow_redirects=True,
        )
        assert "incorrect" in resp.data.decode()

    def test_enables(self, logged_in_client, user, app):
        logged_in_client.post(
            "/profile/mfa/email/toggle",
            data={"password": "password123"},
            follow_redirects=True,
        )
        with app.app_context():
            assert User.query.get(user).email_otp_enabled is True

    def test_toggle_twice_disables(self, logged_in_client, user, app):
        for _ in range(2):
            logged_in_client.post(
                "/profile/mfa/email/toggle",
                data={"password": "password123"},
                follow_redirects=True,
            )
        with app.app_context():
            assert User.query.get(user).email_otp_enabled is False


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------


class TestBackupCodes:
    def test_get_requires_auth(self, client):
        resp = client.get("/profile/backup-codes")
        assert resp.status_code == 302

    def test_generate_wrong_password(self, logged_in_client):
        resp = logged_in_client.post(
            "/profile/backup-codes",
            data={"password": "wrongpassword"},
            follow_redirects=True,
        )
        assert "incorrect" in resp.data.decode()

    def test_generate_success(self, logged_in_client, user, app):
        logged_in_client.post(
            "/profile/backup-codes",
            data={"password": "password123"},
            follow_redirects=True,
        )
        with app.app_context():
            assert User.query.get(user).get_backup_codes_remaining() == 8

    def test_generate_replaces_old_codes(self, logged_in_client, user, app):
        for _ in range(2):
            logged_in_client.post(
                "/profile/backup-codes",
                data={"password": "password123"},
                follow_redirects=True,
            )
        with app.app_context():
            assert User.query.get(user).get_backup_codes_remaining() == 8
