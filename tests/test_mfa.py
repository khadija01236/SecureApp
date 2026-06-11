"""Tests de vérification MFA (TOTP, email OTP, backup codes) et du setup TOTP."""
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app import db
from app.models import User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def totp_user(app):
    """Utilisateur avec TOTP activé. Retourne (user_id, secret)."""
    secret = pyotp.random_base32()
    u = User(username="mfauser", email="mfa@example.com")
    u.set_password("password123")
    u.totp_secret = secret
    u.totp_enabled = True
    db.session.add(u)
    db.session.commit()
    return u.id, secret


@pytest.fixture
def email_otp_user(app):
    """Utilisateur avec Email OTP activé. Retourne user_id."""
    u = User(username="emailmfa", email="emailmfa@example.com")
    u.set_password("password123")
    u.email_otp_enabled = True
    db.session.add(u)
    db.session.commit()
    return u.id


# ---------------------------------------------------------------------------
# Vérification MFA
# ---------------------------------------------------------------------------


class TestMFAVerify:
    def test_verify_redirects_without_session(self, client):
        resp = client.get("/auth/mfa/verify")
        assert resp.status_code == 302

    def test_totp_success(self, client, totp_user):
        user_id, secret = totp_user
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = user_id
            sess["mfa_remember"] = False

        resp = client.post(
            "/auth/mfa/verify",
            data={"code": pyotp.TOTP(secret).now(), "method": "totp"},
            follow_redirects=True,
        )
        assert "Bienvenue" in resp.data.decode()

    def test_totp_wrong_code(self, client, totp_user):
        user_id, _ = totp_user
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = user_id

        resp = client.post(
            "/auth/mfa/verify",
            data={"code": "000000", "method": "totp"},
            follow_redirects=True,
        )
        assert "invalide" in resp.data.decode()

    def test_totp_wrong_code_increments_counter(self, client, totp_user, app):
        user_id, _ = totp_user
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = user_id

        client.post(
            "/auth/mfa/verify",
            data={"code": "000000", "method": "totp"},
        )
        with app.app_context():
            assert db.session.get(User, user_id).failed_login_attempts == 1

    def test_email_otp_success(self, client, email_otp_user, app):
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = email_otp_user

        with app.app_context():
            u = db.session.get(User, email_otp_user)
            u.email_otp_code = "123456"
            u.email_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            db.session.commit()

        resp = client.post(
            "/auth/mfa/verify",
            data={"code": "123456", "method": "email"},
            follow_redirects=True,
        )
        assert "Bienvenue" in resp.data.decode()

    def test_email_otp_expired(self, client, email_otp_user, app):
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = email_otp_user

        with app.app_context():
            u = db.session.get(User, email_otp_user)
            u.email_otp_code = "123456"
            u.email_otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.session.commit()

        resp = client.post(
            "/auth/mfa/verify",
            data={"code": "123456", "method": "email"},
            follow_redirects=True,
        )
        assert "invalide" in resp.data.decode()

    def test_email_otp_consumed_after_use(self, client, email_otp_user, app):
        with client.session_transaction() as sess:
            sess["mfa_user_id"] = email_otp_user

        with app.app_context():
            u = db.session.get(User, email_otp_user)
            u.email_otp_code = "654321"
            u.email_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            db.session.commit()

        client.post(
            "/auth/mfa/verify",
            data={"code": "654321", "method": "email"},
            follow_redirects=True,
        )
        with app.app_context():
            u = db.session.get(User, email_otp_user)
            assert u.email_otp_code is None

    def test_backup_code_success(self, client, app):
        secret = pyotp.random_base32()
        with app.app_context():
            u = User(username="backupuser", email="backup@example.com")
            u.set_password("password123")
            u.totp_secret = secret
            u.totp_enabled = True
            codes = u.generate_backup_codes()
            db.session.add(u)
            db.session.commit()
            user_id = u.id

        with client.session_transaction() as sess:
            sess["mfa_user_id"] = user_id

        resp = client.post(
            "/auth/mfa/verify",
            data={"code": codes[0], "method": "backup"},
            follow_redirects=True,
        )
        assert "Bienvenue" in resp.data.decode()

    def test_backup_code_consumed_after_use(self, client, app):
        secret = pyotp.random_base32()
        with app.app_context():
            u = User(username="backupuser2", email="backup2@example.com")
            u.set_password("password123")
            u.totp_secret = secret
            u.totp_enabled = True
            codes = u.generate_backup_codes()
            db.session.add(u)
            db.session.commit()
            user_id = u.id

        with client.session_transaction() as sess:
            sess["mfa_user_id"] = user_id

        client.post(
            "/auth/mfa/verify",
            data={"code": codes[0], "method": "backup"},
            follow_redirects=True,
        )
        with app.app_context():
            assert db.session.get(User, user_id).get_backup_codes_remaining() == 7


# ---------------------------------------------------------------------------
# Setup TOTP
# ---------------------------------------------------------------------------


class TestMFASetup:
    def test_setup_get(self, logged_in_client):
        assert logged_in_client.get("/auth/mfa/setup").status_code == 200

    def test_setup_requires_auth(self, client):
        resp = client.get("/auth/mfa/setup")
        assert resp.status_code == 302

    def test_setup_success(self, logged_in_client, user, app):
        logged_in_client.get("/auth/mfa/setup")

        with logged_in_client.session_transaction() as sess:
            secret = sess.get("totp_temp_secret")

        assert secret is not None
        code = pyotp.TOTP(secret).now()
        resp = logged_in_client.post(
            "/auth/mfa/setup", data={"code": code}, follow_redirects=True
        )
        assert "activée" in resp.data.decode()

        with app.app_context():
            assert db.session.get(User, user).totp_enabled

    def test_setup_wrong_code(self, logged_in_client):
        logged_in_client.get("/auth/mfa/setup")
        resp = logged_in_client.post(
            "/auth/mfa/setup", data={"code": "000000"}, follow_redirects=True
        )
        assert "incorrect" in resp.data.decode()
