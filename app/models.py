import json
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # MFA TOTP
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # MFA Email OTP
    email_otp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    email_otp_code = db.Column(db.String(8), nullable=True)
    email_otp_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Backup codes (stockés hashés, séparés par virgule)
    backup_codes_json = db.Column(db.Text, nullable=True)

    # Protection contre le brute force
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    # Métadonnées
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)

    login_events = db.relationship("LoginEvent", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def increment_failed_attempts(self):
        from datetime import timedelta

        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 10:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None

    def generate_backup_codes(self):
        """Génère 8 codes de récupération à usage unique."""
        codes = [secrets.token_hex(4).upper() for _ in range(8)]
        self.backup_codes_json = json.dumps(
            [generate_password_hash(c) for c in codes]
        )
        return codes

    def use_backup_code(self, code):
        """Vérifie et consomme un backup code. Retourne True si valide."""
        if not self.backup_codes_json:
            return False
        hashed_codes = json.loads(self.backup_codes_json)
        for i, hashed in enumerate(hashed_codes):
            if hashed and check_password_hash(hashed, code.upper()):
                hashed_codes[i] = None  # Invalider le code utilisé
                self.backup_codes_json = json.dumps(hashed_codes)
                return True
        return False

    def get_backup_codes_remaining(self):
        if not self.backup_codes_json:
            return 0
        return sum(1 for c in json.loads(self.backup_codes_json) if c is not None)

    def has_mfa_enabled(self):
        return self.totp_enabled or self.email_otp_enabled

    def __repr__(self):
        return f"<User {self.username}>"


class LoginEvent(db.Model):
    __tablename__ = "login_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(32), nullable=False)  # voir constantes ci-dessous
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    details = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Constantes pour event_type
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAIL = "login_fail"
    MFA_FAIL = "mfa_fail"
    MFA_SUCCESS = "mfa_success"
    ACCOUNT_LOCKED = "account_locked"
    REGISTER = "register"
    LOGOUT = "logout"
    PASSWORD_RESET = "password_reset"

    def __repr__(self):
        return f"<LoginEvent {self.event_type} user={self.user_id}>"
