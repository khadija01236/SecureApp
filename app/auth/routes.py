import io
import logging
import re
import random
import string
from datetime import datetime, timezone

import pyotp
import qrcode
import qrcode.image.svg
from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from app import db, limiter, mail
from app.auth import auth_bp
from app.models import LoginEvent, User
from flask_mail import Message

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email)) and len(email) <= 120


def _log_event(event_type, user=None, details=None):
    """Enregistre un événement d'authentification en base et dans les logs JSON."""
    ip = request.remote_addr
    ua = request.user_agent.string[:256]
    event = LoginEvent(
        user_id=user.id if user else None,
        event_type=event_type,
        ip_address=ip,
        user_agent=ua,
        details=details,
    )
    db.session.add(event)
    db.session.commit()

    logger.info(
        "auth_event",
        extra={
            "event_type": event_type,
            "user": user.username if user else "anonymous",
            "ip": ip,
            "srcip": ip,
            "user_agent": ua,
            "details": details,
        },
    )


def _generate_email_otp():
    return "".join(random.choices(string.digits, k=6))


def _send_email_otp(user):
    from datetime import timedelta

    code = _generate_email_otp()
    user.email_otp_code = code
    user.email_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.session.commit()

    msg = Message(
        subject="Votre code de vérification",
        recipients=[user.email],
        body=(
            f"Bonjour {user.username},\n\n"
            f"Votre code de vérification est : {code}\n\n"
            "Ce code est valable 10 minutes.\n\n"
            "Si vous n'avez pas demandé ce code, ignorez ce message."
        ),
    )
    mail.send(msg)
    return code


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Tous les champs sont obligatoires.", "danger")
            return render_template("auth/register.html")

        if not _is_valid_email(email):
            flash("Adresse email invalide.", "danger")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà pris.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé.", "danger")
            return render_template("auth/register.html")

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        _log_event(LoginEvent.REGISTER, user=user)
        flash("Compte créé avec succès ! Connecte-toi.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ---------------------------------------------------------------------------
# Login — étape 1 (mot de passe)
# ---------------------------------------------------------------------------


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if not user or not user.check_password(password):
            if user:
                user.increment_failed_attempts()
                db.session.commit()
                if user.is_locked():
                    _log_event(LoginEvent.ACCOUNT_LOCKED, user=user)
                    flash("Compte verrouillé pendant 15 minutes suite à trop de tentatives.", "danger")
                    return render_template("auth/login.html")
            _log_event(LoginEvent.LOGIN_FAIL, user=user, details=f"identifier={identifier}")
            flash("Identifiant ou mot de passe incorrect.", "danger")
            return render_template("auth/login.html")

        if user.is_locked():
            flash("Compte temporairement verrouillé. Réessaie dans quelques minutes.", "danger")
            return render_template("auth/login.html")

        if user.has_mfa_enabled():
            # Stocker l'état dans la session, pas de login complet encore
            session["mfa_user_id"] = user.id
            session["mfa_remember"] = remember

            # Si Email OTP est activé, envoyer le code
            if user.email_otp_enabled:
                _send_email_otp(user)

            return redirect(url_for("auth.mfa_verify"))

        # Pas de MFA : login direct
        user.reset_failed_attempts()
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        db.session.commit()

        login_user(user, remember=remember)
        _log_event(LoginEvent.LOGIN_SUCCESS, user=user)
        flash(f"Bienvenue, {user.username} !", "success")
        next_page = request.args.get("next")
        return redirect(next_page or url_for("main.dashboard"))

    return render_template("auth/login.html")


# ---------------------------------------------------------------------------
# MFA — vérification
# ---------------------------------------------------------------------------


@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def mfa_verify():
    user_id = session.get("mfa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("mfa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        method = request.form.get("method", "totp")

        verified = False

        if method == "totp" and user.totp_enabled and user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            verified = totp.verify(code, valid_window=1)

        elif method == "email" and user.email_otp_enabled:
            expires_at = user.email_otp_expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if (
                user.email_otp_code
                and expires_at
                and datetime.now(timezone.utc) < expires_at
                and user.email_otp_code == code
            ):
                verified = True
                user.email_otp_code = None
                user.email_otp_expires_at = None

        elif method == "backup":
            verified = user.use_backup_code(code)

        if verified:
            user.reset_failed_attempts()
            user.last_login_at = datetime.now(timezone.utc)
            user.last_login_ip = request.remote_addr
            db.session.commit()

            remember = session.pop("mfa_remember", False)
            session.pop("mfa_user_id", None)

            login_user(user, remember=remember)
            _log_event(LoginEvent.MFA_SUCCESS, user=user, details=f"method={method}")
            _log_event(LoginEvent.LOGIN_SUCCESS, user=user)
            flash(f"Bienvenue, {user.username} !", "success")
            return redirect(url_for("main.dashboard"))
        else:
            user.increment_failed_attempts()
            db.session.commit()
            _log_event(LoginEvent.MFA_FAIL, user=user, details=f"method={method}")
            flash("Code invalide ou expiré.", "danger")

    return render_template(
        "auth/mfa_verify.html",
        totp_enabled=user.totp_enabled,
        email_otp_enabled=user.email_otp_enabled,
        email=user.email,
    )


@auth_bp.route("/mfa/email/send", methods=["POST"])
def mfa_email_send():
    user_id = session.get("mfa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if user and user.email_otp_enabled:
        _send_email_otp(user)
        flash("Un nouveau code a été envoyé à ton adresse email.", "info")

    return redirect(url_for("auth.mfa_verify"))


# ---------------------------------------------------------------------------
# MFA Setup — TOTP
# ---------------------------------------------------------------------------


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("totp_temp_secret")

        if not secret:
            flash("Session expirée. Recommence.", "danger")
            return redirect(url_for("auth.mfa_setup"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            session.pop("totp_temp_secret", None)
            db.session.commit()
            flash("Authentification TOTP activée avec succès !", "success")
            return redirect(url_for("main.profile"))
        else:
            flash("Code incorrect. Vérifie ton application d'authentification.", "danger")

    # Générer un nouveau secret temporaire
    secret = pyotp.random_base32()
    session["totp_temp_secret"] = secret

    issuer = current_app.config.get("MFA_ISSUER", "FlaskMFA")
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email, issuer_name=issuer
    )

    # Générer le QR code en SVG (base64)
    import base64
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template(
        "auth/mfa_setup.html",
        secret=secret,
        qr_b64=qr_b64,
    )


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@auth_bp.route("/logout")
@login_required
def logout():
    _log_event(LoginEvent.LOGOUT, user=current_user)
    logout_user()
    flash("Tu es déconnecté.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Mot de passe oublié — étape 1 (saisie email)
# ---------------------------------------------------------------------------


def _get_serializer():
    from itsdangerous import URLSafeTimedSerializer
    from flask import current_app
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not _is_valid_email(email):
            flash("Adresse email invalide.", "danger")
            return render_template("auth/forgot_password.html")

        user = User.query.filter_by(email=email).first()

        # Réponse identique que l'email existe ou non (anti-énumération)
        if user:
            token = _get_serializer().dumps(email, salt="password-reset")
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            msg = Message(
                subject="Réinitialisation de votre mot de passe",
                recipients=[user.email],
                body=(
                    f"Bonjour {user.username},\n\n"
                    f"Cliquez sur le lien suivant pour réinitialiser votre mot de passe :\n"
                    f"{reset_url}\n\n"
                    "Ce lien est valable 1 heure.\n\n"
                    "Si vous n'avez pas demandé cette réinitialisation, ignorez ce message."
                ),
            )
            mail.send(msg)
            logger.info(
                "auth_event",
                extra={
                    "event_type": "password_reset_request",
                    "user": user.username,
                    "ip": request.remote_addr,
                    "srcip": request.remote_addr,
                    "user_agent": request.user_agent.string[:256],
                    "details": None,
                },
            )

        flash(
            "Si cette adresse email est associée à un compte, un lien de réinitialisation a été envoyé.",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


# ---------------------------------------------------------------------------
# Réinitialisation du mot de passe — étape 2 (nouveau mot de passe)
# ---------------------------------------------------------------------------


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    from itsdangerous import BadSignature, SignatureExpired

    try:
        email = _get_serializer().loads(token, salt="password-reset", max_age=3600)
    except SignatureExpired:
        flash("Ce lien a expiré. Demande un nouveau lien de réinitialisation.", "danger")
        return redirect(url_for("auth.forgot_password"))
    except BadSignature:
        flash("Lien invalide.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Lien invalide.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.", "danger")
            return render_template("auth/reset_password.html", token=token)

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template("auth/reset_password.html", token=token)

        user.set_password(password)
        user.reset_failed_attempts()
        db.session.commit()

        _log_event(LoginEvent.PASSWORD_RESET, user=user)
        flash("Mot de passe réinitialisé avec succès. Tu peux te connecter.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", token=token)
