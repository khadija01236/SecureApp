import logging
import os

from dotenv import load_dotenv
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

# Indique à Flask de faire confiance aux headers X-Forwarded-* de Nginx
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Connecte-toi pour accéder à cette page."
login_manager.login_message_category = "warning"


def create_app(test_config=None):
    app = Flask(__name__)

    # Faire confiance au proxy Nginx (X-Real-IP, X-Forwarded-For, X-Forwarded-Proto)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # ── Configuration ─────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MFA_ISSUER"] = os.getenv("MFA_ISSUER", "SecureApp")

    if test_config:
        app.config.update(test_config)

    # Flask-Mail
    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "mailhog")
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 1025))
    app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "false").lower() == "true"
    app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", None)
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", None)
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "noreply@secureapp.local")

    # ── Logging JSON structuré ────────────────────────────────────────────
    _configure_logging(app)

    # ── Extensions ────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)

    # ── User loader ───────────────────────────────────────────────────────
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ── Blueprints ────────────────────────────────────────────────────────
    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from app.main import main_bp
    app.register_blueprint(main_bp)

    # ── Headers de sécurité sur toutes les réponses ───────────────────────
    @app.after_request
    def set_security_headers(response):
        # Déjà gérés par Nginx en prod, présents ici en dev direct (port 5000)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        # Supprimer le header qui révèle la techno
        response.headers.pop("Server", None)
        return response

    return app


def _configure_logging(app):
    """Configure le logging JSON pour que Wazuh puisse parser les événements."""
    import json

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_record = {
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            # Ajouter les champs extra (event_type, user, ip…)
            for key in ("event_type", "user", "ip", "user_agent", "details"):
                if hasattr(record, key):
                    log_record[key] = getattr(record, key)
            return json.dumps(log_record, ensure_ascii=False)

    log_dir = "/var/log/flask"
    os.makedirs(log_dir, exist_ok=True)

    file_handler = logging.FileHandler(f"{log_dir}/app.log")
    file_handler.setFormatter(JsonFormatter())
    file_handler.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JsonFormatter())
    stream_handler.setLevel(logging.INFO)

    # Attacher aux loggers Flask et applicatif
    for logger_name in ("app", "app.auth.routes", __name__):
        lg = logging.getLogger(logger_name)
        lg.setLevel(logging.INFO)
        if not lg.handlers:
            lg.addHandler(file_handler)
            lg.addHandler(stream_handler)

    app.logger.setLevel(logging.INFO)
