from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.main import main_bp
from app.models import LoginEvent


@main_bp.route("/health")
def health():
    """Health check pour Docker et Nginx."""
    return jsonify({"status": "ok"}), 200


@main_bp.route("/")
@login_required
def dashboard():
    recent_events = (
        LoginEvent.query.filter_by(user_id=current_user.id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    return render_template("main/dashboard.html", events=recent_events)


@main_bp.route("/profile")
@login_required
def profile():
    backup_codes_remaining = current_user.get_backup_codes_remaining()
    return render_template(
        "main/profile.html", backup_codes_remaining=backup_codes_remaining
    )


@main_bp.route("/profile/mfa/totp/disable", methods=["POST"])
@login_required
def disable_totp():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Mot de passe incorrect.", "danger")
        return redirect(url_for("main.profile"))

    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.commit()
    flash("Authentification TOTP désactivée.", "info")
    return redirect(url_for("main.profile"))


@main_bp.route("/profile/mfa/email/toggle", methods=["POST"])
@login_required
def toggle_email_otp():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Mot de passe incorrect.", "danger")
        return redirect(url_for("main.profile"))

    current_user.email_otp_enabled = not current_user.email_otp_enabled
    db.session.commit()

    status = "activée" if current_user.email_otp_enabled else "désactivée"
    flash(f"Authentification par email {status}.", "info")
    return redirect(url_for("main.profile"))


@main_bp.route("/profile/backup-codes", methods=["GET", "POST"])
@login_required
def backup_codes():
    codes = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if not current_user.check_password(password):
            flash("Mot de passe incorrect.", "danger")
            return redirect(url_for("main.profile"))
        codes = current_user.generate_backup_codes()
        db.session.commit()
        flash(
            "Nouveaux codes générés. Sauvegarde-les maintenant, ils ne seront plus affichés.",
            "warning",
        )
    return render_template("main/backup_codes.html", codes=codes)
