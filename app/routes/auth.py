"""
Auth Blueprint
==============
Handles user registration, login, and logout.
Passwords are hashed with bcrypt (cost factor 12) before storage.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from ..extensions import db, bcrypt
from ..models import User
from ..audit import log_action

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("vault.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Basic validation
        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not email or "@" not in email:
            errors.append("Please enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html")

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()

        log_action(user, "REGISTER", details=f"New user registered: {username}")
        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("vault.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        # Allow login with username or email
        user = (
            User.query.filter_by(username=identifier).first()
            or User.query.filter_by(email=identifier).first()
        )

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            log_action(user, "LOGIN", details="Successful login")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("vault.dashboard"))

        flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout")
@login_required
def logout():
    log_action(current_user, "LOGOUT", details="User logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
