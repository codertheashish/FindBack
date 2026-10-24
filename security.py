"""Cross-cutting security: CSRF, server-side CAPTCHA, session guards, RBAC permissions, headers."""
import hmac
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import wraps

from flask import (session, request, g, redirect, url_for, flash, abort, current_app, render_template)

import models
from config import ALL_PERMISSIONS

log = logging.getLogger("findback.security")

# Endpoints reachable while a password change is being forced, and without being logged in.
PASSWORD_CHANGE_ALLOWED = {"auth.change_password", "auth.logout", "static"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def client_ip():
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
    return (request.remote_addr or "unknown")[:64]


def safe_next_url(target):
    """Only allow same-site relative redirects (blocks //evil.com, https://evil.com, /\\evil.com)."""
    if not target:
        return None
    t = target.replace("\\", "/")
    parsed = urllib.parse.urlparse(t)
    if parsed.scheme or parsed.netloc or not t.startswith("/") or t.startswith("//"):
        return None
    return t


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def _enforce_csrf():
    if not current_app.config.get("CSRF_ENABLED", True):
        return
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
        abort(400, description="Your form session expired or the security token was missing. Please go back, refresh the page and try again.")


# ---------------------------------------------------------------------------
# CAPTCHA (verified on the server in every mode)
# ---------------------------------------------------------------------------
_CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I confusion
_EXTERNAL = {
    "turnstile": ("https://challenges.cloudflare.com/turnstile/v0/siteverify", "cf-turnstile-response",
                  "https://challenges.cloudflare.com/turnstile/v0/api.js", "cf-turnstile"),
    "recaptcha": ("https://www.google.com/recaptcha/api/siteverify", "g-recaptcha-response",
                  "https://www.google.com/recaptcha/api.js", "g-recaptcha"),
    "hcaptcha": ("https://hcaptcha.com/siteverify", "h-captcha-response",
                 "https://js.hcaptcha.com/1/api.js", "h-captcha"),
}


def captcha_provider():
    """Default is the "I'm not a robot" box (reCAPTCHA). The old image CAPTCHA ('local') is used only when
    CAPTCHA_PROVIDER=local is set explicitly AND the app is not running on Vercel. If the box is selected but
    its keys are missing we do NOT silently fall back to an image: we return 'unconfigured' and login fails closed."""
    cfg = current_app.config
    provider = (cfg.get("CAPTCHA_PROVIDER") or "recaptcha").lower()
    dev_mode = cfg.get("TESTING") or current_app.debug or os.getenv("FLASK_ENV") == "development"
    on_vercel = bool(os.getenv("VERCEL"))
    if provider == "local" and not on_vercel:
        return "local"
    if provider == "disabled" and dev_mode and not on_vercel:
        return "disabled"
    if provider not in _EXTERNAL:          # 'local' on Vercel, 'disabled' in production, unknown values
        provider = "recaptcha"
    if cfg.get("CAPTCHA_SITE_KEY") and cfg.get("CAPTCHA_SECRET_KEY"):
        return provider
    log.warning("CAPTCHA provider '%s' needs CAPTCHA_SITE_KEY and CAPTCHA_SECRET_KEY; login is blocked until set.", provider)
    return "unconfigured"


def _captcha_hash(token, answer):
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{token}:{answer.upper()}".encode(), hashlib.sha256).hexdigest()


def _render_captcha_svg(text):
    rnd = secrets.SystemRandom()
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="170" height="56" viewBox="0 0 170 56" '
             'role="img" aria-label="CAPTCHA image">', '<rect width="170" height="56" rx="6" fill="#eef2f7"/>']
    for _ in range(6):
        parts.append(f'<line x1="{rnd.randint(0,170)}" y1="{rnd.randint(0,56)}" x2="{rnd.randint(0,170)}" '
                     f'y2="{rnd.randint(0,56)}" stroke="#{rnd.randint(0x777777,0xbbbbbb):06x}" stroke-width="{rnd.randint(1,2)}"/>')
    for i, ch in enumerate(text):
        x, y, rot = 18 + i * 28 + rnd.randint(-3, 3), 38 + rnd.randint(-5, 5), rnd.randint(-22, 22)
        parts.append(f'<text x="{x}" y="{y}" font-family="monospace" font-size="{rnd.randint(28,34)}" '
                     f'font-weight="bold" fill="#{rnd.randint(0x111111,0x445577):06x}" '
                     f'transform="rotate({rot} {x} {y})">{ch}</text>')
    for _ in range(25):
        parts.append(f'<circle cx="{rnd.randint(0,170)}" cy="{rnd.randint(0,56)}" r="1" fill="#{rnd.randint(0x555555,0x999999):06x}"/>')
    parts.append("</svg>")
    return "".join(parts)


def _captcha_sig(payload, answer):
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{payload}:{answer.upper()}".encode(), hashlib.sha256).hexdigest()[:40]


def _make_captcha_token(answer):
    """Stateless token (timestamp.nonce.signature). Nothing is stored server-side, so it also works on
    serverless hosts (e.g. Vercel) where consecutive requests may hit different instances."""
    payload = f"{int(time.time())}.{secrets.token_hex(8)}"
    return f"{payload}.{_captcha_sig(payload, answer)}"


_USED_CAPTCHAS = {}   # best-effort single use (per process)


def _verify_local_captcha(token, answer):
    try:
        ts, nonce, sig = token.split(".")
        age = time.time() - int(ts)
    except (ValueError, AttributeError):
        return False
    now = time.time()
    for k in [k for k, v in _USED_CAPTCHAS.items() if now - v > 600]:
        _USED_CAPTCHAS.pop(k, None)
    if token in _USED_CAPTCHAS:
        return False
    _USED_CAPTCHAS[token] = now
    if age < 0 or age > current_app.config.get("CAPTCHA_TTL_SECONDS", 300):
        return False
    return hmac.compare_digest(sig, _captcha_sig(f"{ts}.{nonce}", answer))


def new_captcha_challenge():
    """Context for the login template: which widget to draw and (for 'local') the image + token."""
    provider = captcha_provider()
    ctx = {"provider": provider, "token": None, "svg": None, "site_key": current_app.config.get("CAPTCHA_SITE_KEY"),
           "script_url": None, "widget_class": None}
    if provider == "local":
        answer = "".join(secrets.choice(_CAPTCHA_ALPHABET) for _ in range(5))
        token = _make_captcha_token(answer)
        ctx["token"], ctx["svg"] = token, _render_captcha_svg(answer)
    elif provider in _EXTERNAL:
        ctx["script_url"], ctx["widget_class"] = _EXTERNAL[provider][2], _EXTERNAL[provider][3]
    return ctx


def verify_captcha(form):
    """Server-side verification. Always consumes a local challenge (single use, expires)."""
    provider = captcha_provider()
    if provider == "disabled":
        return True
    if provider == "unconfigured":
        return False
    if provider == "local":
        token = (form.get("captcha_token") or "")[:200]
        answer = (form.get("captcha_answer") or "").strip()
        if not token or not answer:
            return False
        return _verify_local_captcha(token, answer)
    # external provider
    url, field = _EXTERNAL[provider][0], _EXTERNAL[provider][1]
    response_token = form.get(field, "")
    if not response_token:
        return False
    payload = urllib.parse.urlencode({
        "secret": current_app.config["CAPTCHA_SECRET_KEY"], "response": response_token,
        "remoteip": client_ip()}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=5) as resp:
            return bool(json.loads(resp.read().decode()).get("success"))
    except Exception as exc:       # network problem => fail closed
        log.warning("CAPTCHA provider call failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Permissions (RBAC)
# ---------------------------------------------------------------------------
def permissions_for(user):
    if not user:
        return frozenset()
    if user["role"] == models.ROLE_ADMIN:
        return frozenset(ALL_PERMISSIONS)               # admins are never restricted by config
    if user["role"] == models.ROLE_TEACHER:
        return frozenset(current_app.config.get("TEACHER_PERMISSIONS", set()) & ALL_PERMISSIONS)
    return frozenset()                                   # students hold no staff permission


def has_permission(permission):
    return permission in getattr(g, "perms", frozenset())


def _login_redirect():
    nxt = request.full_path.rstrip("?") if request.method == "GET" else None
    return redirect(url_for("auth.login", next=nxt) if nxt else url_for("auth.login"))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user"):
            flash("Please log in to access this page.", "warning")
            return _login_redirect()
        return f(*args, **kwargs)
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user"):
            flash("Please log in to access this page.", "warning")
            return _login_redirect()
        if g.user["role"] != models.ROLE_STUDENT:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def permission_required(*permissions):
    """Staff-only (admin/teacher) AND every listed permission must be granted by policy."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.get("user"):
                flash("Staff authentication required.", "danger")
                return _login_redirect()
            if g.user["role"] not in (models.ROLE_ADMIN, models.ROLE_TEACHER):
                abort(403)
            if not all(has_permission(p) for p in permissions):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user"):
            flash("Staff authentication required.", "danger")
            return _login_redirect()
        if g.user["role"] not in (models.ROLE_ADMIN, models.ROLE_TEACHER):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Kept for backward compatibility: administrator role only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user"):
            flash("Admin authentication required.", "danger")
            return _login_redirect()
        if g.user["role"] != models.ROLE_ADMIN:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------
def _load_current_user():
    g.user, g.perms = None, frozenset()
    if request.endpoint == "static":
        return
    _enforce_csrf()

    uid = session.get("user_id")
    if not uid:
        return
    idle = current_app.config.get("SESSION_IDLE_TIMEOUT", 1800)
    now = time.time()
    last_seen = session.get("last_seen")
    if last_seen and now - last_seen > idle:
        session.clear()
        flash("You were signed out after a period of inactivity.", "info")
        return
    user = models.get_user_by_id(uid)
    if (not user or not user["is_active"] or user["is_deleted"]
            or user["session_version"] != session.get("sv") or user["role"] != session.get("role")):
        session.clear()
        return
    session["last_seen"] = now
    g.user, g.perms = user, permissions_for(user)

    if (user["must_change_password"] and current_app.config.get("PASSWORD_CHANGE_MODE") == "forced"
            and request.endpoint not in PASSWORD_CHANGE_ALLOWED):
        if request.method == "GET":
            flash("You must change your password before continuing.", "warning")
        return redirect(url_for("auth.change_password"))


def establish_session(user):
    """Start a fresh session for an authenticated user (prevents session fixation)."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["sv"] = user["session_version"]
    session["user_name"] = user["name"]
    session["last_seen"] = time.time()
    csrf_token()


def init_security(app):
    app.before_request(_load_current_user)

    @app.after_request
    def add_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if g.get("user") and request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject_security():
        user = g.get("user")
        return {
            "csrf_token": csrf_token,
            "can": has_permission,
            "current_user": user,
            "logged_in": bool(user),
            "current_user_name": user["name"] if user else None,
            "current_user_role": models.ROLE_LABELS.get(user["role"]) if user else None,
            "is_admin": bool(user) and user["role"] == models.ROLE_ADMIN,
            "is_teacher": bool(user) and user["role"] == models.ROLE_TEACHER,
            "is_student": bool(user) and user["role"] == models.ROLE_STUDENT,
            "is_staff": bool(user) and user["role"] in (models.ROLE_ADMIN, models.ROLE_TEACHER),
            "password_pending": bool(user) and bool(user["must_change_password"]),
        }

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("400.html", message=getattr(e, "description", None)), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(413)
    def too_large(e):
        return render_template("400.html", message="That upload is too large. Images must be under 5 MB."), 413
