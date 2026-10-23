import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())


def _env_bool(name, default=False):
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# Placeholder values that were shipped in earlier versions / .env.example.
# They are public, so they must never be accepted as a real signing key.
_INSECURE_SECRETS = {
    "",
    "change-this-to-a-secure-random-32-byte-hex-string",
    "findback-dev-secret-key-991203847291",
}


def _load_secret_key():
    """Use SECRET_KEY from the environment; otherwise create and persist a random one."""
    env_key = os.getenv("SECRET_KEY", "").strip()
    if env_key not in _INSECURE_SECRETS and len(env_key) >= 16:
        return env_key
    instance_dir = BASE_DIR / "instance"
    key_file = instance_dir / ".secret_key"
    try:
        if key_file.exists():
            stored = key_file.read_text(encoding="utf-8").strip()
            if len(stored) >= 32:
                return stored
        instance_dir.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_hex(32)
        key_file.write_text(new_key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return new_key
    except OSError:
        # Read-only file system: fall back to a per-process key (sessions reset on restart).
        return secrets.token_hex(32)


def _parse_permission_list(raw, default):
    if raw is None:
        return set(default)
    return {p.strip() for p in raw.split(",") if p.strip()}


# ---------------------------------------------------------------------------
# Role / permission policy
# ---------------------------------------------------------------------------
# Every protected action is guarded by a named permission, never by a bare role check.
ALL_PERMISSIONS = {
    "students.view",       # see the student roster (contact details are masked)
    "students.manage",     # create / edit / activate / deactivate / delete students
    "students.reset_password",
    "reports.view_all",    # see every lost / found report (private fields hidden)
    "reports.moderate",    # change report status, delete reports
    "claims.review",       # approve / reject ownership claims
    "private.view",        # see private ownership answers, private contact, mobile numbers
    "audit.view",          # see the activity / audit history
    "staff.manage",        # create / disable teacher accounts, reset their passwords
}

# Administrators always hold every permission (not configurable on purpose).
# Teachers get ONLY what is listed here. Default: see reports + student roster (mobile masked) and
# reset a student's forgotten password. No editing/deleting students, no private data. Widen it with the TEACHER_PERMISSIONS
# environment variable, e.g.  TEACHER_PERMISSIONS=reports.view_all,students.view,audit.view
DEFAULT_TEACHER_PERMISSIONS = {"reports.view_all", "students.view", "students.reset_password"}


class Config:
    SECRET_KEY = _load_secret_key()
    DATABASE = os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "findback.sqlite"))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 5 * 1024 * 1024))  # 5MB max
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    ITEMS_PER_PAGE = 9
    ADMIN_PAGE_SIZE = 25

    # ---- Session security ----
    SESSION_COOKIE_NAME = "findback_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set SESSION_COOKIE_SECURE=1 whenever the site is served over HTTPS.
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = int(os.getenv("SESSION_LIFETIME_SECONDS", 8 * 3600))
    SESSION_IDLE_TIMEOUT = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", 30 * 60))

    # ---- CSRF ----
    CSRF_ENABLED = _env_bool("CSRF_ENABLED", True)

    # ---- CAPTCHA / robot check ----
    # checkbox   : simple "I'm not a robot" checkbox (UI check only, not bot-proof)
    # local      : server-generated image challenge, answer verified server-side (no internet needed)
    # turnstile  : Cloudflare Turnstile   (needs CAPTCHA_SITE_KEY / CAPTCHA_SECRET_KEY + internet)
    # recaptcha  : Google reCAPTCHA v2    (needs keys + internet)
    # hcaptcha   : hCaptcha               (needs keys + internet)
    # disabled   : only honoured when FLASK_ENV=development or TESTING; ignored in production
    CAPTCHA_PROVIDER = os.getenv("CAPTCHA_PROVIDER", "checkbox").strip().lower()
    CAPTCHA_SITE_KEY = os.getenv("CAPTCHA_SITE_KEY", "")
    CAPTCHA_SECRET_KEY = os.getenv("CAPTCHA_SECRET_KEY", "")
    CAPTCHA_TTL_SECONDS = 300

    # ---- Login throttling / lockout ----
    LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", 5))            # per account identifier
    LOGIN_LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", 15 * 60))
    LOGIN_IP_MAX_FAILURES = int(os.getenv("LOGIN_IP_MAX_FAILURES", 25))      # per client IP
    LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", 15 * 60))
    # Only trust X-Forwarded-For when running behind a reverse proxy you control.
    TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", False)

    # ---- Student identity rules ----
    # Roll numbers: letters/digits plus - _ /  (3-32 chars). Stored upper-case.
    ROLL_NUMBER_REGEX = os.getenv("ROLL_NUMBER_REGEX", r"^[A-Za-z0-9][A-Za-z0-9/_\-]{2,31}$")
    # Registered mobile (doubles as the initial password). Default: Indian 10-digit mobile.
    MOBILE_REGEX = os.getenv("MOBILE_REGEX", r"^[6-9][0-9]{9}$")
    PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", 8))
    # optional : after first login the change-password page is shown with a "Skip for now" button
    # forced   : nothing else works until the initial password is changed
    PASSWORD_CHANGE_MODE = os.getenv("PASSWORD_CHANGE_MODE", "optional").strip().lower()
    # When 1, staff must re-enter their own password to reset a student's password.
    RESET_REQUIRE_REAUTH = _env_bool("RESET_REQUIRE_REAUTH", False)

    # ---- Permissions ----
    TEACHER_PERMISSIONS = _parse_permission_list(
        os.getenv("TEACHER_PERMISSIONS"), DEFAULT_TEACHER_PERMISSIONS
    ) & ALL_PERMISSIONS
