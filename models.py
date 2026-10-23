import sqlite3
import os
import re
import shutil
import hashlib
import binascii
import hmac
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash, check_password_hash

import validators as V
from validators import ValidationError

# ---------------------------------------------------------------------------
# Role names as stored in users.role.
# NOTE: students keep the historical value 'user' so existing rows / code keep working.
# ---------------------------------------------------------------------------
ROLE_STUDENT = "user"
ROLE_TEACHER = "teacher"
ROLE_ADMIN = "admin"
ALL_ROLES = (ROLE_STUDENT, ROLE_TEACHER, ROLE_ADMIN)
ROLE_LABELS = {ROLE_STUDENT: "Student", ROLE_TEACHER: "Teacher", ROLE_ADMIN: "Administrator"}

WORKFLOW_STATUSES = ['Open', 'Potential Match', 'Claim Pending', 'Verified', 'Returned', 'Closed']

ACTIVITY_ACTIONS = [
    ("report.lost_created", "Lost item reported"),
    ("report.found_created", "Found item reported"),
    ("report.updated", "Report edited"),
    ("report.status_changed", "Status changed"),
    ("report.returned", "Item marked returned"),
    ("report.deleted", "Report removed"),
    ("claim.submitted", "Ownership claim submitted"),
    ("claim.approved", "Claim approved"),
    ("claim.rejected", "Claim rejected"),
    ("student.created", "Student account created"),
    ("student.updated", "Student details edited"),
    ("student.activated", "Student account activated"),
    ("student.deactivated", "Student account deactivated"),
    ("student.deleted", "Student account deleted"),
    ("student.restored", "Student account restored"),
    ("student.password_reset", "Student password reset initiated"),
    ("staff.created", "Staff account created"),
    ("staff.activated", "Staff account activated"),
    ("staff.deactivated", "Staff account deactivated"),
    ("staff.password_reset", "Staff password reset"),
    ("password.changed", "Password changed by user"),
    ("auth.login", "Successful login"),
    ("auth.lockout", "Login lockout triggered"),
    ("account.migrated", "Legacy account migrated"),
]


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# New hashes use Werkzeug (scrypt, per-hash random salt). Legacy rows created by the
# first version of FindBack used "salt_hex$key_hex" (PBKDF2-SHA256, 100k rounds); they are
# still verifiable and are silently upgraded on the next successful login.
def hash_password(password: str) -> str:
    return generate_password_hash(password)


def _is_legacy_hash(stored: str) -> bool:
    return bool(stored) and ':' not in stored.split('$', 1)[0] and stored.count('$') == 1


def verify_password(stored_password_hash: str, provided_password: str) -> bool:
    try:
        if not stored_password_hash:
            return False
        if _is_legacy_hash(stored_password_hash):
            salt_hex, key_hex = stored_password_hash.split('$')
            salt = binascii.unhexlify(salt_hex.encode('ascii'))
            key = binascii.unhexlify(key_hex.encode('ascii'))
            new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
            return hmac.compare_digest(new_key, key)
        return check_password_hash(stored_password_hash, provided_password)
    except Exception:
        return False


def password_needs_rehash(stored_password_hash: str) -> bool:
    return _is_legacy_hash(stored_password_hash)


# ---------------------------------------------------------------------------
# Connection / schema
# ---------------------------------------------------------------------------
def get_db(db_path=None):
    if db_path is None:
        try:
            from flask import current_app, has_app_context
            if has_app_context():
                db_path = current_app.config['DATABASE']
        except Exception:
            db_path = None
    if db_path is None:
        from config import Config
        db_path = Config.DATABASE

    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


BASE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    report_type TEXT NOT NULL CHECK(report_type IN ('lost', 'found')),
    item_name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    date_occurred TEXT NOT NULL,
    location TEXT NOT NULL,
    image_filename TEXT,
    distinguishing_features TEXT,
    private_contact TEXT,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Potential Match', 'Claim Pending', 'Verified', 'Returned', 'Closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    claimant_id INTEGER NOT NULL,
    challenge_answers TEXT NOT NULL,
    claimant_contact TEXT NOT NULL,
    verification_notes TEXT,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
    FOREIGN KEY (claimant_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    changed_by INTEGER NOT NULL,
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    notes TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_type_status ON reports(report_type, status);
CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(category);
CREATE INDEX IF NOT EXISTS idx_claims_report_id ON claims(report_id);
'''


def init_db(db_path=None):
    """Create tables if needed and apply pending migrations (safe to call on every start)."""
    if db_path is None:
        # resolve through get_db's rules so a backup (below) targets the right file
        conn_probe = get_db(None)
        db_path = conn_probe.execute("PRAGMA database_list").fetchone()[2]
        conn_probe.close()
    _backup_legacy_database_if_needed(db_path)
    conn = get_db(db_path)
    try:
        conn.executescript(BASE_SCHEMA)
        conn.commit()
        migrate_db(conn)
    finally:
        conn.close()


def _table_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _backup_legacy_database_if_needed(db_path):
    """Before the very first ERP migration of an existing database, keep a consistent copy."""
    if not db_path or not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        return None
    src = sqlite3.connect(db_path)
    try:
        if not _table_exists(src, 'users') or _table_exists(src, 'schema_migrations'):
            return None
        backup_path = f"{db_path}.pre-erp-migration-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.bak"
        dst = sqlite3.connect(backup_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
        return backup_path
    finally:
        src.close()


def _column_exists(conn, table, column):
    return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})"))


def _add_column(conn, table, column, ddl):
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
def _derive_username(email, taken):
    local = (email or "user").split('@')[0].lower()
    local = re.sub(r'[^a-z0-9._\-]', '', local) or 'user'
    if not local[0].isalpha():
        local = 'u' + local
    local = local.ljust(3, '0')[:28]
    candidate, n = local, 1
    while candidate in taken:
        n += 1
        candidate = f"{local}{n}"
    taken.add(candidate)
    return candidate


def _migration_001_erp_login(conn):
    """Adds ERP-style accounts, soft-delete, session invalidation, report lifecycle
    timestamps, the append-only activity log, login throttling and CAPTCHA storage.
    Existing users / reports / claims / audit rows are kept untouched."""
    # --- users ---
    _add_column(conn, 'users', 'username', 'TEXT')
    _add_column(conn, 'users', 'roll_number', 'TEXT')
    _add_column(conn, 'users', 'mobile', 'TEXT')
    _add_column(conn, 'users', 'class_branch', 'TEXT')
    _add_column(conn, 'users', 'academic_year', 'TEXT')
    _add_column(conn, 'users', 'is_active', 'INTEGER NOT NULL DEFAULT 1')
    _add_column(conn, 'users', 'is_deleted', 'INTEGER NOT NULL DEFAULT 0')
    _add_column(conn, 'users', 'deleted_at', 'TEXT')
    _add_column(conn, 'users', 'must_change_password', 'INTEGER NOT NULL DEFAULT 0')
    _add_column(conn, 'users', 'session_version', 'INTEGER NOT NULL DEFAULT 0')
    _add_column(conn, 'users', 'updated_at', 'TEXT')
    _add_column(conn, 'users', 'password_changed_at', 'TEXT')
    _add_column(conn, 'users', 'password_reset_by', 'INTEGER')
    _add_column(conn, 'users', 'password_reset_at', 'TEXT')
    _add_column(conn, 'users', 'created_by', 'INTEGER')

    # --- reports lifecycle ---
    _add_column(conn, 'reports', 'verified_at', 'TEXT')
    _add_column(conn, 'reports', 'verified_by', 'INTEGER')
    _add_column(conn, 'reports', 'returned_at', 'TEXT')
    _add_column(conn, 'reports', 'returned_by', 'INTEGER')

    # --- constraints / indexes ---
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_roll_number ON users(roll_number) WHERE roll_number IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON users(lower(username)) WHERE username IS NOT NULL")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_users_role_insert
        BEFORE INSERT ON users WHEN NEW.role NOT IN ('user','teacher','admin')
        BEGIN SELECT RAISE(ABORT, 'invalid role'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_users_role_update
        BEFORE UPDATE OF role ON users WHEN NEW.role NOT IN ('user','teacher','admin')
        BEGIN SELECT RAISE(ABORT, 'invalid role'); END""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id)")

    # --- append-only activity log (no FKs on purpose: history must outlive users/reports) ---
    conn.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor_id INTEGER,
        actor_name TEXT,
        actor_roll TEXT,
        actor_role TEXT,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        report_id INTEGER,
        report_type TEXT,
        category TEXT,
        item_name TEXT,
        target_user_id INTEGER,
        target_name TEXT,
        target_roll TEXT,
        old_status TEXT,
        new_status TEXT,
        details TEXT,
        ip TEXT
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_log(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_log(actor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_report ON activity_log(report_id)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_activity_no_update
        BEFORE UPDATE ON activity_log
        BEGIN SELECT RAISE(ABORT, 'activity_log is append-only'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_activity_no_delete
        BEFORE DELETE ON activity_log
        BEGIN SELECT RAISE(ABORT, 'activity_log is append-only'); END""")

    # --- login throttling + CAPTCHA ---
    conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        portal TEXT,
        ip TEXT,
        success INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_ident ON login_attempts(identifier, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, created_at)")
    conn.execute('''CREATE TABLE IF NOT EXISTS captcha_challenges (
        token TEXT PRIMARY KEY,
        answer_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')

    now = now_iso()

    # --- upgrade legacy rows (this migration runs exactly once per database) ---
    conn.execute("UPDATE users SET updated_at = created_at WHERE updated_at IS NULL")
    legacy_users = conn.execute("SELECT id, email, role FROM users").fetchall()
    taken = {r[0] for r in conn.execute("SELECT lower(username) FROM users WHERE username IS NOT NULL")}
    for row in legacy_users:
        if row['role'] == ROLE_ADMIN:
            # Legacy admins log in with a username now. Their old password stays valid but
            # must be changed on next login (the old demo password was publicly documented).
            username = _derive_username(row['email'], taken)
            conn.execute("UPDATE users SET username = ?, must_change_password = 1 WHERE id = ?",
                         (username, row['id']))
            detail = f"Legacy administrator upgraded; username '{username}'. Password change required at next login."
        else:
            # Legacy self-registered students have no roll number / mobile. They stay in the
            # database (their reports are preserved) but cannot log in until an administrator
            # completes the profile and activates the account.
            conn.execute("UPDATE users SET is_active = 0, must_change_password = 1 WHERE id = ?", (row['id'],))
            detail = "Legacy student account preserved but deactivated until an administrator assigns a roll number and mobile number."
        _log_activity(conn, "account.migrated", None, entity_type="user", entity_id=row['id'],
                      target_user_id=row['id'], details=detail, when=now)

    # --- report lifecycle backfill from the old status audit trail ---
    for rep in conn.execute("SELECT id, status, updated_at FROM reports").fetchall():
        for status, col_at, col_by in (('Verified', 'verified_at', 'verified_by'),
                                       ('Returned', 'returned_at', 'returned_by')):
            hit = conn.execute(
                "SELECT timestamp, changed_by FROM audit_logs WHERE report_id=? AND new_status=? "
                "ORDER BY timestamp DESC LIMIT 1", (rep['id'], status)).fetchone()
            if hit:
                conn.execute(f"UPDATE reports SET {col_at}=?, {col_by}=? WHERE id=?",
                             (hit['timestamp'], hit['changed_by'], rep['id']))
            elif rep['status'] == status:
                conn.execute(f"UPDATE reports SET {col_at}=? WHERE id=?", (rep['updated_at'], rep['id']))

    # --- activity history backfill so the admin history is complete from day one ---
    note = "Backfilled from pre-existing record."
    for rep in conn.execute("SELECT * FROM reports ORDER BY id").fetchall():
        _log_activity(conn, f"report.{rep['report_type']}_created", rep['user_id'], entity_type="report",
                      entity_id=rep['id'], report=rep, new_status='Open', details=note, when=rep['created_at'])
    for cl in conn.execute("SELECT * FROM claims ORDER BY id").fetchall():
        rep = conn.execute("SELECT * FROM reports WHERE id=?", (cl['report_id'],)).fetchone()
        _log_activity(conn, "claim.submitted", cl['claimant_id'], entity_type="claim", entity_id=cl['id'],
                      report=rep, details=note, when=cl['created_at'])
        if cl['status'] in ('Approved', 'Rejected') and cl['reviewed_at']:
            _log_activity(conn, f"claim.{cl['status'].lower()}", cl['reviewed_by'], entity_type="claim",
                          entity_id=cl['id'], report=rep, details=note, when=cl['reviewed_at'])
    for au in conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall():
        rep = conn.execute("SELECT * FROM reports WHERE id=?", (au['report_id'],)).fetchone()
        _log_activity(conn, "report.status_changed", au['changed_by'], entity_type="report",
                      entity_id=au['report_id'], report=rep, old_status=au['old_status'],
                      new_status=au['new_status'], details=(au['notes'] or note), when=au['timestamp'])


MIGRATIONS = [
    (1, "erp_login_and_admin_monitoring", _migration_001_erp_login),
]
LATEST_SCHEMA_VERSION = MIGRATIONS[-1][0]


def migrate_db(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations ("
                 "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
    conn.commit()
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    old_isolation = conn.isolation_level
    conn.isolation_level = None  # manual transaction control so DDL + data move atomically
    try:
        for version, name, fn in MIGRATIONS:
            if version in applied:
                continue
            conn.execute("BEGIN IMMEDIATE")
            try:
                fn(conn)
                conn.execute("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                             (version, name, now_iso()))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
    finally:
        conn.isolation_level = old_isolation


def get_schema_version(db_path=None):
    conn = get_db(db_path)
    try:
        if not _table_exists(conn, 'schema_migrations'):
            return 0
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return row[0] or 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Activity (audit) log — append-only
# ---------------------------------------------------------------------------
def _snapshot(conn, user_id):
    if user_id is None:
        return (None, None, None)
    row = conn.execute("SELECT name, role, roll_number, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return ("Deleted/unknown user", None, None)
    ident = row['roll_number'] if row['role'] == ROLE_STUDENT and row['roll_number'] else row['username']
    return (row['name'], ident, row['role'])


def _log_activity(conn, action, actor_id=None, *, entity_type=None, entity_id=None, report=None,
                  target_user_id=None, old_status=None, new_status=None, details=None, ip=None, when=None):
    """Append one row to activity_log using an already-open connection (same transaction)."""
    a_name, a_roll, a_role = _snapshot(conn, actor_id)
    t_name, t_roll, _ = _snapshot(conn, target_user_id)

    def rep_get(key):
        if report is None:
            return None
        try:
            return report[key]
        except (KeyError, IndexError):
            return None

    conn.execute('''
        INSERT INTO activity_log (timestamp, actor_id, actor_name, actor_roll, actor_role, action,
            entity_type, entity_id, report_id, report_type, category, item_name,
            target_user_id, target_name, target_roll, old_status, new_status, details, ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (when or now_iso(), actor_id, a_name, a_roll, a_role, action,
          entity_type, entity_id, rep_get('id') if entity_type != 'report' else (entity_id or rep_get('id')),
          rep_get('report_type'), rep_get('category'), rep_get('item_name'),
          target_user_id, t_name, t_roll, old_status, new_status, details, ip))


def log_activity(action, actor_id=None, db_path=None, **kwargs):
    """Stand-alone logging helper (opens its own connection)."""
    conn = get_db(db_path)
    try:
        _log_activity(conn, action, actor_id, **kwargs)
        conn.commit()
    finally:
        conn.close()


def _like(term):
    term = (term or "").strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f"%{term}%"


def query_activity(filters=None, limit=25, offset=0, db_path=None):
    """Searchable audit history. All filters are optional and fully parameterised."""
    f = filters or {}
    where, params = ["1=1"], []
    if f.get('date_from'):
        where.append("timestamp >= ?")
        params.append(f['date_from'] + "T00:00:00")
    if f.get('date_to'):
        where.append("timestamp <= ?")
        params.append(f['date_to'] + "T23:59:59.999999")
    if f.get('roll'):
        where.append("(actor_roll LIKE ? ESCAPE '\\' OR target_roll LIKE ? ESCAPE '\\')")
        params.extend([_like(f['roll'])] * 2)
    if f.get('action'):
        where.append("action = ?")
        params.append(f['action'])
    if f.get('report_type') in ('lost', 'found'):
        where.append("report_type = ?")
        params.append(f['report_type'])
    if f.get('category') and f['category'] != 'All':
        where.append("category = ?")
        params.append(f['category'])
    if f.get('status') and f['status'] != 'All':
        where.append("new_status = ?")
        params.append(f['status'])
    if f.get('q'):
        where.append("(item_name LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\' OR actor_name LIKE ? ESCAPE '\\' "
                     "OR target_name LIKE ? ESCAPE '\\')")
        params.extend([_like(f['q'])] * 4)
    clause = " AND ".join(where)
    conn = get_db(db_path)
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM activity_log WHERE {clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM activity_log WHERE {clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
        return [dict(r) for r in rows], total
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------
def _placeholder_email(kind, ident):
    # users.email is a legacy NOT NULL UNIQUE column. ERP accounts log in by roll number /
    # username, so they get a non-routable placeholder (".invalid" is reserved by RFC 2606).
    safe = re.sub(r'[^a-z0-9._\-]', '-', ident.lower())
    return f"{safe}@{kind}.findback.invalid"


def create_user(name, email, password, role="user", db_path=None):
    """Legacy helper kept for backward compatibility (email-based account, no roll number)."""
    conn = get_db(db_path)
    cur = conn.cursor()
    pwd_hash = hash_password(password)
    now = now_iso()
    try:
        cur.execute(
            "INSERT INTO users (name, email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name.strip(), email.strip().lower(), pwd_hash, role, now, now)
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _fetch_user(where_sql, params, db_path=None):
    conn = get_db(db_path)
    try:
        row = conn.execute(f"SELECT * FROM users WHERE {where_sql}", params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_email(email, db_path=None):
    return _fetch_user("email = ?", (email.strip().lower(),), db_path)


def get_user_by_id(user_id, db_path=None):
    return _fetch_user("id = ?", (user_id,), db_path)


def get_student_by_roll(roll_number, db_path=None):
    return _fetch_user("role = 'user' AND roll_number = ?", ((roll_number or "").strip().upper(),), db_path)


def get_staff_by_username(username, db_path=None):
    return _fetch_user("role IN ('admin','teacher') AND lower(username) = ?", ((username or "").strip().lower(),), db_path)


def _integrity_message(exc, default):
    text = str(exc).lower()
    if 'roll_number' in text:
        return "A user with this roll number already exists."
    if 'username' in text:
        return "That username is already taken."
    return default


def create_student(roll_number, name, mobile, class_branch="", academic_year="", created_by=None,
                   db_path=None, roll_regex=V.DEFAULT_ROLL_REGEX, mobile_regex=V.DEFAULT_MOBILE_REGEX):
    """Admin-side student creation. The registered mobile number becomes the *initial* password
    (stored only as a hash) and the account is flagged for a forced password change."""
    errors = []
    try:
        roll = V.normalize_roll(roll_number, roll_regex)
    except ValidationError as e:
        errors.extend(e.errors)
        roll = None
    try:
        name = V.normalize_name(name)
    except ValidationError as e:
        errors.extend(e.errors)
    try:
        mobile = V.normalize_mobile(mobile, mobile_regex)
    except ValidationError as e:
        errors.extend(e.errors)
    try:
        class_branch = V.clean_text(class_branch, 60, "Class / branch")
        academic_year = V.clean_text(academic_year, 30, "Year / batch")
    except ValidationError as e:
        errors.extend(e.errors)
    if errors:
        raise ValidationError(errors)

    conn = get_db(db_path)
    now = now_iso()
    try:
        existing = conn.execute("SELECT is_deleted FROM users WHERE roll_number = ?", (roll,)).fetchone()
        if existing:
            raise ValidationError("A deleted account with this roll number exists; restore it instead."
                                  if existing['is_deleted'] else "A student with this roll number already exists.")
        try:
            cur = conn.execute('''
                INSERT INTO users (name, email, password_hash, role, created_at, updated_at, roll_number, mobile,
                                   class_branch, academic_year, is_active, must_change_password, created_by,
                                   password_changed_at)
                VALUES (?, ?, ?, 'user', ?, ?, ?, ?, ?, ?, 1, 1, ?, NULL)
            ''', (name, _placeholder_email('students', roll), hash_password(mobile), now, now, roll, mobile,
                  class_branch or None, academic_year or None, created_by))
        except sqlite3.IntegrityError as exc:
            raise ValidationError(_integrity_message(exc, "Could not create the account."))
        sid = cur.lastrowid
        _log_activity(conn, "student.created", created_by, entity_type="user", entity_id=sid, target_user_id=sid,
                      details=f"Student account created ({class_branch or 'no class'}); initial password set to registered mobile; password change forced.")
        conn.commit()
        return sid
    finally:
        conn.close()


def create_staff(username, name, role, initial_password, created_by=None, db_path=None, min_length=8):
    """Create an admin or teacher account with its own username + password."""
    if role not in (ROLE_ADMIN, ROLE_TEACHER):
        raise ValidationError("Role must be admin or teacher.")
    errors = []
    try:
        username = V.normalize_username(username)
    except ValidationError as e:
        errors.extend(e.errors)
    try:
        name = V.normalize_name(name)
    except ValidationError as e:
        errors.extend(e.errors)
    errors.extend(V.validate_new_password(initial_password, forbidden=(username,), min_length=min_length))
    if errors:
        raise ValidationError(errors)

    conn = get_db(db_path)
    now = now_iso()
    try:
        try:
            cur = conn.execute('''
                INSERT INTO users (name, email, password_hash, role, created_at, updated_at, username,
                                   is_active, must_change_password, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ''', (name, _placeholder_email('staff', username), hash_password(initial_password), role, now, now,
                  username, 0 if role == ROLE_ADMIN and created_by is None else 1, created_by))
        except sqlite3.IntegrityError as exc:
            raise ValidationError(_integrity_message(exc, "Could not create the account."))
        uid = cur.lastrowid
        _log_activity(conn, "staff.created", created_by, entity_type="user", entity_id=uid, target_user_id=uid,
                      details=f"{ROLE_LABELS[role]} account '{username}' created.")
        conn.commit()
        return uid
    finally:
        conn.close()


def update_student(student_id, data, actor_id, db_path=None,
                   roll_regex=V.DEFAULT_ROLL_REGEX, mobile_regex=V.DEFAULT_MOBILE_REGEX):
    """Edit profile fields. Changing the mobile does NOT change an existing password."""
    conn = get_db(db_path)
    try:
        cur_row = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (student_id,)).fetchone()
        if not cur_row:
            raise ValidationError("Student not found.")
        errors, new = [], {}
        try:
            new['roll_number'] = V.normalize_roll(data.get('roll_number', cur_row['roll_number']), roll_regex)
        except ValidationError as e:
            errors.extend(e.errors)
        try:
            new['name'] = V.normalize_name(data.get('name', cur_row['name']))
        except ValidationError as e:
            errors.extend(e.errors)
        try:
            new['mobile'] = V.normalize_mobile(data.get('mobile', cur_row['mobile']), mobile_regex)
        except ValidationError as e:
            errors.extend(e.errors)
        try:
            new['class_branch'] = V.clean_text(data.get('class_branch', cur_row['class_branch']), 60, "Class / branch") or None
            new['academic_year'] = V.clean_text(data.get('academic_year', cur_row['academic_year']), 30, "Year / batch") or None
        except ValidationError as e:
            errors.extend(e.errors)
        if errors:
            raise ValidationError(errors)

        changed = [k for k in new if (new[k] or None) != (cur_row[k] or None)]
        if not changed:
            return []
        try:
            conn.execute('''UPDATE users SET roll_number=?, name=?, mobile=?, class_branch=?, academic_year=?,
                            updated_at=? WHERE id=?''',
                         (new['roll_number'], new['name'], new['mobile'], new['class_branch'],
                          new['academic_year'], now_iso(), student_id))
        except sqlite3.IntegrityError as exc:
            raise ValidationError(_integrity_message(exc, "Could not update the account."))
        if 'roll_number' in changed:
            # the login username changed: end any session created under the old one
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (student_id,))
        parts = []
        for k in changed:
            if k == 'mobile':
                parts.append("mobile number updated")           # never log the value itself
            else:
                parts.append(f"{k}: '{cur_row[k] or ''}' -> '{new[k] or ''}'")
        _log_activity(conn, "student.updated", actor_id, entity_type="user", entity_id=student_id,
                      target_user_id=student_id, details="; ".join(parts))
        conn.commit()
        return changed
    finally:
        conn.close()


def set_user_active(user_id, active, actor_id, db_path=None):
    """Activate / deactivate a student or staff account. Deactivation ends live sessions."""
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ValidationError("Account not found.")
        if row['is_deleted']:
            raise ValidationError("This account is deleted. Restore it first.")
        if active and row['role'] == ROLE_STUDENT and (not row['roll_number'] or not row['mobile']):
            raise ValidationError("Assign a roll number and mobile number before activating this legacy account.")
        if not active:
            if user_id == actor_id:
                raise ValidationError("You cannot deactivate your own account.")
            if row['role'] == ROLE_ADMIN:
                n = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1 AND is_deleted=0 AND id<>?",
                                 (user_id,)).fetchone()[0]
                if n == 0:
                    raise ValidationError("At least one active administrator must remain.")
        conn.execute("UPDATE users SET is_active=?, updated_at=?, session_version = session_version + 1 WHERE id=?",
                     (1 if active else 0, now_iso(), user_id))
        prefix = "student" if row['role'] == ROLE_STUDENT else "staff"
        _log_activity(conn, f"{prefix}.{'activated' if active else 'deactivated'}", actor_id, entity_type="user",
                      entity_id=user_id, target_user_id=user_id, details="Account " + ("enabled" if active else "disabled"))
        conn.commit()
    finally:
        conn.close()


def student_dependency_counts(student_id, conn):
    return {
        'reports': conn.execute("SELECT COUNT(*) FROM reports WHERE user_id=?", (student_id,)).fetchone()[0],
        'claims': conn.execute("SELECT COUNT(*) FROM claims WHERE claimant_id=?", (student_id,)).fetchone()[0],
        'status_changes': conn.execute("SELECT COUNT(*) FROM audit_logs WHERE changed_by=?", (student_id,)).fetchone()[0],
    }


def delete_student(student_id, actor_id, db_path=None):
    """Hard-delete only when the student has no history; otherwise soft-delete so reports,
    claims and audit rows keep pointing at a real record. Returns 'deleted' or 'soft_deleted'."""
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (student_id,)).fetchone()
        if not row:
            raise ValidationError("Student not found.")
        if row['is_deleted']:
            raise ValidationError("This account is already deleted.")
        deps = student_dependency_counts(student_id, conn)
        if sum(deps.values()) == 0:
            _log_activity(conn, "student.deleted", actor_id, entity_type="user", entity_id=student_id,
                          target_user_id=student_id, details="Account permanently deleted (no report history).")
            conn.execute("DELETE FROM users WHERE id = ?", (student_id,))
            result = 'deleted'
        else:
            conn.execute("UPDATE users SET is_deleted=1, is_active=0, deleted_at=?, updated_at=?, "
                         "session_version = session_version + 1 WHERE id=?", (now_iso(), now_iso(), student_id))
            _log_activity(conn, "student.deleted", actor_id, entity_type="user", entity_id=student_id,
                          target_user_id=student_id,
                          details=f"Account soft-deleted; history kept ({deps['reports']} reports, {deps['claims']} claims).")
            result = 'soft_deleted'
        conn.commit()
        return result
    finally:
        conn.close()


def restore_student(student_id, actor_id, db_path=None):
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id=? AND role='user' AND is_deleted=1", (student_id,)).fetchone()
        if not row:
            raise ValidationError("No deleted student with that ID.")
        conn.execute("UPDATE users SET is_deleted=0, deleted_at=NULL, is_active=0, updated_at=?, "
                     "session_version = session_version + 1 WHERE id=?", (now_iso(), student_id))
        _log_activity(conn, "student.restored", actor_id, entity_type="user", entity_id=student_id,
                      target_user_id=student_id, details="Account restored (left deactivated until an admin activates it).")
        conn.commit()
    finally:
        conn.close()


def reset_student_password(student_id, actor_id, reason=None, db_path=None, new_password=None, min_length=8):
    """Admin-initiated reset: the password goes back to the registered mobile number (hashed),
    the student must change it at next login, and every existing session is invalidated.
    The reset is recorded with who/when/why — never with any password value."""
    reason = V.clean_text(reason, 200, "Note") or "Reset by staff"
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (student_id,)).fetchone()
        if not row or row['is_deleted']:
            raise ValidationError("Student not found.")
        if not row['mobile'] or not row['roll_number']:
            raise ValidationError("This account has no registered mobile number / roll number to reset to.")
        if new_password:
            problems = V.validate_new_password(new_password, min_length=min_length)
            if problems:
                raise ValidationError(problems)
            new_secret, how = new_password, "temporary password set by staff"
        else:
            new_secret, how = row['mobile'], "reset to registered mobile"
        now = now_iso()
        # Only the password and session version change: reports, claims and history are untouched.
        conn.execute('''UPDATE users SET password_hash=?, must_change_password=1, session_version=session_version+1,
                        password_reset_by=?, password_reset_at=?, updated_at=? WHERE id=?''',
                     (hash_password(new_secret), actor_id, now, now, student_id))
        _log_activity(conn, "student.password_reset", actor_id, entity_type="user", entity_id=student_id,
                      target_user_id=student_id,
                      details=f"Password {how}; student should change it after sign-in. Note: {reason}")
        conn.commit()
    finally:
        conn.close()


def reset_staff_password(staff_id, actor_id, new_temp_password, db_path=None, min_length=8):
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'teacher'", (staff_id,)).fetchone()
        if not row:
            raise ValidationError("Teacher account not found.")
        errors = V.validate_new_password(new_temp_password, forbidden=(row['username'],), min_length=min_length)
        if errors:
            raise ValidationError(errors)
        now = now_iso()
        conn.execute('''UPDATE users SET password_hash=?, must_change_password=1, session_version=session_version+1,
                        password_reset_by=?, password_reset_at=?, updated_at=? WHERE id=?''',
                     (hash_password(new_temp_password), actor_id, now, now, staff_id))
        _log_activity(conn, "staff.password_reset", actor_id, entity_type="user", entity_id=staff_id,
                      target_user_id=staff_id, details="Temporary password issued; change forced at next login.")
        conn.commit()
    finally:
        conn.close()


def change_password(user_id, current_password, new_password, db_path=None, min_length=8):
    """Self-service change. Needs the current password; ends all other sessions.
    Returns the new session_version so the caller can keep the current session alive."""
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row or not row['is_active'] or row['is_deleted']:
            raise ValidationError("Account is not available.")
        if not verify_password(row['password_hash'], current_password or ""):
            raise ValidationError("Current password is incorrect.")
        forbidden = (row['roll_number'], row['username'], row['mobile'], row['name'])
        errors = V.validate_new_password(new_password, current_password=current_password,
                                         forbidden=forbidden, min_length=min_length)
        if errors:
            raise ValidationError(errors)
        now = now_iso()
        new_version = row['session_version'] + 1
        conn.execute('''UPDATE users SET password_hash=?, must_change_password=0, session_version=?,
                        password_changed_at=?, updated_at=? WHERE id=?''',
                     (hash_password(new_password), new_version, now, now, user_id))
        _log_activity(conn, "password.changed", user_id, entity_type="user", entity_id=user_id,
                      target_user_id=user_id, details="Password changed by account owner.")
        conn.commit()
        return new_version
    finally:
        conn.close()


def rehash_password_if_needed(user_id, plain_password, db_path=None):
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if row and password_needs_rehash(row['password_hash']):
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(plain_password), user_id))
            conn.commit()
    finally:
        conn.close()


def list_students(q=None, status=None, limit=25, offset=0, db_path=None):
    where, params = ["u.role = 'user'"], []
    if q:
        where.append("(u.roll_number LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\')")
        params.extend([_like(q)] * 2)
    if status == 'active':
        where.append("u.is_active = 1 AND u.is_deleted = 0")
    elif status == 'inactive':
        where.append("u.is_active = 0 AND u.is_deleted = 0")
    elif status == 'deleted':
        where.append("u.is_deleted = 1")
    elif status == 'password_pending':
        where.append("u.must_change_password = 1 AND u.is_deleted = 0")
    elif status == 'legacy':
        where.append("u.roll_number IS NULL AND u.is_deleted = 0")
    else:
        where.append("u.is_deleted = 0")
    clause = " AND ".join(where)
    conn = get_db(db_path)
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM users u WHERE {clause}", params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT u.*,
              (SELECT COUNT(*) FROM reports r WHERE r.user_id=u.id AND r.report_type='lost')  AS lost_count,
              (SELECT COUNT(*) FROM reports r WHERE r.user_id=u.id AND r.report_type='found') AS found_count
            FROM users u WHERE {clause}
            ORDER BY u.roll_number IS NULL, u.roll_number, u.name LIMIT ? OFFSET ?''',
                            params + [limit, offset]).fetchall()
        return [dict(r) for r in rows], total
    finally:
        conn.close()


def list_staff(db_path=None):
    conn = get_db(db_path)
    try:
        rows = conn.execute("SELECT * FROM users WHERE role IN ('admin','teacher') AND is_deleted=0 "
                            "ORDER BY role, username").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_student_history(student_id, db_path=None):
    conn = get_db(db_path)
    try:
        lost = [dict(r) for r in conn.execute(
            "SELECT * FROM reports WHERE user_id=? AND report_type='lost' ORDER BY created_at DESC", (student_id,))]
        found = [dict(r) for r in conn.execute(
            "SELECT * FROM reports WHERE user_id=? AND report_type='found' ORDER BY created_at DESC", (student_id,))]
        claims = [dict(r) for r in conn.execute('''
            SELECT c.id, c.status, c.created_at, c.reviewed_at, r.item_name, r.id AS report_id
            FROM claims c JOIN reports r ON c.report_id = r.id WHERE c.claimant_id=? ORDER BY c.created_at DESC''',
                                                  (student_id,))]
        return {'lost': lost, 'found': found, 'claims': claims,
                'deps': student_dependency_counts(student_id, conn)}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Login throttling + CAPTCHA storage
# ---------------------------------------------------------------------------
def _norm_ident(identifier):
    return (identifier or "").strip().lower()[:64]


def record_login_attempt(identifier, ip, success, portal=None, db_path=None):
    conn = get_db(db_path)
    try:
        conn.execute("INSERT INTO login_attempts (identifier, portal, ip, success, created_at) VALUES (?,?,?,?,?)",
                     (_norm_ident(identifier), portal, ip, 1 if success else 0, now_iso()))
        # keep the table small
        conn.execute("DELETE FROM login_attempts WHERE created_at < ?",
                     (_iso(datetime.now(timezone.utc) - timedelta(days=2)),))
        conn.commit()
    finally:
        conn.close()


def login_lock_status(identifier, ip, max_failures, lockout_seconds, ip_max_failures, window_seconds, db_path=None):
    """Return (locked: bool, retry_after_seconds: int). Failed attempts made while locked are not
    recorded, so an attacker cannot extend a victim's lockout indefinitely."""
    ident = _norm_ident(identifier)
    now = datetime.now(timezone.utc)
    conn = get_db(db_path)
    try:
        cutoff = _iso(now - timedelta(seconds=lockout_seconds))
        last_ok = conn.execute("SELECT MAX(created_at) FROM login_attempts WHERE identifier=? AND success=1",
                               (ident,)).fetchone()[0]
        since = max(cutoff, last_ok) if last_ok else cutoff
        rows = conn.execute("SELECT created_at FROM login_attempts WHERE identifier=? AND success=0 AND created_at>? "
                            "ORDER BY created_at DESC", (ident, since)).fetchall()
        if len(rows) >= max_failures:
            last_fail = datetime.strptime(rows[0][0], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc)
            retry = int((last_fail + timedelta(seconds=lockout_seconds) - now).total_seconds())
            if retry > 0:
                return True, retry
        if ip:
            ip_cut = _iso(now - timedelta(seconds=window_seconds))
            n = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created_at>?",
                             (ip, ip_cut)).fetchone()[0]
            if n >= ip_max_failures:
                return True, window_seconds
        return False, 0
    finally:
        conn.close()


def store_captcha(token, answer_hash, db_path=None):
    conn = get_db(db_path)
    try:
        conn.execute("INSERT OR REPLACE INTO captcha_challenges (token, answer_hash, created_at) VALUES (?,?,?)",
                     (token, answer_hash, now_iso()))
        conn.execute("DELETE FROM captcha_challenges WHERE created_at < ?",
                     (_iso(datetime.now(timezone.utc) - timedelta(hours=1)),))
        conn.commit()
    finally:
        conn.close()


def pop_captcha(token, db_path=None):
    """Fetch-and-delete: a challenge can be attempted exactly once."""
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT answer_hash, created_at FROM captcha_challenges WHERE token=?", (token,)).fetchone()
        if row:
            conn.execute("DELETE FROM captcha_challenges WHERE token=?", (token,))
            conn.commit()
            return dict(row)
        return None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------
def create_report(user_id, report_type, item_name, category, description,
                  date_occurred, location, image_filename=None,
                  distinguishing_features=None, private_contact=None, db_path=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    now = now_iso()
    try:
        cur.execute('''
            INSERT INTO reports (
                user_id, report_type, item_name, category, description,
                date_occurred, location, image_filename, distinguishing_features,
                private_contact, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
        ''', (
            user_id, report_type, item_name.strip(), category.strip(), description.strip(),
            date_occurred, location.strip(), image_filename,
            distinguishing_features.strip() if distinguishing_features else None,
            private_contact.strip() if private_contact else None,
            now, now
        ))
        report_id = cur.lastrowid
        rep = cur.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        _log_activity(conn, f"report.{report_type}_created", user_id, entity_type="report", entity_id=report_id,
                      report=rep, new_status='Open', details=f"{report_type.title()} report created: {rep['item_name']}")
        conn.commit()
        return report_id
    finally:
        conn.close()


_REPORT_SELECT = '''
    SELECT r.*, u.name AS reporter_name, u.roll_number AS reporter_roll, u.username AS reporter_username,
           u.role AS reporter_role
    FROM reports r JOIN users u ON r.user_id = u.id
'''


def get_report_by_id(report_id, db_path=None):
    conn = get_db(db_path)
    try:
        row = conn.execute(_REPORT_SELECT + " WHERE r.id = ?", (report_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_reports(report_type=None, category=None, location=None, keyword=None, status=None,
                limit=50, offset=0, db_path=None, user_id=None, exclude_user_id=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    query = _REPORT_SELECT + " WHERE 1=1"
    params = []
    if report_type:
        query += " AND r.report_type = ?"
        params.append(report_type)
    if user_id is not None:
        query += " AND r.user_id = ?"
        params.append(user_id)
    if exclude_user_id is not None:
        query += " AND r.user_id <> ?"
        params.append(exclude_user_id)
    if category and category != 'All':
        query += " AND r.category = ?"
        params.append(category)
    if location:
        query += " AND r.location LIKE ? ESCAPE '\\'"
        params.append(_like(location))
    if keyword:
        query += " AND (r.item_name LIKE ? ESCAPE '\\' OR r.description LIKE ? ESCAPE '\\')"
        term = _like(keyword)
        params.extend([term, term])
    if status and status != 'All':
        query += " AND r.status = ?"
        params.append(status)

    query += " ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def query_reports_admin(filters=None, limit=25, offset=0, db_path=None):
    """Operational view for administrators: every report with the reporting student's identity."""
    f = filters or {}
    where, params = ["1=1"], []
    if f.get('report_type') in ('lost', 'found'):
        where.append("r.report_type = ?")
        params.append(f['report_type'])
    if f.get('category') and f['category'] != 'All':
        where.append("r.category = ?")
        params.append(f['category'])
    if f.get('status') and f['status'] != 'All':
        where.append("r.status = ?")
        params.append(f['status'])
    if f.get('roll'):
        where.append("(u.roll_number LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\')")
        params.extend([_like(f['roll'])] * 2)
    if f.get('date_from'):
        where.append("r.created_at >= ?")
        params.append(f['date_from'] + "T00:00:00")
    if f.get('date_to'):
        where.append("r.created_at <= ?")
        params.append(f['date_to'] + "T23:59:59.999999")
    if f.get('q'):
        where.append("(r.item_name LIKE ? ESCAPE '\\' OR r.description LIKE ? ESCAPE '\\' OR r.location LIKE ? ESCAPE '\\')")
        params.extend([_like(f['q'])] * 3)
    clause = " AND ".join(where)
    conn = get_db(db_path)
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM reports r JOIN users u ON r.user_id=u.id WHERE {clause}",
                             params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT r.*, u.name AS reporter_name, u.roll_number AS reporter_roll, u.username AS reporter_username,
                   (SELECT COUNT(*) FROM claims c WHERE c.report_id = r.id) AS claim_count,
                   (SELECT COUNT(*) FROM claims c WHERE c.report_id = r.id AND c.status='Pending') AS pending_claims
            FROM reports r JOIN users u ON r.user_id = u.id
            WHERE {clause} ORDER BY r.created_at DESC, r.id DESC LIMIT ? OFFSET ?''',
                            params + [limit, offset]).fetchall()
        return [dict(r) for r in rows], total
    finally:
        conn.close()


def update_report_fields(report_id, editor_id, data, db_path=None):
    """Owner edit of the descriptive fields (status/ownership cannot be changed here)."""
    allowed = ('item_name', 'category', 'description', 'date_occurred', 'location',
               'distinguishing_features', 'private_contact')
    conn = get_db(db_path)
    try:
        old = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not old:
            return []
        changed = [k for k in allowed if k in data and (data[k] or None) != (old[k] or None)]
        if not changed:
            return []
        sets = ", ".join(f"{k} = ?" for k in changed)   # column names come from the fixed whitelist above
        conn.execute(f"UPDATE reports SET {sets}, updated_at = ? WHERE id = ?",
                     [data[k] or None for k in changed] + [now_iso(), report_id])
        rep = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        _log_activity(conn, "report.updated", editor_id, entity_type="report", entity_id=report_id, report=rep,
                      details="Fields edited: " + ", ".join(changed))
        conn.commit()
        return changed
    finally:
        conn.close()


def delete_report(report_id, actor_id, db_path=None):
    conn = get_db(db_path)
    try:
        rep = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not rep:
            return False
        _log_activity(conn, "report.deleted", actor_id, entity_type="report", entity_id=report_id, report=rep,
                      old_status=rep['status'], details=f"Report removed by moderator: {rep['item_name']}")
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        conn.commit()
        return True
    finally:
        conn.close()


def update_report_status(report_id, new_status, changed_by, notes=None, db_path=None):
    if new_status not in WORKFLOW_STATUSES:
        return False
    conn = get_db(db_path)
    cur = conn.cursor()
    now = now_iso()
    try:
        cur.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = cur.fetchone()
        if not row:
            return False
        old_status = row['status']

        cur.execute("UPDATE reports SET status = ?, updated_at = ? WHERE id = ?", (new_status, now, report_id))
        if new_status == 'Verified' and old_status != 'Verified':
            cur.execute("UPDATE reports SET verified_at=?, verified_by=? WHERE id=?", (now, changed_by, report_id))
        if new_status == 'Returned' and old_status != 'Returned':
            cur.execute("UPDATE reports SET returned_at=?, returned_by=? WHERE id=?", (now, changed_by, report_id))
        text = notes or f"Status changed to {new_status}"
        cur.execute('''
            INSERT INTO audit_logs (report_id, changed_by, old_status, new_status, notes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (report_id, changed_by, old_status, new_status, text, now))
        _log_activity(conn, "report.status_changed", changed_by, entity_type="report", entity_id=report_id,
                      report=row, old_status=old_status, new_status=new_status, details=text)
        if new_status == 'Returned' and old_status != 'Returned':
            _log_activity(conn, "report.returned", changed_by, entity_type="report", entity_id=report_id,
                          report=row, old_status=old_status, new_status=new_status,
                          details="Item marked as returned to its owner.")
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Claim helpers
# ---------------------------------------------------------------------------
def create_claim(report_id, claimant_id, challenge_answers, claimant_contact, db_path=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    now = now_iso()
    try:
        cur.execute('''
            INSERT INTO claims (report_id, claimant_id, challenge_answers, claimant_contact, status, created_at)
            VALUES (?, ?, ?, ?, 'Pending', ?)
        ''', (report_id, claimant_id, challenge_answers, claimant_contact, now))
        claim_id = cur.lastrowid

        cur.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        rep = cur.fetchone()
        _log_activity(conn, "claim.submitted", claimant_id, entity_type="claim", entity_id=claim_id, report=rep,
                      details="Ownership claim submitted (answers stored privately).")
        # Advance report status to 'Claim Pending' if it was Open or Potential Match
        if rep and rep['status'] in ('Open', 'Potential Match'):
            cur.execute("UPDATE reports SET status = 'Claim Pending', updated_at = ? WHERE id = ?", (now, report_id))
            cur.execute('''
                INSERT INTO audit_logs (report_id, changed_by, old_status, new_status, notes, timestamp)
                VALUES (?, ?, ?, 'Claim Pending', 'Claim submitted by user', ?)
            ''', (report_id, claimant_id, rep['status'], now))
            _log_activity(conn, "report.status_changed", claimant_id, entity_type="report", entity_id=report_id,
                          report=rep, old_status=rep['status'], new_status='Claim Pending',
                          details="Claim submitted by user")

        conn.commit()
        return claim_id
    finally:
        conn.close()


def has_pending_claim(report_id, claimant_id, db_path=None):
    conn = get_db(db_path)
    try:
        return conn.execute("SELECT 1 FROM claims WHERE report_id=? AND claimant_id=? AND status='Pending'",
                            (report_id, claimant_id)).fetchone() is not None
    finally:
        conn.close()


def get_claims_for_report(report_id, db_path=None):
    """Claim history for a report. Private answers are deliberately NOT selected here."""
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT c.id, c.report_id, c.claimant_id, c.status, c.created_at, c.reviewed_at, c.reviewed_by,
                   c.verification_notes,
                   u.name AS claimant_name, u.roll_number AS claimant_roll,
                   rv.name AS reviewer_name, rv.username AS reviewer_username
            FROM claims c
            JOIN users u ON c.claimant_id = u.id
            LEFT JOIN users rv ON c.reviewed_by = rv.id
            WHERE c.report_id = ?
            ORDER BY c.created_at DESC
        ''', (report_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_claim_by_id(claim_id, db_path=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT c.*, u.name as claimant_name, u.roll_number as claimant_roll,
                   r.item_name, r.category, r.distinguishing_features, r.status as report_status,
                   r.user_id as report_owner_id,
                   rv.name as reviewer_name
            FROM claims c
            JOIN users u ON c.claimant_id = u.id
            JOIN reports r ON c.report_id = r.id
            LEFT JOIN users rv ON c.reviewed_by = rv.id
            WHERE c.id = ?
        ''', (claim_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def review_claim(claim_id, reviewer_id, action, notes=None, db_path=None):
    """action: 'Approved' | 'Rejected'. Only a Pending claim can be reviewed."""
    if action not in ('Approved', 'Rejected'):
        return False
    conn = get_db(db_path)
    cur = conn.cursor()
    now = now_iso()
    try:
        cur.execute("SELECT report_id, status FROM claims WHERE id = ?", (claim_id,))
        claim = cur.fetchone()
        if not claim or claim['status'] != 'Pending':
            return False

        report_id = claim['report_id']
        cur.execute('''
            UPDATE claims
            SET status = ?, reviewed_at = ?, reviewed_by = ?, verification_notes = ?
            WHERE id = ?
        ''', (action, now, reviewer_id, notes, claim_id))

        cur.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        rep = cur.fetchone()
        old_status = rep['status'] if rep else 'Claim Pending'
        if action == 'Approved':
            new_rep_status = 'Verified'
        else:
            others = cur.execute("SELECT COUNT(*) FROM claims WHERE report_id=? AND status='Pending' AND id<>?",
                                 (report_id, claim_id)).fetchone()[0]
            new_rep_status = 'Claim Pending' if others else 'Open'

        cur.execute("UPDATE reports SET status = ?, updated_at = ? WHERE id = ?", (new_rep_status, now, report_id))
        if action == 'Approved':
            cur.execute("UPDATE reports SET verified_at=?, verified_by=? WHERE id=?", (now, reviewer_id, report_id))
        text = f"Claim #{claim_id} {action}: {notes or ''}"
        cur.execute('''
            INSERT INTO audit_logs (report_id, changed_by, old_status, new_status, notes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (report_id, reviewer_id, old_status, new_rep_status, text, now))
        _log_activity(conn, f"claim.{action.lower()}", reviewer_id, entity_type="claim", entity_id=claim_id,
                      report=rep, old_status=old_status, new_status=new_rep_status,
                      details=f"Claim #{claim_id} {action.lower()}. Notes: {notes or '-'}")
        if old_status != new_rep_status:
            _log_activity(conn, "report.status_changed", reviewer_id, entity_type="report", entity_id=report_id,
                          report=rep, old_status=old_status, new_status=new_rep_status, details=text)

        conn.commit()
        return True
    finally:
        conn.close()


def get_audit_logs(report_id, db_path=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT a.*, u.name as user_name, u.roll_number as user_roll, u.username as user_username
            FROM audit_logs a
            LEFT JOIN users u ON a.changed_by = u.id
            WHERE a.report_id = ?
            ORDER BY a.timestamp ASC
        ''', (report_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
