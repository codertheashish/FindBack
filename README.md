# FindBack – Lost & Found Verification Portal (SS-15) · Flask backend

Privacy-first lost & found portal for a college campus, now with **college-ERP style login**
(roll number + password, CAPTCHA, lockout), **role-based access** (Student / Teacher / Admin),
**admin student management**, and a **searchable, append-only activity history**.

---

## Production deployment: important database note

**Do not deploy this SQLite-backed version to Vercel for live student accounts.** Vercel Functions use an ephemeral, per-instance filesystem; a SQLite file in `/tmp` can be empty on a cold start or differ between instances. That is why students may disappear and logins may behave inconsistently. Environment variables cannot make that SQLite file persistent.

### Recommended: Render with a persistent disk

This repository includes `render.yaml` configured for a Render web service with a persistent disk mounted at `/var/data`. The database is `/var/data/findback.sqlite`, uploads are stored under `/var/data/uploads`, and the service uses Gunicorn. A persistent disk requires a paid Render instance; do not remove the disk or change its mount path after real data has been added.

1. Push this project (without `.env` or any local database file) to your GitHub repository.
2. In Render, choose **New → Blueprint** and select the repository containing `render.yaml`.
3. When asked for `SEED_ADMIN_PASSWORD`, enter a strong password you have not published anywhere. The first admin username is `codertheashish`; the password is the value you enter in Render. Do not use a password already posted in screenshots or committed files.
4. Deploy and open the Render URL. Sign in to the **Admin / Teacher** portal. Add a test student, sign out, sign in as that student, and verify the student still appears after a redeploy.
5. Keep the persistent disk attached. Do not set `DATABASE_PATH` to `/tmp` or use the old Vercel URL for production data.

### Existing local students

The local `instance/findback.sqlite` file is intentionally not shipped in this deployment ZIP or committed to GitHub because it contains account records. Before switching production, export/record the student roster securely and recreate/import the required students into the persistent deployment. The database on Vercel and the local database are separate; students created in one do not automatically exist in the other. Do not delete the local database until you have verified the new deployment.

### Security

Never commit `.env`, `instance/findback.sqlite`, or student data. Rotate any signing key or password that has been exposed in a screenshot, chat, or repository. `CAPTCHA_PROVIDER=checkbox` is a simple checkbox UI, not a server-side bot challenge; use Cloudflare Turnstile or Google reCAPTCHA for stronger bot protection if required.

---

## 1. Run on Windows (PowerShell)

```powershell
cd FindBack\findback
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env            # optional; a random SECRET_KEY is generated if you leave it empty

python manage.py migrate          # creates / upgrades the database (existing data is kept and backed up)
python manage.py create-admin     # first administrator (prompts for a password; nothing is hard-coded)
python tests\run_tests.py         # run the test suite
python app.py                     # http://127.0.0.1:5000
```

Optional demo data: `python seed.py` (3 demo students whose initial password is their mobile number; the demo admin
password comes from `SEED_ADMIN_PASSWORD` or is generated and printed once).

Production: use a real WSGI server (e.g. `pip install waitress`, then `waitress-serve --call app:create_app`), set
`SECRET_KEY`, `SESSION_COOKIE_SECURE=1` (HTTPS) and keep `FLASK_DEBUG=0`.

## 2. First administrator (secure bootstrap)

There is **no default admin password and no admin "secret key" on a register page any more** (public registration is
disabled). Create the first admin from the server console:

```powershell
python manage.py create-admin --username principal --name "College Admin"
```

You are prompted twice for a password (min 8 chars, a letter and a digit; not echoed, stored only as a hash).
Sign in on the **Admin / Teacher** tab. Teachers are created from *Admin → Teachers*.

## 3. Admin creates a student account

*Admin → Students → + Add Student* → roll number, name, **registered mobile number**, class/branch, year.

* Roll numbers are unique (case-insensitive, stored upper-case) and are the student's username.
* The mobile number becomes the **initial password**; only its hash is stored.
* The account is flagged *password change pending*.
* From the student page the admin can edit details (incl. mobile), activate/deactivate, reset the password,
  delete/restore, and see the student's lost/found/claim history and recent activity.

## 4. First-login workflow for students

1. Student opens the **Student** tab, enters roll number + registered mobile number + a simple “I’m not a robot” checkbox.
2. They are redirected to *Change password*; no other page works until it is done.
3. They enter the current password (the mobile number), a new password (≥ 8 chars, letter + digit, not common,
   not their roll/mobile number) and confirm it.
4. All other sessions of that account are invalidated; the student lands on their dashboard.
5. Later changes: *Change Password* in the user menu (the current password is always required).

Mode is set by `PASSWORD_CHANGE_MODE` in `.env`: `optional` (default – the change page has a **Skip for now** button and a
reminder banner stays until the password is changed) or `forced` (nothing else works until it is changed).

### Forgotten password (admin or teacher)
*Students → open student → "Forgot password? Reset it…"*. No current password is needed. Leave the new password empty to
put the registered mobile number back, or type a temporary password. Only the password changes – the student's reports,
claims and history stay intact; their other logged-in devices are signed out. The activity log records who/when/why
(never a password). Teachers can do this by default (`students.reset_password`); set `RESET_REQUIRE_REAUTH=1` to make staff
re-enter their own password first. Admins can see *whether* a change is pending, never a password.

## 5. Roles and permissions

Every protected action is guarded by a named permission (see `config.py`). **Admins always have all of them.**
**Teachers get only what `TEACHER_PERMISSIONS` lists** (default: `reports.view_all`, `students.view`, `students.reset_password` –
reports overview, masked student roster, and password resets; no editing/deleting students, no private data). Students hold none and can never open admin/teacher pages.

| Permission | Meaning |
|---|---|
| `students.view` / `students.manage` / `students.reset_password` | roster (mobile masked) / create-edit-activate-delete / reset passwords |
| `reports.view_all` / `reports.moderate` | see all reports / change status, delete reports |
| `claims.review` + `private.view` | open private ownership answers and approve/reject claims |
| `private.view` | private contact numbers, mobile numbers, hidden distinguishing features |
| `audit.view` | activity history |
| `staff.manage` | create/disable teachers, reset their passwords |

Example: `TEACHER_PERMISSIONS=reports.view_all,students.view,audit.view` in `.env`.

## 6. Security features

| Area | Implementation |
|---|---|
| Password storage | Werkzeug scrypt hashes; legacy PBKDF2 hashes still verify and are upgraded at next login |
| Robot check | `CAPTCHA_PROVIDER=checkbox` (default) shows a single “I’m not a robot” checkbox. This is only a lightweight UI check, not a real bot-proof CAPTCHA. Existing `local`, `turnstile`, `recaptcha`, and `hcaptcha` options remain available. CSRF protection and login/IP throttling remain enabled. |
| Brute force | 5 failed logins per account → 15-minute lockout (even for the right password); per-IP throttle; CAPTCHA failures never lock an account; all configurable |
| Sessions | fresh session on login, 8 h lifetime, 30 min idle timeout, HttpOnly + SameSite cookies; `session_version` ends sessions on password change/reset, deactivation and deletion |
| CSRF | token on every POST form (`CSRF_ENABLED`) |
| Uploads | extension + file-signature check, random server-side name, only image types served, `nosniff` |
| Audit | `activity_log` is append-only (SQLite triggers reject UPDATE/DELETE); actor IDs + name/roll snapshots; never stores passwords or private answers |
| SQL | parameterised queries only; LIKE wildcards escaped; dynamic filters use fixed whitelists |
| Misc | open-redirect-safe `next`, security headers, `no-store` on logged-in pages, debug server off by default |

## 7. Database migration

Schema version 1 is applied automatically by `init_db()` (at app start and by `python manage.py migrate`).
Before touching a pre-ERP database a consistent copy is written next to it
(`findback.sqlite.pre-erp-migration-<timestamp>.bak`). The migration is transactional and idempotent. It:

* adds account columns (`username`, `roll_number`, `mobile`, `class_branch`, `academic_year`, `is_active`, `is_deleted`,
  `must_change_password`, `session_version`, timestamps) with unique indexes on roll number and username;
* adds `verified_at/by` and `returned_at/by` to `reports` (back-filled from the old status trail);
* creates `activity_log`, `login_attempts`, `captcha_challenges`, `schema_migrations`, and back-fills activity history from
  existing reports, claims and status changes;
* **keeps every existing user, report, claim and audit row.** Legacy admins get a username derived from their e-mail
  (`admin@findback.edu` → `admin`) and must change their password at next login. Legacy self-registered students have no
  roll number or mobile, so they are **kept but deactivated** until an admin completes the profile and activates them.

Students are stored with role value `user` (the historical value) and shown as "Student" in the UI.

## 8. Limitations

* Because the initial password is the mobile number the admin typed, the admin knows it **until the student's first login**
  (the forced change limits the window). Mobile numbers are masked for staff without `private.view`.
* The default single-checkbox robot check is not bot-proof; automated clients can submit it. For stronger production protection, configure Cloudflare Turnstile or another server-verified CAPTCHA provider.
* Lockout is per account identifier (an attacker who solves CAPTCHAs could temporarily lock a roll number) plus per-IP limits.
* `X-Forwarded-For` is trusted only when `TRUST_PROXY_HEADERS=1`.
* Only students file reports and claims; teachers/admins monitor and moderate.
* SQLite is kept (as before); move to PostgreSQL for many concurrent users.
* The React demo in `../src` is a standalone mock with its own seed data and is not wired to this backend.

---

## 📁 Project Structure

```
findback/
├── app.py                # Application factory, routes, and entrypoint
├── config.py             # Environment configurations and session cookies
├── models.py             # SQLite database layer, schema, and queries
├── matching.py           # Pure Python deterministic scoring engine
├── seed.py               # Pre-populated demo database runner
├── requirements.txt      # Dependencies (Flask, Werkzeug, python-dotenv)
├── .env.example          # Template for environment secrets
├── .gitignore            # Clean git configuration
├── auth/                 # User registration, login, logout, RBAC
│   ├── __init__.py
│   └── routes.py
├── reports/              # Lost & found submission, browse, smart matching
│   ├── __init__.py
│   └── routes.py
├── claims/               # Private claim submission & owner challenge
│   ├── __init__.py
│   └── routes.py
├── admin/                # Security admin dashboard, verification console
│   ├── __init__.py
│   └── routes.py
├── templates/            # Bootstrap 5 responsive templates
│   ├── base.html
│   ├── index.html
│   ├── 404.html
│   ├── 500.html
│   ├── auth/
│   ├── reports/
│   ├── claims/
│   ├── user/
│   └── admin/
├── static/               # CSS styles & client JavaScript
│   ├── css/custom.css
│   └── js/main.js
├── tests/                # Automated test suite (18 unit tests)
│   ├── test_auth.py
│   ├── test_reports.py
│   ├── test_matching.py
│   ├── test_claims_and_rbac.py
│   └── run_tests.py
└── uploads/              # Local storage for optional report photos
```

---

## 🚀 Setup & Execution Instructions

### On Windows (PowerShell)

1. **Clone or Extract Archive:**
   ```powershell
   cd FindBack_Lost_and_Found_Portal
   ```

2. **Create and Activate Python Virtual Environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Configure Environment:**
   ```powershell
   Copy-Item .env.example .env
   ```

5. **Seed Demo Data & Run Tests:**
   ```powershell
   # Run automated test suite (18 tests)
   python tests\run_tests.py

   # Seed database with demo items & credentials
   python seed.py
   ```

6. **Start the FindBack Portal:**
   ```powershell
   python app.py
   ```
   Open your browser to: `http://localhost:5000`

---

### On Linux / macOS (Bash)

1. **Activate Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

2. **Run Tests & Seed Database:**
   ```bash
   python3 tests/run_tests.py
   python3 seed.py
   ```

3. **Launch Server:**
   ```bash
   python3 app.py
   ```
   Open: `http://localhost:5000`

---


## 🛡️ Security & Privacy Guarantees

- **No SQL Injection**: 100% parameterized SQLite statements (`cur.execute(query, params)`).
- **No Password Exposure**: Passwords never logged or stored in plain-text; hashed with 100,000 PBKDF2-HMAC-SHA256 iterations and random salt.
- **No Private Contact Leakage**: Public endpoints filter out phone numbers and emails.
- **Challenge Answer Protection**: Claim verification answers are stored securely and never displayed to normal users.
- **Immutable Status Audit**: Every lifecycle shift is logged with user ID, timestamps, old status, new status, and administrative reason notes.

Additional modules: `security.py` (CSRF, CAPTCHA, RBAC, session guards), `validators.py`, `manage.py` (CLI), `tests/helpers.py`.
