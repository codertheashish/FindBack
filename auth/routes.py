from flask import render_template, request, redirect, url_for, flash, session, current_app, g, jsonify, abort

import models
from . import auth_bp
from validators import ValidationError
from security import (  # re-exported: other blueprints (and older code) import these from here
    login_required, admin_required, permission_required, student_required, staff_required,
    client_ip, safe_next_url, verify_captcha, new_captcha_challenge, establish_session,
)

_DUMMY_HASH = None


def _dummy_verify(password):
    """Spend the same hashing time when the account does not exist (limits user enumeration)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = models.hash_password("not-a-real-password-for-timing")
    models.verify_password(_DUMMY_HASH, password)


def _forced():
    return current_app.config.get('PASSWORD_CHANGE_MODE') == 'forced'


@auth_bp.route('/captcha/new')
def captcha_new():
    """Fresh CAPTCHA image for the refresh (recycle) button — no page reload, typed fields are kept."""
    challenge = new_captcha_challenge()
    if challenge['provider'] != 'local':
        abort(404)
    resp = jsonify(token=challenge['token'], svg=challenge['svg'])
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def home_for(user):
    if user['role'] == models.ROLE_ADMIN:
        return url_for('admin.dashboard')
    if user['role'] == models.ROLE_TEACHER:
        return url_for('teacher.dashboard')
    return url_for('reports.my_dashboard')


def _render_login(portal, status=200, identifier=""):
    return render_template('auth/login.html', portal=portal, captcha=new_captcha_challenge(),
                           identifier=identifier), status


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Self-registration is intentionally disabled: accounts are created by administrators.
    flash('Student accounts are created by the college administrator. Sign in with your roll number.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if g.user and not g.user['must_change_password']:
        return redirect(home_for(g.user))

    portal = request.values.get('portal', 'student')
    portal = portal if portal in ('student', 'staff') else 'student'

    if request.method != 'POST':
        return _render_login(portal)

    cfg = current_app.config
    identifier = (request.form.get('username') or '').strip()[:64]
    password = request.form.get('password') or ''
    ip = client_ip()
    lock_key = f"{portal}:{identifier.lower()}"

    # 1) Temporary lockout / IP throttle — checked before doing any credential work.
    locked, retry = models.login_lock_status(
        lock_key, ip, cfg['LOGIN_MAX_FAILURES'], cfg['LOGIN_LOCKOUT_SECONDS'],
        cfg['LOGIN_IP_MAX_FAILURES'], cfg['LOGIN_WINDOW_SECONDS'])
    if locked:
        minutes = max(1, (retry + 59) // 60)
        flash(f'Too many failed sign-in attempts. Please try again in about {minutes} minute(s).', 'danger')
        return _render_login(portal, 429, identifier)

    # 2) CAPTCHA is verified server-side. A wrong CAPTCHA counts against the IP only, so nobody can
    #    lock a victim's account without also solving CAPTCHAs.
    if not verify_captcha(request.form):
        models.record_login_attempt('(captcha)', ip, False, portal)
        flash('The CAPTCHA was incorrect or expired. Please try again.', 'danger')
        return _render_login(portal, 400, identifier)

    if not identifier or not password:
        flash('Please enter your credentials.', 'danger')
        return _render_login(portal, 400, identifier)

    # 3) Credentials
    if portal == 'student':
        user = models.get_student_by_roll(identifier)
    else:
        user = models.get_staff_by_username(identifier)

    if user:
        password_ok = models.verify_password(user['password_hash'], password)
    else:
        _dummy_verify(password)
        password_ok = False

    if not password_ok:
        models.record_login_attempt(lock_key, ip, False, portal)
        locked_now, _ = models.login_lock_status(
            lock_key, ip, cfg['LOGIN_MAX_FAILURES'], cfg['LOGIN_LOCKOUT_SECONDS'],
            cfg['LOGIN_IP_MAX_FAILURES'], cfg['LOGIN_WINDOW_SECONDS'])
        if locked_now and user:
            models.log_activity('auth.lockout', None, entity_type='user', entity_id=user['id'],
                                target_user_id=user['id'], ip=ip,
                                details=f"Temporary lockout after repeated failed sign-ins ({portal} portal).")
        flash('Invalid username or password.', 'danger')
        return _render_login(portal, 401, identifier)

    if not user['is_active'] or user['is_deleted']:
        models.record_login_attempt(lock_key, ip, False, portal)
        flash('This account is disabled. Please contact the administrator.', 'danger')
        return _render_login(portal, 403, identifier)

    # 4) Success
    models.record_login_attempt(lock_key, ip, True, portal)
    models.rehash_password_if_needed(user['id'], password)
    establish_session(user)
    models.log_activity('auth.login', user['id'], entity_type='user', entity_id=user['id'],
                        target_user_id=user['id'], ip=ip, details=f"Signed in via {portal} portal.")

    if user['must_change_password']:
        if _forced():
            flash('Welcome! For your security you must set a new password before continuing.', 'warning')
        else:
            flash('Welcome! You are using your initial password. You can change it now or skip for later.', 'info')
        return redirect(url_for('auth.change_password'))

    flash(f"Welcome back, {user['name']}!", 'success')
    return redirect(safe_next_url(request.args.get('next')) or home_for(user))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = g.user
    forced = bool(user['must_change_password']) and _forced()
    pending = bool(user['must_change_password'])
    if request.method == 'POST':
        cfg = current_app.config
        current_pw = request.form.get('current_password') or ''
        new_pw = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''
        key = f"chpw:{user['id']}"

        locked, retry = models.login_lock_status(
            key, None, cfg['LOGIN_MAX_FAILURES'], cfg['LOGIN_LOCKOUT_SECONDS'], 10**9, 1)
        if locked:
            flash('Too many incorrect attempts. Please wait a few minutes and try again.', 'danger')
            return render_template('auth/change_password.html', forced=forced, pending=pending, skip_url=home_for(user)), 429
        if new_pw != confirm:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('auth/change_password.html', forced=forced, pending=pending, skip_url=home_for(user)), 400
        try:
            new_version = models.change_password(user['id'], current_pw, new_pw,
                                                 min_length=cfg['PASSWORD_MIN_LENGTH'])
        except ValidationError as exc:
            if 'Current password is incorrect.' in exc.errors:
                models.record_login_attempt(key, None, False, 'change-password')
            for msg in exc.errors:
                flash(msg, 'danger')
            return render_template('auth/change_password.html', forced=forced, pending=pending, skip_url=home_for(user)), 400

        # All other sessions died with the session_version bump; keep this one alive.
        refreshed = models.get_user_by_id(user['id'])
        establish_session(refreshed)
        flash('Your password has been changed. Other devices have been signed out.', 'success')
        return redirect(home_for(refreshed))
    return render_template('auth/change_password.html', forced=forced, pending=pending, skip_url=home_for(user))


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out safely.', 'info')
    return redirect(url_for('auth.login'))
