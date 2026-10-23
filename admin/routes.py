import json
import math
import re
from flask import render_template, request, redirect, url_for, flash, abort, g, current_app

import models
from . import admin_bp
from security import admin_required, permission_required, has_permission
from validators import ValidationError
from matching import find_matches_for_report
from models import (
    get_db, get_reports, get_report_by_id, update_report_status,
    get_claim_by_id, review_claim, WORKFLOW_STATUSES,
)

DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
ACTIVITY_LABELS = dict(models.ACTIVITY_ACTIONS)


# ------------------------------------------------------------------ helpers
def _page_args():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    size = current_app.config.get('ADMIN_PAGE_SIZE', 25)
    return page, size, (page - 1) * size


def _pager(page, size, total):
    return {'page': page, 'pages': max(1, math.ceil(total / size)), 'total': total}


def _date_arg(name):
    value = (request.args.get(name) or '').strip()
    return value if DATE_RE.match(value) else ''


def _categories():
    from reports.routes import CATEGORIES
    return CATEGORIES


def _recheck_admin_password(password):
    """Re-authentication for sensitive actions (throttled like a login)."""
    cfg = current_app.config
    key = f"reauth:{g.user['id']}"
    locked, _ = models.login_lock_status(key, None, cfg['LOGIN_MAX_FAILURES'], cfg['LOGIN_LOCKOUT_SECONDS'], 10**9, 1)
    if locked:
        raise ValidationError("Too many incorrect confirmations. Please wait a few minutes.")
    if not models.verify_password(g.user['password_hash'], password or ''):
        models.record_login_attempt(key, None, False, 'reauth')
        raise ValidationError("Your administrator password was incorrect.")


# ------------------------------------------------------------------ dashboard
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    try:
        counts = {
            'total_lost': "SELECT COUNT(*) FROM reports WHERE report_type = 'lost'",
            'total_found': "SELECT COUNT(*) FROM reports WHERE report_type = 'found'",
            'pending_claims': "SELECT COUNT(*) FROM claims WHERE status = 'Pending'",
            'matched_items': "SELECT COUNT(*) FROM reports WHERE status = 'Potential Match'",
            'returned_items': "SELECT COUNT(*) FROM reports WHERE status = 'Returned'",
            'closed_items': "SELECT COUNT(*) FROM reports WHERE status = 'Closed'",
            'active_students': "SELECT COUNT(*) FROM users WHERE role='user' AND is_active=1 AND is_deleted=0",
        }
        metrics = {k: cur.execute(sql).fetchone()[0] for k, sql in counts.items()}

        cur.execute('''
            SELECT c.id, c.created_at, c.claimant_contact, c.status,
                   u.name as claimant_name, u.roll_number as claimant_roll,
                   r.item_name, r.category, r.status as report_status
            FROM claims c
            JOIN users u ON c.claimant_id = u.id
            JOIN reports r ON c.report_id = r.id
            WHERE c.status = 'Pending'
            ORDER BY c.created_at ASC
        ''')
        pending_claims = [dict(r) for r in cur.fetchall()]

        cur.execute('''
            SELECT r.*, u.name as reporter_name, u.roll_number as reporter_roll
            FROM reports r JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC LIMIT 10
        ''')
        recent_reports = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    recent_activity, _ = models.query_activity(limit=10)

    return render_template(
        'admin/dashboard.html',
        metrics=metrics,
        pending_claims=pending_claims,
        recent_reports=recent_reports,
        recent_activity=recent_activity,
        action_labels=ACTIVITY_LABELS,
        statuses=WORKFLOW_STATUSES
    )


# ------------------------------------------------------------------ claims
@admin_bp.route('/claims/<int:claim_id>', methods=['GET', 'POST'])
@permission_required('claims.review', 'private.view')
def review_claim_detail(claim_id):
    claim = get_claim_by_id(claim_id)
    if not claim:
        abort(404)

    report = get_report_by_id(claim['report_id'])

    try:
        challenge_answers = json.loads(claim['challenge_answers'])
    except Exception:
        challenge_answers = {"raw": claim['challenge_answers']}

    if request.method == 'POST':
        action = request.form.get('action')  # 'Approved' or 'Rejected'
        notes = (request.form.get('notes') or '').strip()[:1000]

        if action not in ('Approved', 'Rejected'):
            flash('Invalid review decision.', 'danger')
            return redirect(url_for('admin.review_claim_detail', claim_id=claim_id))

        success = review_claim(
            claim_id=claim_id,
            reviewer_id=g.user['id'],
            action=action,
            notes=notes
        )

        if success:
            if action == 'Approved':
                flash(f"Claim #{claim_id} Approved! Item marked as 'Verified' for return handover.", 'success')
            else:
                flash(f"Claim #{claim_id} Rejected.", 'info')
            return redirect(url_for('admin.dashboard'))
        flash('This claim has already been reviewed or could not be processed.', 'danger')
        return redirect(url_for('admin.dashboard'))

    return render_template(
        'admin/claim_review.html',
        claim=claim,
        report=report,
        challenge_answers=challenge_answers
    )


# ------------------------------------------------------------------ report moderation
@admin_bp.route('/reports/<int:report_id>/status', methods=['POST'])
@permission_required('reports.moderate')
def update_status(report_id):
    new_status = request.form.get('status')
    notes = (request.form.get('notes') or '').strip()[:500]

    if new_status not in WORKFLOW_STATUSES:
        flash('Invalid status choice.', 'danger')
        return redirect(url_for('reports.detail', report_id=report_id))

    success = update_report_status(
        report_id=report_id,
        new_status=new_status,
        changed_by=g.user['id'],
        notes=notes or f"Manual status transition by {g.user['name']} to {new_status}"
    )

    if success:
        flash(f'Report status successfully transitioned to {new_status}.', 'success')
    else:
        flash('Could not update report status.', 'danger')

    return redirect(request.form.get('back') if (request.form.get('back') or '').startswith('/admin/')
                    else url_for('reports.detail', report_id=report_id))


@admin_bp.route('/reports/<int:report_id>/delete', methods=['POST'])
@permission_required('reports.moderate')
def delete_report(report_id):
    if models.delete_report(report_id, g.user['id']):
        flash(f'Report #{report_id} has been moderated and removed. The removal is kept in the activity history.', 'info')
    else:
        flash('Report not found.', 'warning')
    return redirect(url_for('admin.dashboard'))


# ------------------------------------------------------------------ lost/found monitoring
@admin_bp.route('/reports')
@permission_required('reports.view_all')
def reports_monitor():
    page, size, offset = _page_args()
    filters = {
        'report_type': request.args.get('type', ''),
        'category': request.args.get('category', 'All'),
        'status': request.args.get('status', 'All'),
        'roll': (request.args.get('roll') or '').strip()[:40],
        'q': (request.args.get('q') or '').strip()[:100],
        'date_from': _date_arg('date_from'),
        'date_to': _date_arg('date_to'),
    }
    rows, total = models.query_reports_admin(filters, limit=size, offset=offset)

    # Real matching engine results for the rows on this page (no invented scores).
    pools = {}
    for row in rows:
        opposing = 'found' if row['report_type'] == 'lost' else 'lost'
        if opposing not in pools:
            pools[opposing] = get_reports(report_type=opposing, limit=300)
        matches = find_matches_for_report(row, pools[opposing], min_score=50)
        row['match_count'] = len(matches)
        row['top_match'] = matches[0] if matches else None
        row['is_verified'] = bool(row.get('verified_at')) or row['status'] in ('Verified', 'Returned')
        row['is_returned'] = bool(row.get('returned_at')) or row['status'] == 'Returned'

    return render_template(
        'admin/reports.html', rows=rows, filters=filters, categories=_categories(),
        statuses=WORKFLOW_STATUSES, pager=_pager(page, size, total),
        can_private=has_permission('private.view'))


# ------------------------------------------------------------------ activity history
@admin_bp.route('/activity')
@permission_required('audit.view')
def activity():
    page, size, offset = _page_args()
    filters = {
        'report_type': request.args.get('type', ''),
        'category': request.args.get('category', 'All'),
        'status': request.args.get('status', 'All'),
        'roll': (request.args.get('roll') or '').strip()[:40],
        'action': request.args.get('action', ''),
        'q': (request.args.get('q') or '').strip()[:100],
        'date_from': _date_arg('date_from'),
        'date_to': _date_arg('date_to'),
    }
    if filters['action'] not in ACTIVITY_LABELS:
        filters['action'] = ''
    rows, total = models.query_activity(filters, limit=size, offset=offset)
    return render_template(
        'admin/activity.html', rows=rows, filters=filters, categories=_categories(),
        statuses=WORKFLOW_STATUSES, actions=models.ACTIVITY_ACTIONS, labels=ACTIVITY_LABELS,
        pager=_pager(page, size, total))


# ------------------------------------------------------------------ student management
@admin_bp.route('/students')
@permission_required('students.view')
def students():
    page, size, offset = _page_args()
    q = (request.args.get('q') or '').strip()[:60]
    status = request.args.get('status', '')
    rows, total = models.list_students(q=q, status=status, limit=size, offset=offset)
    return render_template('admin/students.html', rows=rows, q=q, status=status,
                           pager=_pager(page, size, total), can_private=has_permission('private.view'))


@admin_bp.route('/students/new', methods=['GET', 'POST'])
@permission_required('students.manage')
def student_new():
    cfg = current_app.config
    if request.method == 'POST':
        try:
            sid = models.create_student(
                request.form.get('roll_number'), request.form.get('name'), request.form.get('mobile'),
                request.form.get('class_branch'), request.form.get('academic_year'),
                created_by=g.user['id'], roll_regex=cfg['ROLL_NUMBER_REGEX'], mobile_regex=cfg['MOBILE_REGEX'])
        except ValidationError as exc:
            for msg in exc.errors:
                flash(msg, 'danger')
            return render_template('admin/student_form.html', student=None, form=request.form), 400
        flash('Student account created. The registered mobile number is the initial password; '
              'the student must change it at first login.', 'success')
        return redirect(url_for('admin.student_detail', student_id=sid))
    return render_template('admin/student_form.html', student=None, form={})


def _get_student_or_404(student_id):
    s = models.get_user_by_id(student_id)
    if not s or s['role'] != models.ROLE_STUDENT:
        abort(404)
    return s


@admin_bp.route('/students/<int:student_id>')
@permission_required('students.view')
def student_detail(student_id):
    student = _get_student_or_404(student_id)
    history = models.get_student_history(student_id)
    activity_rows, _ = models.query_activity({'roll': student['roll_number']} if student['roll_number'] else {}, limit=15) \
        if has_permission('audit.view') else ([], 0)
    resetter = models.get_user_by_id(student['password_reset_by']) if student['password_reset_by'] else None
    return render_template('admin/student_detail.html', student=student, history=history,
                           activity_rows=activity_rows, labels=ACTIVITY_LABELS, resetter=resetter,
                           can_private=has_permission('private.view'),
                           reauth=current_app.config.get('RESET_REQUIRE_REAUTH'))


@admin_bp.route('/students/<int:student_id>/edit', methods=['GET', 'POST'])
@permission_required('students.manage')
def student_edit(student_id):
    student = _get_student_or_404(student_id)
    cfg = current_app.config
    if request.method == 'POST':
        try:
            changed = models.update_student(
                student_id, {k: request.form.get(k, '') for k in
                             ('roll_number', 'name', 'mobile', 'class_branch', 'academic_year')},
                g.user['id'], roll_regex=cfg['ROLL_NUMBER_REGEX'], mobile_regex=cfg['MOBILE_REGEX'])
        except ValidationError as exc:
            for msg in exc.errors:
                flash(msg, 'danger')
            return render_template('admin/student_form.html', student=student, form=request.form), 400
        if 'mobile' in changed:
            flash('Mobile number updated. This does not change the current password; '
                  'use "Reset password" if the student needs the initial password re-applied.', 'info')
        flash('Student details saved.' if changed else 'No changes were made.', 'success' if changed else 'info')
        return redirect(url_for('admin.student_detail', student_id=student_id))
    return render_template('admin/student_form.html', student=student, form=student)


@admin_bp.route('/students/<int:student_id>/toggle-active', methods=['POST'])
@permission_required('students.manage')
def student_toggle_active(student_id):
    student = _get_student_or_404(student_id)
    want_active = request.form.get('active') == '1'
    try:
        models.set_user_active(student_id, want_active, g.user['id'])
        flash(f"Account {'activated' if want_active else 'deactivated'}.", 'success')
    except ValidationError as exc:
        flash(exc.errors[0], 'danger')
    return redirect(url_for('admin.student_detail', student_id=student['id']))


@admin_bp.route('/students/<int:student_id>/reset-password', methods=['POST'])
@permission_required('students.reset_password')
def student_reset_password(student_id):
    """Forgotten password: works without knowing the current password and never touches the
    student's reports, claims or history. Empty new password = back to the registered mobile."""
    student = _get_student_or_404(student_id)
    cfg = current_app.config
    try:
        if cfg.get('RESET_REQUIRE_REAUTH'):
            _recheck_admin_password(request.form.get('admin_password'))
        models.reset_student_password(
            student_id, g.user['id'], request.form.get('reason'),
            new_password=(request.form.get('new_password') or '').strip() or None,
            min_length=cfg['PASSWORD_MIN_LENGTH'])
        flash('Password reset done. Tell the student to sign in with the new password '
              '(or their registered mobile number if you left it empty). Their data is untouched.', 'success')
    except ValidationError as exc:
        for msg in exc.errors:
            flash(msg, 'danger')
    return redirect(url_for('admin.student_detail', student_id=student['id']))


@admin_bp.route('/students/<int:student_id>/delete', methods=['POST'])
@permission_required('students.manage')
def student_delete(student_id):
    student = _get_student_or_404(student_id)
    try:
        if (request.form.get('confirm_roll') or '').strip().upper() != (student['roll_number'] or '-'):
            raise ValidationError("Type the student's roll number exactly to confirm deletion.")
        result = models.delete_student(student_id, g.user['id'])
    except ValidationError as exc:
        for msg in exc.errors:
            flash(msg, 'danger')
        return redirect(url_for('admin.student_detail', student_id=student_id))
    if result == 'deleted':
        flash('Account permanently deleted (it had no report history).', 'info')
        return redirect(url_for('admin.students'))
    flash('This student has report history, so the account was deactivated and archived (soft-deleted) '
          'instead of being erased. Reports and audit history are preserved.', 'info')
    return redirect(url_for('admin.students', status='deleted'))


@admin_bp.route('/students/<int:student_id>/restore', methods=['POST'])
@permission_required('students.manage')
def student_restore(student_id):
    _get_student_or_404(student_id)
    try:
        models.restore_student(student_id, g.user['id'])
        flash('Account restored but left deactivated. Review it, then activate.', 'success')
    except ValidationError as exc:
        flash(exc.errors[0], 'danger')
    return redirect(url_for('admin.student_detail', student_id=student_id))


# ------------------------------------------------------------------ staff (teacher) accounts
@admin_bp.route('/staff', methods=['GET', 'POST'])
@permission_required('staff.manage')
def staff():
    if request.method == 'POST':
        try:
            models.create_staff(request.form.get('username'), request.form.get('name'), models.ROLE_TEACHER,
                                request.form.get('temp_password'), created_by=g.user['id'],
                                min_length=current_app.config['PASSWORD_MIN_LENGTH'])
            flash('Teacher account created. They must change the temporary password at first login.', 'success')
            return redirect(url_for('admin.staff'))
        except ValidationError as exc:
            for msg in exc.errors:
                flash(msg, 'danger')
    return render_template('admin/staff.html', staff=models.list_staff(),
                           teacher_permissions=sorted(current_app.config['TEACHER_PERMISSIONS']))


@admin_bp.route('/staff/<int:staff_id>/toggle-active', methods=['POST'])
@permission_required('staff.manage')
def staff_toggle_active(staff_id):
    target = models.get_user_by_id(staff_id)
    if not target or target['role'] not in (models.ROLE_ADMIN, models.ROLE_TEACHER):
        abort(404)
    try:
        models.set_user_active(staff_id, request.form.get('active') == '1', g.user['id'])
        flash('Staff account updated.', 'success')
    except ValidationError as exc:
        flash(exc.errors[0], 'danger')
    return redirect(url_for('admin.staff'))


@admin_bp.route('/staff/<int:staff_id>/reset-password', methods=['POST'])
@permission_required('staff.manage')
def staff_reset_password(staff_id):
    try:
        _recheck_admin_password(request.form.get('admin_password'))
        models.reset_staff_password(staff_id, g.user['id'], request.form.get('temp_password'),
                                    min_length=current_app.config['PASSWORD_MIN_LENGTH'])
        flash('Temporary password issued. The teacher must change it at next login.', 'success')
    except ValidationError as exc:
        for msg in exc.errors:
            flash(msg, 'danger')
    return redirect(url_for('admin.staff'))
