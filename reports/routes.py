import os
import uuid
from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, current_app, abort, g

from . import reports_bp
from security import login_required, student_required, has_permission
import models
from models import (
    create_report, get_report_by_id, get_reports, get_db, get_audit_logs,
    get_claims_for_report, update_report_fields,
)
from matching import find_matches_for_report, calculate_match
from validators import validate_report_form, sniff_image_type

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
CATEGORIES = [
    'Electronics',
    'Wallets & Bags',
    'ID & Cards',
    'Keys',
    'Clothing & Apparel',
    'Books & Stationery',
    'Jewelry & Watches',
    'Bottles & Flasks',
    'Other'
]
ACTIVE_STATUSES = ('Open', 'Potential Match', 'Claim Pending')
EDITABLE_STATUSES = ('Open', 'Potential Match')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_image(file):
    """Validate by extension AND file signature; store under a random name with the detected type.
    Returns (stored_filename | None, error_message | None)."""
    if not file or not file.filename:
        return None, None
    if not allowed_file(file.filename):
        return None, 'Invalid image format. Allowed: PNG, JPG, JPEG, WEBP.'
    head = file.stream.read(16)
    file.stream.seek(0)
    kind = sniff_image_type(head)
    claimed = file.filename.rsplit('.', 1)[1].lower()
    claimed = 'jpg' if claimed == 'jpeg' else claimed
    if kind is None or kind != claimed:
        return None, 'The uploaded file is not a valid image of the type its name claims.'
    unique_name = f"{uuid.uuid4().hex}.{kind}"
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file.save(os.path.join(upload_dir, unique_name))
    return unique_name, None


@reports_bp.route('/browse')
def browse():
    report_type = request.args.get('type')  # 'lost', 'found', or None
    if report_type not in ('lost', 'found'):
        report_type = None
    category = request.args.get('category', 'All')
    location = request.args.get('location', '')[:100]
    keyword = request.args.get('q', '')[:100]
    status = request.args.get('status', 'All')

    reports = get_reports(
        report_type=report_type,
        category=category,
        location=location,
        keyword=keyword,
        status=status,
        limit=50
    )

    return render_template(
        'reports/browse.html',
        reports=reports,
        categories=CATEGORIES,
        selected_type=report_type,
        selected_category=category,
        location=location,
        keyword=keyword,
        selected_status=status
    )


def _handle_new_report(report_type):
    template = f'reports/report_{report_type}.html'
    today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    if request.method == 'POST':
        cleaned, errors = validate_report_form(
            request.form, CATEGORIES, 'Date lost' if report_type == 'lost' else 'Date found')

        image_filename = None
        if not errors:
            file = request.files.get('image')
            image_filename, img_err = save_uploaded_image(file)
            if img_err:
                errors.append(img_err)

        if errors:
            for msg in errors:
                flash(msg, 'danger')
            return render_template(template, categories=CATEGORIES, form=request.form, today_str=today_str), 400

        # The reporter is ALWAYS the authenticated student; any user id in the form is ignored.
        report_id = create_report(
            user_id=g.user['id'],
            report_type=report_type,
            image_filename=image_filename,
            **cleaned
        )
        if report_type == 'lost':
            flash('Your lost item report has been published. Smart matching has analyzed potential finds!', 'success')
            return redirect(url_for('reports.view_matches', report_id=report_id))
        flash('Thank you for reporting this found item! The distinguishing features will be kept confidential for ownership verification.', 'success')
        return redirect(url_for('reports.detail', report_id=report_id))
    return render_template(template, categories=CATEGORIES, today_str=today_str)


@reports_bp.route('/lost/new', methods=['GET', 'POST'])
@student_required
def report_lost():
    return _handle_new_report('lost')


@reports_bp.route('/found/new', methods=['GET', 'POST'])
@student_required
def report_found():
    return _handle_new_report('found')


@reports_bp.route('/<int:report_id>/edit', methods=['GET', 'POST'])
@student_required
def edit_report(report_id):
    report = get_report_by_id(report_id)
    if not report:
        abort(404)
    if report['user_id'] != g.user['id']:
        abort(403)                                  # never edit someone else's report
    if report['status'] not in EDITABLE_STATUSES:
        flash('This report can no longer be edited because a claim or return is already in progress.', 'warning')
        return redirect(url_for('reports.detail', report_id=report_id))

    if request.method == 'POST':
        cleaned, errors = validate_report_form(
            request.form, CATEGORIES, 'Date lost' if report['report_type'] == 'lost' else 'Date found')
        if errors:
            for msg in errors:
                flash(msg, 'danger')
            return render_template('reports/edit_report.html', report=report, categories=CATEGORIES,
                                   form=request.form), 400
        changed = update_report_fields(report_id, g.user['id'], cleaned)
        flash('Report updated.' if changed else 'No changes were made.', 'success' if changed else 'info')
        return redirect(url_for('reports.detail', report_id=report_id))
    return render_template('reports/edit_report.html', report=report, categories=CATEGORIES, form=report)


@reports_bp.route('/<int:report_id>')
def detail(report_id):
    report = get_report_by_id(report_id)
    if not report:
        abort(404)

    user = g.user
    is_owner = bool(user) and user['id'] == report['user_id']
    can_private = has_permission('private.view')
    can_view_all = has_permission('reports.view_all')

    # Privacy filtering:
    # 1. Distinguishing features on FOUND items are never shown publicly — only to the finder or
    #    explicitly authorised staff — to prevent fraudulent claims.
    hide_secret_features = (report['report_type'] == 'found') and not (is_owner or can_private)
    # 2. Private contact details are only for the owner or staff holding 'private.view'.
    hide_private_contact = not (is_owner or can_private)

    audit_trail = get_audit_logs(report_id) if (is_owner or has_permission('audit.view')) else []
    claim_history = get_claims_for_report(report_id) if can_view_all else []

    staff_matches = []
    if can_view_all:
        opposing = 'found' if report['report_type'] == 'lost' else 'lost'
        staff_matches = find_matches_for_report(report, get_reports(report_type=opposing, limit=200), min_score=25)[:8]

    return render_template(
        'reports/detail.html',
        report=report,
        is_owner=is_owner,
        can_moderate=has_permission('reports.moderate'),
        can_view_all=can_view_all,
        can_edit=is_owner and report['status'] in EDITABLE_STATUSES and user['role'] == models.ROLE_STUDENT,
        hide_secret_features=hide_secret_features,
        hide_private_contact=hide_private_contact,
        audit_trail=audit_trail,
        claim_history=claim_history,
        staff_matches=staff_matches,
        workflow_statuses=models.WORKFLOW_STATUSES,
    )


@reports_bp.route('/<int:report_id>/matches')
@login_required
def view_matches(report_id):
    target = get_report_by_id(report_id)
    if not target:
        abort(404)
    # Only the report's owner (or staff allowed to see every report) may run its match view.
    if target['user_id'] != g.user['id'] and not has_permission('reports.view_all'):
        abort(403)

    # If it is a lost item, find matching found items; and vice versa
    opposing_type = 'found' if target['report_type'] == 'lost' else 'lost'
    candidates = get_reports(report_type=opposing_type, limit=100)

    matches = find_matches_for_report(target, candidates, min_score=25)

    return render_template(
        'reports/matches.html',
        target=target,
        matches=matches
    )


def _possible_matches_for_student(user_id, min_score=50, per_report=3, max_reports=10):
    """Real deterministic matching (matching.py) of this student's open reports against other
    students' active reports of the opposite type — no fabricated scores."""
    mine = [r for r in get_reports(user_id=user_id, limit=100) if r['status'] in ACTIVE_STATUSES][:max_reports]
    pool = {
        'found': [r for r in get_reports(report_type='found', exclude_user_id=user_id, limit=300)
                  if r['status'] in ACTIVE_STATUSES],
        'lost': [r for r in get_reports(report_type='lost', exclude_user_id=user_id, limit=300)
                 if r['status'] in ACTIVE_STATUSES],
    }
    out = []
    for rep in mine:
        opposing = 'found' if rep['report_type'] == 'lost' else 'lost'
        found = find_matches_for_report(rep, pool[opposing], min_score=min_score)[:per_report]
        if found:
            out.append({'report': rep, 'matches': found})
    return out


@reports_bp.route('/my-dashboard')
@student_required
def my_dashboard():
    user_id = g.user['id']
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM reports WHERE user_id = ? AND report_type = 'lost' ORDER BY created_at DESC", (user_id,))
        my_lost = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT * FROM reports WHERE user_id = ? AND report_type = 'found' ORDER BY created_at DESC", (user_id,))
        my_found = [dict(r) for r in cur.fetchall()]

        cur.execute('''
            SELECT c.id, c.status, c.created_at, c.reviewed_at, c.verification_notes, c.report_id,
                   r.item_name, r.category, r.location, r.status as report_status, r.returned_at
            FROM claims c
            JOIN reports r ON c.report_id = r.id
            WHERE c.claimant_id = ?
            ORDER BY c.created_at DESC
        ''', (user_id,))
        my_claims = [dict(r) for r in cur.fetchall()]

        # Claims filed on items *I* found: status only — never the claimant's identity or answers.
        cur.execute('''
            SELECT c.id, c.status, c.created_at, r.id AS report_id, r.item_name, r.status AS report_status
            FROM claims c JOIN reports r ON c.report_id = r.id
            WHERE r.user_id = ? ORDER BY c.created_at DESC
        ''', (user_id,))
        claims_on_my_found = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    return render_template(
        'user/dashboard.html',
        profile=g.user,
        my_lost=my_lost,
        my_found=my_found,
        my_claims=my_claims,
        claims_on_my_found=claims_on_my_found,
        possible_matches=_possible_matches_for_student(user_id),
    )
