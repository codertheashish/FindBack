import json
from flask import render_template, request, redirect, url_for, flash, abort, g
from . import claims_bp
from security import student_required, login_required, has_permission
from models import get_report_by_id, create_claim, get_claim_by_id, has_pending_claim
from validators import clean_text, ValidationError


@claims_bp.route('/submit/<int:report_id>', methods=['GET', 'POST'])
@student_required
def submit_claim(report_id):
    report = get_report_by_id(report_id)
    if not report:
        abort(404)

    # Can only claim a found item, or an item that has not been returned
    if report['report_type'] != 'found':
        flash('Claims can only be filed against Found item reports.', 'warning')
        return redirect(url_for('reports.detail', report_id=report_id))

    if report['status'] in ('Returned', 'Closed'):
        flash('This item has already been returned or closed.', 'info')
        return redirect(url_for('reports.detail', report_id=report_id))

    # User cannot claim their own reported found item
    if report['user_id'] == g.user['id']:
        flash('You reported this item as found; you cannot claim ownership of it.', 'warning')
        return redirect(url_for('reports.detail', report_id=report_id))

    if has_pending_claim(report_id, g.user['id']):
        flash('You already have a claim under review for this item.', 'info')
        return redirect(url_for('reports.my_dashboard'))

    if request.method == 'POST':
        try:
            distinguishing_proof = clean_text(request.form.get('distinguishing_proof'), 1500, 'Distinguishing proof', multiline=True)
            contents_proof = clean_text(request.form.get('contents_proof'), 1000, 'Contents details', multiline=True)
            custom_marks = clean_text(request.form.get('custom_marks'), 1000, 'Marks / serial number', multiline=True)
            loss_context = clean_text(request.form.get('loss_context'), 1000, 'Loss circumstances', multiline=True)
            contact_phone = clean_text(request.form.get('contact_phone'), 100, 'Contact number')
        except ValidationError as exc:
            for msg in exc.errors:
                flash(msg, 'danger')
            return render_template('claims/submit_claim.html', report=report, form=request.form), 400

        if not distinguishing_proof or not contact_phone:
            flash('Please answer the key verification question and provide your contact number.', 'danger')
            return render_template('claims/submit_claim.html', report=report, form=request.form), 400

        # Structure confidential verification answers
        challenge_payload = {
            "distinguishing_proof": distinguishing_proof,
            "contents_or_pouch_details": contents_proof or "Not specified",
            "marks_or_serial_number": custom_marks or "Not specified",
            "loss_circumstances": loss_context or "Not specified"
        }

        challenge_answers_json = json.dumps(challenge_payload, indent=2)

        create_claim(
            report_id=report_id,
            claimant_id=g.user['id'],            # from the authenticated session, never from the form
            challenge_answers=challenge_answers_json,
            claimant_contact=contact_phone
        )

        flash(
            'Your private ownership claim has been submitted! Our security admins will inspect your confidential proof against the item before approving.',
            'success'
        )
        return redirect(url_for('reports.my_dashboard'))

    return render_template('claims/submit_claim.html', report=report)


@claims_bp.route('/view/<int:claim_id>')
@login_required
def view_claim(claim_id):
    claim = get_claim_by_id(claim_id)
    if not claim:
        abort(404)

    is_claimant = (g.user['id'] == claim['claimant_id'])
    can_see_private = has_permission('private.view') and has_permission('claims.review')

    # Strictly protect private challenge answers: only the claimant or explicitly authorised staff.
    if not (is_claimant or can_see_private):
        abort(403)

    try:
        answers = json.loads(claim['challenge_answers'])
    except Exception:
        answers = {"raw": claim['challenge_answers']}

    return render_template(
        'claims/claim_view.html',
        claim=claim,
        answers=answers,
        is_admin=can_see_private,
        is_claimant=is_claimant
    )
