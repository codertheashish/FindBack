from flask import render_template, g

import models
from . import teacher_bp
from security import staff_required, has_permission


@teacher_bp.route('/dashboard')
@staff_required
def dashboard():
    """Teacher home. Shows only what the configured permission policy allows (default: a
    read-only report overview with no private data). Admins are sent to their own console."""
    if g.user['role'] != models.ROLE_TEACHER:
        from flask import redirect, url_for
        return redirect(url_for('admin.dashboard'))
    recent = []
    if has_permission('reports.view_all'):
        recent, _ = models.query_reports_admin({}, limit=15)
    return render_template('teacher/dashboard.html', recent=recent,
                           permissions=sorted(g.perms))
