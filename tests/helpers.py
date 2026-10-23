"""Shared test fixtures: an isolated Flask app + SQLite DB per test (never touches the real DB)."""
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import models
import security
from app import create_app

ADMIN_PW = "AdminPass123!"
TEACHER_PW = "TeacherPass123!"
MOBILE_A = "9876543210"
MOBILE_B = "9123456780"


class AppTestCase(unittest.TestCase):
    csrf = False
    captcha = "disabled"
    extra_config = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="findback-test-")
        cfg = {
            "TESTING": True,
            "DATABASE": os.path.join(self.tmp, "test.sqlite"),
            "UPLOAD_FOLDER": os.path.join(self.tmp, "uploads"),
            "CSRF_ENABLED": self.csrf,
            "CAPTCHA_PROVIDER": self.captcha,
            "SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
            "SESSION_IDLE_TIMEOUT": 1800,
            "PASSWORD_CHANGE_MODE": "forced",     # most tests exercise the strict mode; optional mode has its own tests
        }
        cfg.update(self.extra_config)
        self.app = create_app(cfg)
        self.db = cfg["DATABASE"]
        self.admin_id = models.create_staff("admin1", "Admin One", models.ROLE_ADMIN, ADMIN_PW, db_path=self.db)
        self.teacher_id = models.create_staff("teach1", "Teacher One", models.ROLE_TEACHER, TEACHER_PW,
                                              created_by=self.admin_id, db_path=self.db)
        # teachers' temp password must be changed; clear the flag for tests that are not about it
        self._clear_force(self.teacher_id)
        self.sid_a = models.create_student("21CS001", "Asha Rao", MOBILE_A, "B.Tech CSE", "2nd Year",
                                           self.admin_id, self.db)
        self.sid_b = models.create_student("21CS002", "Bilal Khan", MOBILE_B, "B.Tech CSE", "2nd Year",
                                           self.admin_id, self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers
    def _clear_force(self, user_id):
        conn = models.get_db(self.db)
        conn.execute("UPDATE users SET must_change_password=0 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

    def settle_student(self, sid, password="NewPass12345"):
        """Skip the forced password change for a student (set a real password)."""
        conn = models.get_db(self.db)
        conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                     (models.hash_password(password), sid))
        conn.commit()
        conn.close()

    def login(self, client, username, password, portal="student", extra=None):
        data = {"username": username, "password": password, "portal": portal}
        if extra:
            data.update(extra)
        return client.post(f"/auth/login?portal={portal}", data=data)

    def student_client(self, roll="21CS001", sid=None, password="NewPass12345"):
        sid = sid or (self.sid_a if roll == "21CS001" else self.sid_b)
        self.settle_student(sid, password)
        c = self.app.test_client()
        r = self.login(c, roll, password)
        assert r.status_code == 302, r.status_code
        return c

    def admin_client(self):
        c = self.app.test_client()
        r = self.login(c, "admin1", ADMIN_PW, "staff")
        assert r.status_code == 302, r.status_code
        return c

    def teacher_client(self):
        c = self.app.test_client()
        r = self.login(c, "teach1", TEACHER_PW, "staff")
        assert r.status_code == 302, r.status_code
        return c

    def report_form(self, **over):
        form = {"item_name": "Blue Water Bottle", "category": "Bottles & Flasks",
                "description": "Cobalt blue steel bottle with dent", "date_occurred": "2026-10-20",
                "location": "Library 2nd Floor", "distinguishing_features": "Sticker of a mountain",
                "private_contact": "9876543210"}
        form.update(over)
        return form

    def row(self, sql, params=()):
        conn = models.get_db(self.db)
        try:
            r = conn.execute(sql, params).fetchone()
            return dict(r) if r else None
        finally:
            conn.close()

    def rows(self, sql, params=()):
        conn = models.get_db(self.db)
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()


class CaptureCaptcha:
    """Context manager that records the plain-text answer of every local CAPTCHA drawn."""
    def __enter__(self):
        self.answers = []
        self._orig = security._render_captcha_svg
        def spy(text):
            self.answers.append(text)
            return self._orig(text)
        security._render_captcha_svg = spy
        return self

    def __exit__(self, *a):
        security._render_captcha_svg = self._orig

    def solve_from(self, html):
        token = re.search(r'name="captcha_token" value="([^"]+)"', html).group(1)
        return token, self.answers[-1]


def extract_csrf(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
