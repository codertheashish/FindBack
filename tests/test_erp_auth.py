import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sqlite3
import unittest
from helpers import *


class TestStudentLoginAndPasswordFlow(AppTestCase):
    def test_initial_login_uses_mobile_and_forces_password_change(self):
        c = self.app.test_client()
        r = self.login(c, "21cs001", MOBILE_A)          # roll numbers are case-insensitive
        self.assertEqual(r.status_code, 302)
        self.assertIn("/auth/change-password", r.headers["Location"])
        # everything else is blocked until the password is changed
        r = c.get("/reports/my-dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/auth/change-password", r.headers["Location"])
        r = c.post("/reports/lost/new", data=self.report_form())
        self.assertEqual(r.status_code, 302)
        self.assertIn("/auth/change-password", r.headers["Location"])
        self.assertEqual(self.rows("SELECT * FROM reports"), [])

    def test_password_is_stored_only_as_hash(self):
        row = self.row("SELECT password_hash, mobile FROM users WHERE id=?", (self.sid_a,))
        self.assertNotIn(MOBILE_A, row["password_hash"])
        self.assertNotEqual(row["password_hash"], MOBILE_A)
        self.assertTrue(models.verify_password(row["password_hash"], MOBILE_A))

    def test_change_password_rules_and_new_login(self):
        c = self.app.test_client()
        self.login(c, "21CS001", MOBILE_A)
        post = lambda cur, new, conf=None: c.post("/auth/change-password", data={
            "current_password": cur, "new_password": new, "confirm_password": conf or new})
        self.assertEqual(post("wrongcurrent1", "GoodPass123").status_code, 400)   # wrong current
        self.assertEqual(post(MOBILE_A, "short1").status_code, 400)               # too short
        self.assertEqual(post(MOBILE_A, "onlyletters").status_code, 400)          # no digit
        self.assertEqual(post(MOBILE_A, MOBILE_A).status_code, 400)               # same as current/mobile
        self.assertEqual(post(MOBILE_A, "password123").status_code, 400)          # common
        self.assertEqual(post(MOBILE_A, "GoodPass123", "Different123").status_code, 400)
        r = post(MOBILE_A, "GoodPass123")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.row("SELECT must_change_password m FROM users WHERE id=?", (self.sid_a,))["m"], 0)
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 200)          # session kept alive
        # old (mobile) password no longer works; new one does
        c2 = self.app.test_client()
        self.assertEqual(self.login(c2, "21CS001", MOBILE_A).status_code, 401)
        self.assertEqual(self.login(c2, "21CS001", "GoodPass123").status_code, 302)

    def test_change_password_invalidates_other_sessions(self):
        other = self.student_client()                      # session #1
        mine = self.app.test_client()
        self.login(mine, "21CS001", "NewPass12345")        # session #2
        r = mine.post("/auth/change-password", data={"current_password": "NewPass12345",
                      "new_password": "Another12345", "confirm_password": "Another12345"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(other.get("/reports/my-dashboard").status_code, 302)   # kicked out
        self.assertEqual(mine.get("/reports/my-dashboard").status_code, 200)

    def test_change_password_requires_login(self):
        r = self.app.test_client().get("/auth/change-password")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/auth/login", r.headers["Location"])


class TestLoginRejections(AppTestCase):
    def test_invalid_credentials_generic_message(self):
        c = self.app.test_client()
        r1 = self.login(c, "21CS001", "wrong-password1")
        r2 = self.login(c, "NOSUCH99", "wrong-password1")
        self.assertEqual(r1.status_code, 401)
        self.assertEqual(r2.status_code, 401)
        self.assertIn(b"Invalid username or password", r1.data)
        self.assertIn(b"Invalid username or password", r2.data)   # no user enumeration

    def test_portals_are_separate(self):
        c = self.app.test_client()
        self.assertEqual(self.login(c, "admin1", ADMIN_PW, "student").status_code, 401)
        self.assertEqual(self.login(c, "21CS001", MOBILE_A, "staff").status_code, 401)
        self.assertEqual(self.login(c, "teach1", TEACHER_PW, "student").status_code, 401)

    def test_deactivated_and_deleted_students_cannot_login(self):
        models.set_user_active(self.sid_a, False, self.admin_id, self.db)
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 403)
        models.set_user_active(self.sid_a, True, self.admin_id, self.db)
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 302)
        models.delete_student(self.sid_b, self.admin_id, self.db)           # no history -> hard delete
        self.assertEqual(self.login(self.app.test_client(), "21CS002", MOBILE_B).status_code, 401)

    def test_self_registration_disabled(self):
        c = self.app.test_client()
        r = c.post("/auth/register", data={"name": "Evil", "email": "e@x.com", "password": "Password123",
                                          "confirm_password": "Password123", "admin_code": "FindBackAdmin2026!"})
        self.assertEqual(r.status_code, 302)
        self.assertIsNone(self.row("SELECT 1 FROM users WHERE name='Evil'"))

    def test_open_redirect_blocked(self):
        self.settle_student(self.sid_a)
        for bad in ("//evil.com", "https://evil.com", "/\\evil.com"):
            c = self.app.test_client()
            r = c.post(f"/auth/login?next={bad}", data={"username": "21CS001", "password": "NewPass12345"})
            self.assertEqual(r.status_code, 302)
            self.assertNotIn("evil.com", r.headers["Location"])
        c = self.app.test_client()
        r = c.post("/auth/login?next=/reports/browse", data={"username": "21CS001", "password": "NewPass12345"})
        self.assertTrue(r.headers["Location"].endswith("/reports/browse"))

    def test_logout_requires_post_and_ends_session(self):
        c = self.student_client()
        self.assertEqual(c.get("/auth/logout").status_code, 405)
        self.assertEqual(c.post("/auth/logout").status_code, 302)
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 302)

    def test_legacy_hash_still_verifies_and_is_upgraded(self):
        import hashlib, binascii, os
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', b"OldPassword9", salt, 100000)
        legacy = binascii.hexlify(salt).decode() + "$" + binascii.hexlify(key).decode()
        self.assertTrue(models.verify_password(legacy, "OldPassword9"))
        self.assertFalse(models.verify_password(legacy, "nope"))
        conn = models.get_db(self.db)
        conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (legacy, self.sid_a))
        conn.commit(); conn.close()
        self.assertEqual(self.login(self.app.test_client(), "21CS001", "OldPassword9").status_code, 302)
        self.assertFalse(models.password_needs_rehash(self.row("SELECT password_hash h FROM users WHERE id=?", (self.sid_a,))["h"]))


class TestCaptchaServerSide(AppTestCase):
    captcha = "local"

    def _attempt(self, c, user, pw, token, answer):
        return c.post("/auth/login", data={"username": user, "password": pw,
                                           "captcha_token": token, "captcha_answer": answer})

    def test_missing_wrong_and_reused_captcha_rejected(self):
        with CaptureCaptcha() as cap:
            c = self.app.test_client()
            html = c.get("/auth/login").data.decode()
            self.assertIn("<svg", html)
            self.assertNotIn(cap.answers[-1], html.replace("aria-label", ""))   # answer is not in the page as text
            token, answer = cap.solve_from(html)
            # no captcha fields at all
            self.assertEqual(c.post("/auth/login", data={"username": "21CS001", "password": MOBILE_A}).status_code, 400)
            # wrong answer (and the challenge is burned)
            self.assertEqual(self._attempt(c, "21CS001", MOBILE_A, token, "WRONG").status_code, 400)
            self.assertEqual(self._attempt(c, "21CS001", MOBILE_A, token, answer).status_code, 400)   # reuse fails
            # forged token
            self.assertEqual(self._attempt(c, "21CS001", MOBILE_A, "forged", answer).status_code, 400)

    def test_correct_captcha_accepts_valid_credentials_only(self):
        with CaptureCaptcha() as cap:
            c = self.app.test_client()
            token, answer = cap.solve_from(c.get("/auth/login").data.decode())
            self.assertEqual(self._attempt(c, "21CS001", "badpass1234", token, answer).status_code, 401)
            token, answer = cap.solve_from(c.get("/auth/login").data.decode())
            self.assertEqual(self._attempt(c, "21CS001", MOBILE_A, token, answer.lower()).status_code, 302)

    def test_expired_captcha_rejected(self):
        with CaptureCaptcha() as cap:
            c = self.app.test_client()
            token, answer = cap.solve_from(c.get("/auth/login").data.decode())
            # captcha tokens are stateless now: age the token by shifting "time" forward past the TTL
            import time as _time
            real_time = _time.time
            _time.time = lambda: real_time() + 10_000
            try:
                self.assertEqual(self._attempt(c, "21CS001", MOBILE_A, token, answer).status_code, 400)
            finally:
                _time.time = real_time

    def test_disabled_captcha_is_ignored_outside_development(self):
        app = create_app({"TESTING": False, "DATABASE": self.db, "UPLOAD_FOLDER": self.tmp,
                          "CAPTCHA_PROVIDER": "disabled", "SECRET_KEY": "k" * 40})
        app.debug = False
        with app.test_request_context("/"):
            import os
            old = os.environ.pop("FLASK_ENV", None)
            try:
                self.assertEqual(security.captcha_provider(), "local")
            finally:
                if old: os.environ["FLASK_ENV"] = old

    def test_external_provider_verified_server_side_and_fails_closed(self):
        app = create_app({"TESTING": True, "DATABASE": self.db, "UPLOAD_FOLDER": self.tmp, "CAPTCHA_PROVIDER": "turnstile",
                          "CAPTCHA_SITE_KEY": "site", "CAPTCHA_SECRET_KEY": "secret", "SECRET_KEY": "k" * 40})
        calls = []
        class FakeResp:
            def __init__(s, ok): s.ok = ok
            def read(s): return b'{"success": %s}' % (b"true" if s.ok else b"false")
            def __enter__(s): return s
            def __exit__(s, *a): return False
        import urllib.request
        orig = urllib.request.urlopen
        try:
            urllib.request.urlopen = lambda req, timeout=5: (calls.append(req.data) or FakeResp(b"good" in req.data))
            with app.test_request_context("/"):
                self.assertTrue(security.verify_captcha({"cf-turnstile-response": "good-token"}))
                self.assertFalse(security.verify_captcha({"cf-turnstile-response": "bad-token"}))
                self.assertFalse(security.verify_captcha({}))
            def boom(req, timeout=5): raise OSError("offline")
            urllib.request.urlopen = boom
            with app.test_request_context("/"):
                self.assertFalse(security.verify_captcha({"cf-turnstile-response": "good-token"}))
        finally:
            urllib.request.urlopen = orig
        self.assertEqual(len(calls), 2)


class TestLockoutAndCsrf(AppTestCase):
    extra_config = {"LOGIN_MAX_FAILURES": 3, "LOGIN_LOCKOUT_SECONDS": 600}

    def test_lockout_after_repeated_failures_even_for_correct_password(self):
        c = self.app.test_client()
        for _ in range(3):
            self.assertEqual(self.login(c, "21CS001", "wrong-pass-1").status_code, 401)
        r = self.login(c, "21CS001", MOBILE_A)             # correct, but locked
        self.assertEqual(r.status_code, 429)
        self.assertIn(b"Too many failed", r.data)
        self.assertEqual(self.row("SELECT COUNT(*) n FROM activity_log WHERE action='auth.lockout'")["n"], 1)
        # another account is unaffected
        self.assertEqual(self.login(self.app.test_client(), "21CS002", MOBILE_B).status_code, 302)
        # lock expires
        conn = models.get_db(self.db)
        conn.execute("UPDATE login_attempts SET created_at='2000-01-01T00:00:00.000000'")
        conn.commit(); conn.close()
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 302)

    def test_successful_login_resets_failure_count(self):
        c = self.app.test_client()
        for _ in range(2):
            self.login(c, "21CS001", "wrong-pass-1")
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 302)
        for _ in range(2):
            self.login(c, "21CS001", "wrong-pass-1")
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 302)

    def test_ip_throttle(self):
        self.app.config.update(LOGIN_IP_MAX_FAILURES=4, LOGIN_MAX_FAILURES=100)
        c = self.app.test_client()
        for i in range(4):
            self.login(c, f"nobody{i}", "wrong-pass-1")
        self.assertEqual(self.login(c, "21CS001", MOBILE_A).status_code, 429)


class TestCsrf(AppTestCase):
    csrf = True

    def test_post_without_token_rejected_with_token_accepted(self):
        c = self.app.test_client()
        r = c.get("/auth/login")
        token = extract_csrf(r.data.decode())
        bad = c.post("/auth/login", data={"username": "21CS001", "password": MOBILE_A})
        self.assertEqual(bad.status_code, 400)
        bad2 = c.post("/auth/login", data={"username": "21CS001", "password": MOBILE_A, "csrf_token": "forged"})
        self.assertEqual(bad2.status_code, 400)
        ok = c.post("/auth/login", data={"username": "21CS001", "password": MOBILE_A, "csrf_token": token})
        self.assertEqual(ok.status_code, 302)

    def test_state_changing_admin_post_needs_token(self):
        c = self.app.test_client()
        token = extract_csrf(c.get("/auth/login?portal=staff").data.decode())
        c.post("/auth/login?portal=staff", data={"username": "admin1", "password": ADMIN_PW, "portal": "staff", "csrf_token": token})
        self.assertEqual(c.post(f"/admin/students/{self.sid_a}/toggle-active", data={"active": "0"}).status_code, 400)
        self.assertEqual(self.row("SELECT is_active a FROM users WHERE id=?", (self.sid_a,))["a"], 1)
        token = extract_csrf(c.get(f"/admin/students/{self.sid_a}").data.decode())
        r = c.post(f"/admin/students/{self.sid_a}/toggle-active", data={"active": "0", "csrf_token": token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.row("SELECT is_active a FROM users WHERE id=?", (self.sid_a,))["a"], 0)


if __name__ == "__main__":
    unittest.main()
