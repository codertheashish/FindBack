import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sqlite3
import unittest
from helpers import *

ADMIN_URLS = ["/admin/dashboard", "/admin/students", "/admin/students/new", "/admin/reports", "/admin/activity",
              "/admin/staff"]


class TestRoleSeparation(AppTestCase):
    def test_anonymous_redirected_to_login(self):
        c = self.app.test_client()
        for url in ADMIN_URLS + ["/teacher/dashboard", "/reports/my-dashboard"]:
            r = c.get(url)
            self.assertEqual(r.status_code, 302, url)
            self.assertIn("/auth/login", r.headers["Location"])

    def test_student_never_reaches_staff_pages(self):
        c = self.student_client()
        for url in ADMIN_URLS + ["/teacher/dashboard", f"/admin/students/{self.sid_a}"]:
            self.assertEqual(c.get(url).status_code, 403, url)
        for url in (f"/admin/students/{self.sid_a}/toggle-active", f"/admin/students/{self.sid_b}/delete",
                    f"/admin/students/{self.sid_b}/reset-password", "/admin/students/new", "/admin/staff"):
            self.assertEqual(c.post(url, data={}).status_code, 403, url)
        self.assertEqual(self.row("SELECT is_active a FROM users WHERE id=?", (self.sid_b,))["a"], 1)

    def test_teacher_does_not_get_admin_privileges_by_default(self):
        t = self.teacher_client()
        self.assertEqual(t.get("/teacher/dashboard").status_code, 200)
        self.assertEqual(t.get("/admin/reports").status_code, 200)       # default: reports + roster + password reset
        self.assertEqual(t.get("/admin/students").status_code, 200)
        self.assertNotIn(MOBILE_A, t.get("/admin/students").data.decode())      # mobile stays masked
        self.assertNotIn(MOBILE_A, t.get(f"/admin/students/{self.sid_a}").data.decode())
        for url in ["/admin/dashboard", "/admin/students/new", "/admin/activity", "/admin/staff",
                    f"/admin/students/{self.sid_a}/edit"]:
            self.assertEqual(t.get(url).status_code, 403, url)
        self.assertEqual(t.post(f"/admin/students/{self.sid_a}/delete", data={"confirm_roll": "21CS001"}).status_code, 403)
        self.assertEqual(t.post(f"/admin/students/{self.sid_a}/toggle-active", data={"active": "0"}).status_code, 403)
        self.assertEqual(t.post("/admin/staff", data={"username": "x1y", "name": "X", "temp_password": "Passw0rd123"}).status_code, 403)
        # teachers do not file reports or claims either
        self.assertEqual(t.get("/reports/lost/new").status_code, 403)

    def test_teacher_cannot_see_private_data_by_default(self):
        rid = models.create_report(self.sid_a, "found", "Black Wallet", "Wallets & Bags", "leather", "2026-10-20",
                                   "Cafeteria", distinguishing_features="SECRET-MARK-77", private_contact="PRIVATE-PHONE-55",
                                   db_path=self.db)
        html = self.teacher_client().get(f"/reports/{rid}").data.decode()
        self.assertNotIn("SECRET-MARK-77", html)
        self.assertNotIn("PRIVATE-PHONE-55", html)
        admin_html = self.admin_client().get(f"/reports/{rid}").data.decode()
        self.assertIn("SECRET-MARK-77", admin_html)
        self.assertIn("PRIVATE-PHONE-55", admin_html)

    def test_admin_has_everything_admin_pages_render(self):
        a = self.admin_client()
        for url in ADMIN_URLS + [f"/admin/students/{self.sid_a}", f"/admin/students/{self.sid_a}/edit"]:
            self.assertEqual(a.get(url).status_code, 200, url)

    def test_forced_password_change_applies_to_new_teacher(self):
        models.create_staff("teach2", "Teacher Two", models.ROLE_TEACHER, "TempPass123", self.admin_id, self.db)
        c = self.app.test_client()
        r = self.login(c, "teach2", "TempPass123", "staff")
        self.assertIn("/auth/change-password", r.headers["Location"])
        self.assertEqual(c.get("/admin/reports").status_code, 302)


class TestConfigurableTeacherPolicy(AppTestCase):
    extra_config = {"TEACHER_PERMISSIONS": {"reports.view_all", "students.view", "audit.view"}}

    def test_without_reset_permission_teacher_cannot_reset(self):
        r = self.teacher_client().post(f"/admin/students/{self.sid_a}/reset-password", data={})
        self.assertEqual(r.status_code, 403)

    def test_widened_policy_grants_exactly_those_permissions(self):
        t = self.teacher_client()
        for url in ["/admin/reports", "/admin/students", "/admin/activity"]:
            self.assertEqual(t.get(url).status_code, 200, url)
        self.assertEqual(t.get("/admin/students/new").status_code, 403)          # still no manage
        self.assertEqual(t.get("/admin/staff").status_code, 403)
        self.assertEqual(t.get("/admin/dashboard").status_code, 403)             # admin console stays admin-only
        # mobile numbers stay masked without private.view
        self.assertNotIn(MOBILE_A, t.get("/admin/students").data.decode())
        self.assertIn(MOBILE_A, self.admin_client().get("/admin/students").data.decode())


class TestAdminStudentManagement(AppTestCase):
    def new_student(self, a, **over):
        data = {"roll_number": "22ME010", "name": "Chitra Iyer", "mobile": "+91 98765 11111",
                "class_branch": "B.Tech ME", "academic_year": "1st Year"}
        data.update(over)
        return a.post("/admin/students/new", data=data)

    def test_create_student_and_first_login(self):
        a = self.admin_client()
        r = self.new_student(a)
        self.assertEqual(r.status_code, 302)
        s = self.row("SELECT * FROM users WHERE roll_number='22ME010'")
        self.assertEqual((s["name"], s["mobile"], s["class_branch"], s["role"]), ("Chitra Iyer", "9876511111", "B.Tech ME", "user"))
        self.assertEqual(s["must_change_password"], 1)
        self.assertEqual(s["created_by"], self.admin_id)
        c = self.app.test_client()
        self.assertIn("/auth/change-password", self.login(c, "22me010", "9876511111").headers["Location"])

    def test_validation_and_unique_roll(self):
        a = self.admin_client()
        self.assertEqual(self.new_student(a, roll_number="21CS001").status_code, 400)        # duplicate
        self.assertEqual(self.new_student(a, roll_number="21cs001").status_code, 400)        # duplicate, other case
        self.assertEqual(self.new_student(a, mobile="12345").status_code, 400)
        self.assertEqual(self.new_student(a, roll_number="a b").status_code, 400)
        self.assertEqual(self.new_student(a, name="").status_code, 400)
        self.assertEqual(self.new_student(a, name="<script>").status_code, 400)
        self.assertEqual(self.row("SELECT COUNT(*) n FROM users WHERE role='user'")["n"], 2)
        with self.assertRaises(sqlite3.IntegrityError):                                        # DB-level constraint
            conn = models.get_db(self.db)
            conn.execute("UPDATE users SET roll_number='21CS001' WHERE id=?", (self.sid_b,))

    def test_search_by_roll_and_name(self):
        a = self.admin_client()
        html = a.get("/admin/students?q=21cs001").data.decode()
        self.assertIn("Asha Rao", html); self.assertNotIn("Bilal Khan", html)
        html = a.get("/admin/students?q=bilal").data.decode()
        self.assertIn("Bilal Khan", html); self.assertNotIn("Asha Rao", html)
        self.assertNotIn("Asha Rao", a.get("/admin/students?q=%25").data.decode())   # LIKE wildcards are escaped

    def test_edit_details_and_mobile_does_not_change_password(self):
        self.settle_student(self.sid_a, "KeepThis12345")
        a = self.admin_client()
        r = a.post(f"/admin/students/{self.sid_a}/edit", data={"roll_number": "21CS001", "name": "Asha R. Rao",
                   "mobile": "9000011111", "class_branch": "MBA", "academic_year": "1st Year"})
        self.assertEqual(r.status_code, 302)
        s = self.row("SELECT * FROM users WHERE id=?", (self.sid_a,))
        self.assertEqual((s["name"], s["mobile"], s["class_branch"]), ("Asha R. Rao", "9000011111", "MBA"))
        self.assertTrue(models.verify_password(s["password_hash"], "KeepThis12345"))
        self.assertGreater(s["updated_at"], s["created_at"])
        # duplicate roll on edit rejected
        r = a.post(f"/admin/students/{self.sid_a}/edit", data={"roll_number": "21CS002", "name": "X Y", "mobile": "9000011111"})
        self.assertEqual(r.status_code, 400)

    def test_deactivate_blocks_login_and_kills_live_session(self):
        c = self.student_client()
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 200)
        a = self.admin_client()
        a.post(f"/admin/students/{self.sid_a}/toggle-active", data={"active": "0"})
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "21CS001", "NewPass12345").status_code, 403)
        a.post(f"/admin/students/{self.sid_a}/toggle-active", data={"active": "1"})
        self.assertEqual(self.login(self.app.test_client(), "21CS001", "NewPass12345").status_code, 302)

    def test_delete_safeguards(self):
        a = self.admin_client()
        # needs the exact roll number
        a.post(f"/admin/students/{self.sid_b}/delete", data={"confirm_roll": "WRONG"})
        self.assertEqual(self.row("SELECT is_deleted d FROM users WHERE id=?", (self.sid_b,))["d"], 0)
        # student with history -> soft delete, history intact
        rid = models.create_report(self.sid_a, "lost", "Umbrella", "Other", "black", "2026-10-20", "Gate", db_path=self.db)
        a.post(f"/admin/students/{self.sid_a}/delete", data={"confirm_roll": "21cs001"})
        s = self.row("SELECT * FROM users WHERE id=?", (self.sid_a,))
        self.assertEqual((s["is_deleted"], s["is_active"]), (1, 0))
        self.assertIsNotNone(self.row("SELECT 1 FROM reports WHERE id=?", (rid,)))
        self.assertEqual(self.login(self.app.test_client(), "21CS001", MOBILE_A).status_code, 403)   # archived = disabled
        # duplicate create is refused with a hint, restore works (left inactive)
        self.assertEqual(self.new_student(a, roll_number="21CS001").status_code, 400)
        a.post(f"/admin/students/{self.sid_a}/restore", data={})
        s = self.row("SELECT * FROM users WHERE id=?", (self.sid_a,))
        self.assertEqual((s["is_deleted"], s["is_active"]), (0, 0))
        # student without history -> permanently removed
        a.post(f"/admin/students/{self.sid_b}/delete", data={"confirm_roll": "21CS002"})
        self.assertIsNone(self.row("SELECT 1 FROM users WHERE id=?", (self.sid_b,)))

    def test_cannot_deactivate_self_or_last_admin(self):
        with self.assertRaises(models.ValidationError):
            models.set_user_active(self.admin_id, False, self.admin_id, self.db)
        other = models.create_staff("admin2", "Admin Two", models.ROLE_ADMIN, "AdminTwo12345", self.admin_id, self.db)
        models.set_user_active(other, False, self.admin_id, self.db)       # fine: one active admin remains
        with self.assertRaises(models.ValidationError):
            models.set_user_active(self.admin_id, False, 9999, self.db)      # would leave no active admin


class TestAdminPasswordReset(AppTestCase):
    def reset(self, client, sid=None, **over):
        data = {"reason": "ID card verified"}
        data.update(over)
        return client.post(f"/admin/students/{sid or self.sid_a}/reset-password", data=data)

    def test_reset_works_without_knowing_current_password_and_keeps_data(self):
        old = self.student_client()                                    # student set their own password earlier
        rid = models.create_report(self.sid_a, "lost", "Umbrella", "Other", "black", "2026-10-20", "Gate", db_path=self.db)
        a = self.admin_client()
        self.assertEqual(old.get("/reports/my-dashboard").status_code, 200)
        r = self.reset(a)                                              # no current password, no confirmation typing
        self.assertEqual(r.status_code, 302)
        s = self.row("SELECT * FROM users WHERE id=?", (self.sid_a,))
        self.assertEqual((s["must_change_password"], s["password_reset_by"]), (1, self.admin_id))
        self.assertIsNotNone(s["password_reset_at"])
        self.assertTrue(models.verify_password(s["password_hash"], MOBILE_A))     # back to registered mobile
        self.assertEqual(old.get("/reports/my-dashboard").status_code, 302)        # old session invalidated
        c = self.app.test_client()
        self.assertEqual(self.login(c, "21CS001", "NewPass12345").status_code, 401)    # previous password dead
        self.assertEqual(self.login(c, "21CS001", MOBILE_A).status_code, 302)
        # data not lost
        self.assertEqual(self.row("SELECT item_name n, user_id u FROM reports WHERE id=?", (rid,)),
                         {"n": "Umbrella", "u": self.sid_a})
        self.assertEqual(self.row("SELECT roll_number r, name n FROM users WHERE id=?", (self.sid_a,)),
                         {"r": "21CS001", "n": "Asha Rao"})

    def test_admin_can_set_a_specific_temporary_password(self):
        a = self.admin_client()
        self.reset(a, new_password="Temp@Pass2026")
        c = self.app.test_client()
        self.assertEqual(self.login(c, "21CS001", MOBILE_A).status_code, 401)
        self.assertEqual(self.login(c, "21CS001", "Temp@Pass2026").status_code, 302)
        # weak temporary passwords are refused and nothing changes
        before = self.row("SELECT password_hash h FROM users WHERE id=?", (self.sid_b,))["h"]
        self.reset(a, sid=self.sid_b, new_password="abc")
        self.assertEqual(self.row("SELECT password_hash h FROM users WHERE id=?", (self.sid_b,))["h"], before)

    def test_teacher_can_reset_by_default_student_cannot(self):
        t = self.teacher_client()
        self.assertEqual(self.reset(t).status_code, 302)
        self.assertEqual(self.row("SELECT password_reset_by p FROM users WHERE id=?", (self.sid_a,))["p"], self.teacher_id)
        self.assertEqual(self.reset(self.student_client("21CS002")).status_code, 403)

    def test_reset_recorded_without_any_password(self):
        a = self.admin_client()
        self.reset(a, new_password="Temp@Pass2026")
        ev = self.row("SELECT * FROM activity_log WHERE action='student.password_reset'")
        self.assertEqual((ev["actor_id"], ev["target_user_id"], ev["actor_roll"]), (self.admin_id, self.sid_a, "admin1"))
        self.assertIsNotNone(ev["timestamp"])
        for secret in (MOBILE_A, ADMIN_PW, "Temp@Pass2026"):
            self.assertNotIn(secret, ev["details"])
        html = a.get(f"/admin/students/{self.sid_a}").data.decode()
        self.assertIn("change pending", html)
        self.assertNotIn("scrypt", html)

    def test_staff_password_reset_for_teacher(self):
        a = self.admin_client()
        r = a.post(f"/admin/staff/{self.teacher_id}/reset-password", data={"temp_password": "TempReset123", "admin_password": ADMIN_PW})
        self.assertEqual(r.status_code, 302)
        c = self.app.test_client()
        self.assertIn("/auth/change-password", self.login(c, "teach1", "TempReset123", "staff").headers["Location"])


class TestResetReauthSetting(AppTestCase):
    extra_config = {"RESET_REQUIRE_REAUTH": True}

    def test_admin_password_required_when_enabled(self):
        a = self.admin_client()
        self.settle_student(self.sid_a, "KeepThis12345")
        a.post(f"/admin/students/{self.sid_a}/reset-password", data={"admin_password": "wrong"})
        self.assertTrue(models.verify_password(self.row("SELECT password_hash h FROM users WHERE id=?", (self.sid_a,))["h"], "KeepThis12345"))
        a.post(f"/admin/students/{self.sid_a}/reset-password", data={"admin_password": ADMIN_PW})
        self.assertTrue(models.verify_password(self.row("SELECT password_hash h FROM users WHERE id=?", (self.sid_a,))["h"], MOBILE_A))


class TestOptionalPasswordChangeAndUi(AppTestCase):
    extra_config = {"PASSWORD_CHANGE_MODE": "optional"}

    def test_change_password_page_is_skippable(self):
        c = self.app.test_client()
        r = self.login(c, "21CS001", MOBILE_A)
        self.assertIn("/auth/change-password", r.headers["Location"])        # shown after first login ...
        page = c.get("/auth/change-password").data.decode()
        self.assertIn("Skip for now", page)
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 200)     # ... but nothing is blocked
        self.assertEqual(c.post("/reports/lost/new", data=self.report_form()).status_code, 302)
        self.assertIn("still using your initial password", c.get("/reports/browse").data.decode())
        # changing it later still works and clears the reminder
        r = c.post("/auth/change-password", data={"current_password": MOBILE_A, "new_password": "GoodPass123",
                                                  "confirm_password": "GoodPass123"})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("still using your initial password", c.get("/reports/browse").data.decode())

    def test_forced_mode_still_available(self):
        self.app.config["PASSWORD_CHANGE_MODE"] = "forced"
        c = self.app.test_client()
        self.login(c, "21CS001", MOBILE_A)
        self.assertNotIn("Skip for now", c.get("/auth/change-password").data.decode())
        self.assertEqual(c.get("/reports/my-dashboard").status_code, 302)

    def test_branding_and_ui_helpers(self):
        html = self.app.test_client().get("/").data.decode()
        self.assertIn("Created by", html); self.assertIn("Hack Hawk", html)
        self.assertNotIn("SS-15", html)
        for url in ("/reports/browse", "/auth/login"):
            self.assertNotIn("SS-15", self.app.test_client().get(url).data.decode(), url)
        js = self.app.test_client().get("/static/js/main.js").data.decode()
        self.assertIn('input[type="password"]', js)                          # show/hide password
        self.assertIn("captcha-refresh", js)


class TestCaptchaRefreshButton(AppTestCase):
    captcha = "local"

    def test_refresh_endpoint_returns_new_valid_challenge(self):
        with CaptureCaptcha() as cap:
            c = self.app.test_client()
            html = c.get("/auth/login").data.decode()
            self.assertIn('id="captcha-refresh"', html)                      # recycle icon button
            self.assertNotIn("New image</a>", html)
            first_token, _ = cap.solve_from(html)
            data = c.get("/auth/captcha/new").get_json()
            self.assertIn("<svg", data["svg"])
            self.assertNotEqual(data["token"], first_token)
            r = c.post("/auth/login", data={"username": "21CS001", "password": MOBILE_A,
                                            "captcha_token": data["token"], "captcha_answer": cap.answers[-1]})
            self.assertEqual(r.status_code, 302)

    def test_refresh_not_available_for_disabled_provider(self):
        self.app.config["CAPTCHA_PROVIDER"] = "disabled"
        self.assertEqual(self.app.test_client().get("/auth/captcha/new").status_code, 404)


if __name__ == "__main__":
    unittest.main()
