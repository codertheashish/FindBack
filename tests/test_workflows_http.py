import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import io
import sqlite3
import unittest
from helpers import *

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class TestReportOwnership(AppTestCase):
    def test_reporter_comes_from_session_not_form(self):
        c = self.student_client("21CS001")
        form = self.report_form(user_id=str(self.sid_b), reporter_id=str(self.sid_b))
        r = c.post("/reports/lost/new", data=form)
        self.assertEqual(r.status_code, 302)
        rep = self.row("SELECT * FROM reports")
        self.assertEqual(rep["user_id"], self.sid_a)
        self.assertEqual(rep["report_type"], "lost")
        r = c.post("/reports/found/new", data=self.report_form(item_name="Found Key", category="Keys", user_id=str(self.sid_b)))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.row("SELECT user_id u FROM reports WHERE item_name='Found Key'")["u"], self.sid_a)

    def test_input_validation(self):
        c = self.student_client()
        for bad in (self.report_form(category="Hacking"), self.report_form(date_occurred="not-a-date"),
                    self.report_form(date_occurred="2999-01-01"), self.report_form(item_name=""),
                    self.report_form(description="x" * 2001)):
            self.assertEqual(c.post("/reports/lost/new", data=bad).status_code, 400)
        self.assertEqual(self.rows("SELECT * FROM reports"), [])

    def test_sql_metacharacters_are_stored_literally(self):
        c = self.student_client()
        c.post("/reports/lost/new", data=self.report_form(item_name="x'); DROP TABLE reports;--"))
        self.assertEqual(self.row("SELECT item_name n FROM reports")["n"], "x'); DROP TABLE reports;--")
        self.assertEqual(c.get("/reports/browse?q=' OR '1'='1&location=%25").status_code, 200)

    def test_image_upload_validation(self):
        c = self.student_client()
        def post(content, name):
            return c.post("/reports/found/new", data={**self.report_form(), "image": (io.BytesIO(content), name)},
                          content_type="multipart/form-data")
        self.assertEqual(post(b"<?php echo 1;?>", "shell.php").status_code, 400)           # bad extension
        self.assertEqual(post(b"<?php echo 1;?>", "shell.png").status_code, 400)           # fake image
        self.assertEqual(post(PNG, "x.jpg").status_code, 400)                                # type mismatch
        self.assertEqual(self.rows("SELECT * FROM reports"), [])
        self.assertEqual(post(PNG, "../../evil.png").status_code, 302)
        name = self.row("SELECT image_filename f FROM reports")["f"]
        self.assertRegex(name, r"^[0-9a-f]{32}\.png$")
        self.assertTrue(os.path.exists(os.path.join(self.app.config["UPLOAD_FOLDER"], name)))
        r = c.get(f"/uploads/{name}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        r.close()
        self.assertEqual(c.get("/uploads/anything.php").status_code, 404)

    def test_oversize_upload_rejected(self):
        self.app.config["MAX_CONTENT_LENGTH"] = 1024
        c = self.student_client()
        r = c.post("/reports/found/new", data={**self.report_form(), "image": (io.BytesIO(PNG + b"0" * 5000), "x.png")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)

    def test_cannot_edit_or_peek_at_other_students_reports(self):
        rid = models.create_report(self.sid_a, "lost", "Asha Laptop", "Electronics", "silver laptop", "2026-10-20",
                                   "Library", distinguishing_features="SECRET-A", private_contact="PHONE-A-111", db_path=self.db)
        b = self.student_client("21CS002")
        self.assertEqual(b.get(f"/reports/{rid}/edit").status_code, 403)
        self.assertEqual(b.post(f"/reports/{rid}/edit", data=self.report_form(item_name="HACKED")).status_code, 403)
        self.assertEqual(self.row("SELECT item_name n FROM reports WHERE id=?", (rid,))["n"], "Asha Laptop")
        self.assertEqual(b.get(f"/reports/{rid}/matches").status_code, 403)
        html = b.get(f"/reports/{rid}").data.decode()
        self.assertNotIn("PHONE-A-111", html)                    # private contact hidden from other students
        self.assertNotIn("Edit</a>", html)
        # the owner can
        a = self.student_client("21CS001")
        self.assertIn("PHONE-A-111", a.get(f"/reports/{rid}").data.decode())
        r = a.post(f"/reports/{rid}/edit", data=self.report_form(item_name="Asha Laptop v2", category="Electronics"))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.row("SELECT item_name n FROM reports WHERE id=?", (rid,))["n"], "Asha Laptop v2")

    def test_dashboard_shows_only_own_reports_and_real_matches(self):
        models.create_report(self.sid_a, "lost", "Silver Dell XPS Laptop", "Electronics", "silver dell laptop stickers",
                             "2026-10-20", "Main Library 2nd Floor", db_path=self.db)
        models.create_report(self.sid_b, "found", "Silver Dell Laptop", "Electronics", "silver dell laptop with stickers",
                             "2026-10-20", "Main Library 2nd Floor", distinguishing_features="B-SECRET", db_path=self.db)
        models.create_report(self.sid_b, "lost", "Green Umbrella", "Other", "green", "2026-10-19", "Gate", db_path=self.db)
        html = self.student_client("21CS001").get("/reports/my-dashboard").data.decode()
        self.assertIn("Silver Dell XPS Laptop", html)
        self.assertNotIn("Green Umbrella", html)                 # B's lost report is not on A's lists
        self.assertIn("Possible Matches", html)
        self.assertIn("Silver Dell Laptop", html)                # match found by the real engine
        self.assertNotIn("B-SECRET", html)
        self.assertIn("21CS001", html)                           # profile card
        # score shown equals the engine's score
        from matching import calculate_match
        a_rep, b_rep = self.rows("SELECT * FROM reports WHERE id IN (1,2) ORDER BY id")
        self.assertIn(f"{calculate_match(a_rep, b_rep)['score']}%", html)

    def test_edit_blocked_once_claim_in_progress(self):
        rid = models.create_report(self.sid_a, "found", "Wallet", "Wallets & Bags", "brown", "2026-10-20", "Cafe", db_path=self.db)
        models.create_claim(rid, self.sid_b, "{}", "9000000000", db_path=self.db)
        a = self.student_client("21CS001")
        r = a.post(f"/reports/{rid}/edit", data=self.report_form(item_name="Changed"))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.row("SELECT item_name n FROM reports WHERE id=?", (rid,))["n"], "Wallet")


class TestClaimsAndReturnWorkflowHttp(AppTestCase):
    def setUp(self):
        super().setUp()
        self.found = models.create_report(self.sid_a, "found", "Silver Dell Laptop", "Electronics", "silver laptop",
                                          "2026-10-20", "Library", distinguishing_features="Tux sticker 8X99", db_path=self.db)
        self.b = self.student_client("21CS002")
        self.a = self.student_client("21CS001")
        self.admin = self.admin_client()
        self.claim_form = {"distinguishing_proof": "Tux sticker and tag 8X99", "contact_phone": "9123456780",
                           "contents_proof": "charger", "client_id": str(self.sid_a), "claimant_id": str(self.sid_a)}

    def test_full_lifecycle_with_audit_trail(self):
        r = self.b.post(f"/claims/submit/{self.found}", data=self.claim_form)
        self.assertEqual(r.status_code, 302)
        claim = self.row("SELECT * FROM claims")
        self.assertEqual(claim["claimant_id"], self.sid_b)                  # session user, not form field
        self.assertEqual(self.row("SELECT status s FROM reports WHERE id=?", (self.found,))["s"], "Claim Pending")
        # duplicate pending claim refused
        self.b.post(f"/claims/submit/{self.found}", data=self.claim_form)
        self.assertEqual(self.row("SELECT COUNT(*) n FROM claims")["n"], 1)
        # finder cannot claim own item; third parties cannot read the claim
        self.assertEqual(self.a.post(f"/claims/submit/{self.found}", data=self.claim_form).status_code, 302)
        self.assertEqual(self.row("SELECT COUNT(*) n FROM claims")["n"], 1)
        self.assertEqual(self.a.get(f"/claims/view/{claim['id']}").status_code, 403)
        self.assertEqual(self.teacher_client().get(f"/claims/view/{claim['id']}").status_code, 403)
        self.assertIn("Tux sticker", self.b.get(f"/claims/view/{claim['id']}").data.decode())
        # finder's dashboard shows status but not claimant identity/answers
        dash = self.a.get("/reports/my-dashboard").data.decode()
        self.assertIn("Claims on Items I Found", dash)
        self.assertNotIn("Tux sticker and tag", dash); self.assertNotIn("21CS002", dash)
        # teacher cannot review; students cannot review
        self.assertEqual(self.teacher_client().post(f"/admin/claims/{claim['id']}", data={"action": "Approved"}).status_code, 403)
        self.assertEqual(self.b.post(f"/admin/claims/{claim['id']}", data={"action": "Approved"}).status_code, 403)
        # admin approves -> Verified
        self.assertIn("Tux sticker", self.admin.get(f"/admin/claims/{claim['id']}").data.decode())
        self.admin.post(f"/admin/claims/{claim['id']}", data={"action": "Approved", "notes": "serial matched"})
        rep = self.row("SELECT * FROM reports WHERE id=?", (self.found,))
        self.assertEqual((rep["status"], rep["verified_by"]), ("Verified", self.admin_id))
        self.assertIsNotNone(rep["verified_at"]); self.assertIsNone(rep["returned_at"])
        # second review of the same claim is refused
        self.admin.post(f"/admin/claims/{claim['id']}", data={"action": "Rejected"})
        self.assertEqual(self.row("SELECT status s FROM claims")["s"], "Approved")
        # return
        self.admin.post(f"/admin/reports/{self.found}/status", data={"status": "Returned", "notes": "handed over"})
        rep = self.row("SELECT * FROM reports WHERE id=?", (self.found,))
        self.assertEqual((rep["status"], rep["returned_by"]), ("Returned", self.admin_id))
        self.assertIsNotNone(rep["returned_at"])
        # claimant sees the return status
        self.assertIn("Returned", self.b.get("/reports/my-dashboard").data.decode())
        # admin history
        actions = [r["action"] for r in self.rows("SELECT action FROM activity_log ORDER BY id")]
        for expected in ("claim.submitted", "claim.approved", "report.status_changed", "report.returned"):
            self.assertIn(expected, actions)
        appr = self.row("SELECT * FROM activity_log WHERE action='claim.approved'")
        self.assertEqual((appr["actor_id"], appr["actor_roll"]), (self.admin_id, "admin1"))
        ret = self.row("SELECT * FROM activity_log WHERE action='report.returned'")
        self.assertEqual(ret["actor_id"], self.admin_id)

    def test_rejection_and_students_cannot_change_status(self):
        self.b.post(f"/claims/submit/{self.found}", data=self.claim_form)
        cid = self.row("SELECT id FROM claims")["id"]
        self.admin.post(f"/admin/claims/{cid}", data={"action": "Rejected", "notes": "could not describe"})
        self.assertEqual(self.row("SELECT status s FROM reports WHERE id=?", (self.found,))["s"], "Open")
        self.assertEqual(self.row("SELECT * FROM activity_log WHERE action='claim.rejected'")["actor_id"], self.admin_id)
        self.assertEqual(self.b.post(f"/admin/reports/{self.found}/status", data={"status": "Returned"}).status_code, 403)
        self.assertEqual(self.a.post(f"/admin/reports/{self.found}/delete").status_code, 403)

    def test_staff_monitoring_page_shows_match_claim_and_return_columns(self):
        lost = models.create_report(self.sid_b, "lost", "Silver Dell Laptop", "Electronics", "silver dell laptop library",
                                    "2026-10-20", "Library", db_path=self.db)
        self.b.post(f"/claims/submit/{self.found}", data=self.claim_form)
        html = self.admin.get("/admin/reports").data.decode()
        self.assertIn("21CS001", html); self.assertIn("21CS002", html)
        self.assertIn("1 pending", html); self.assertIn("match", html)
        self.assertNotIn("Tux sticker and tag", html)            # private answers never listed
        self.assertIn("Silver Dell Laptop", self.admin.get("/admin/reports?type=found&roll=21cs001").data.decode())


if __name__ == "__main__":
    unittest.main()
