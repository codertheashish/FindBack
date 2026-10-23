import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hashlib, binascii
import shutil
import sqlite3
import tempfile
import unittest
from helpers import *


class TestActivityHistory(AppTestCase):
    def setUp(self):
        super().setUp()
        self.lost = models.create_report(self.sid_a, "lost", "Blue Bottle", "Bottles & Flasks", "blue", "2026-10-20", "Gym", db_path=self.db)
        self.found = models.create_report(self.sid_b, "found", "Red Hoodie", "Clothing & Apparel", "red", "2026-10-21", "Hall", db_path=self.db)
        models.update_report_status(self.lost, "Potential Match", self.admin_id, "engine hint", db_path=self.db)
        self.cid = models.create_claim(self.found, self.sid_a, "{}", "9000000000", db_path=self.db)
        models.review_claim(self.cid, self.admin_id, "Approved", "ok", db_path=self.db)
        models.update_report_status(self.found, "Returned", self.admin_id, "handover", db_path=self.db)

    def test_every_required_event_is_recorded_with_actor_and_time(self):
        by_action = {}
        for r in self.rows("SELECT * FROM activity_log ORDER BY id"):
            by_action.setdefault(r["action"], []).append(r)
        for a in ("student.created", "staff.created", "report.lost_created", "report.found_created",
                  "report.status_changed", "claim.submitted", "claim.approved", "report.returned"):
            self.assertIn(a, by_action, a)
        lost_ev = by_action["report.lost_created"][0]
        self.assertEqual((lost_ev["actor_id"], lost_ev["actor_roll"], lost_ev["actor_name"]), (self.sid_a, "21CS001", "Asha Rao"))
        self.assertEqual((lost_ev["report_type"], lost_ev["category"]), ("lost", "Bottles & Flasks"))
        self.assertEqual(by_action["claim.submitted"][0]["actor_id"], self.sid_a)
        self.assertEqual(by_action["claim.approved"][0]["actor_roll"], "admin1")
        sc = [r for r in by_action["report.status_changed"] if r["report_id"] == self.lost][0]
        self.assertEqual((sc["old_status"], sc["new_status"], sc["actor_id"]), ("Open", "Potential Match", self.admin_id))
        for r in self.rows("SELECT timestamp FROM activity_log"):
            self.assertRegex(r["timestamp"], r"^\d{4}-\d\d-\d\dT")

    def test_filters(self):
        q = lambda **f: models.query_activity(f, db_path=self.db)[0]
        self.assertTrue(all(r["report_type"] == "lost" for r in q(report_type="lost")))
        self.assertTrue(q(report_type="lost"))
        self.assertTrue(all(r["category"] == "Clothing & Apparel" for r in q(category="Clothing & Apparel")))
        self.assertTrue(all(r["new_status"] == "Returned" for r in q(status="Returned")))
        self.assertEqual({r["action"] for r in q(action="claim.approved")}, {"claim.approved"})
        rolls = q(roll="21CS001")
        self.assertTrue(rolls and all("21CS001" in (r["actor_roll"] or "") + (r["target_roll"] or "") for r in rolls))
        self.assertEqual(q(date_from="2999-01-01"), [])
        self.assertTrue(q(date_from="2000-01-01", date_to="2999-12-31"))
        self.assertTrue(q(q="Blue Bottle"))
        self.assertEqual(q(q="'; DROP TABLE activity_log; --"), [])           # injection attempt is inert
        self.assertGreater(self.row("SELECT COUNT(*) n FROM activity_log")["n"], 5)
        page1, total = models.query_activity({}, limit=3, offset=0, db_path=self.db)
        self.assertEqual(len(page1), 3); self.assertGreater(total, 3)

    def test_log_is_append_only_even_at_sql_level(self):
        conn = models.get_db(self.db)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE activity_log SET details='tampered'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM activity_log")
        conn.close()
        # no HTTP route can modify it either
        a = self.admin_client()
        for method in (a.post, a.put, a.delete):
            self.assertIn(method("/admin/activity", data={"id": "1"}).status_code, (404, 405))

    def test_history_survives_hard_delete_of_user_and_report(self):
        sid = models.create_student("23XX001", "Temp Student", "9000000001", created_by=self.admin_id, db_path=self.db)
        models.delete_student(sid, self.admin_id, self.db)
        models.delete_report(self.lost, self.admin_id, self.db)
        evs = self.rows("SELECT * FROM activity_log WHERE action IN ('student.deleted','report.deleted')")
        self.assertEqual({e["action"] for e in evs}, {"student.deleted", "report.deleted"})
        self.assertTrue(self.rows("SELECT * FROM activity_log WHERE action='report.lost_created'"))
        self.assertEqual(self.rows("SELECT * FROM activity_log WHERE target_roll='23XX001' AND action='student.created'")[0]["target_name"], "Temp Student")

    def test_account_events_logged_and_no_secrets_anywhere_in_log(self):
        models.set_user_active(self.sid_b, False, self.admin_id, self.db)
        models.reset_student_password(self.sid_a, self.admin_id, "ID verified", self.db)
        models.update_student(self.sid_a, {"mobile": "9000099999"}, self.admin_id, self.db)
        self.settle_student(self.sid_a)
        c = self.app.test_client(); self.login(c, "21CS001", "NewPass12345")
        c.post("/auth/change-password", data={"current_password": "NewPass12345", "new_password": "FreshPass12345",
                                              "confirm_password": "FreshPass12345"})
        actions = {r["action"] for r in self.rows("SELECT action FROM activity_log")}
        self.assertTrue({"student.deactivated", "student.password_reset", "student.updated", "password.changed", "auth.login"} <= actions)
        blob = " ".join(" ".join(str(v) for v in r.values()) for r in self.rows("SELECT * FROM activity_log"))
        for secret in (MOBILE_A, MOBILE_B, "9000099999", ADMIN_PW, TEACHER_PW, "NewPass12345", "FreshPass12345", "scrypt"):
            self.assertNotIn(secret, blob, secret)

    def test_activity_page_permissions_and_rendering(self):
        html = self.admin_client().get("/admin/activity?type=lost&category=Bottles+%26+Flasks&roll=21CS001").data.decode()
        self.assertIn("Blue Bottle", html); self.assertNotIn("Red Hoodie", html)
        self.assertEqual(self.student_client().get("/admin/activity").status_code, 403)
        self.assertEqual(self.teacher_client().get("/admin/activity").status_code, 403)


# ---------------------------------------------------------------------------------------------
LEGACY_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL);
CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    report_type TEXT NOT NULL CHECK(report_type IN ('lost','found')), item_name TEXT NOT NULL, category TEXT NOT NULL,
    description TEXT NOT NULL, date_occurred TEXT NOT NULL, location TEXT NOT NULL, image_filename TEXT,
    distinguishing_features TEXT, private_contact TEXT,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Potential Match','Claim Pending','Verified','Returned','Closed')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE);
CREATE TABLE claims (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, claimant_id INTEGER NOT NULL,
    challenge_answers TEXT NOT NULL, claimant_contact TEXT NOT NULL, verification_notes TEXT,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected')),
    created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by INTEGER,
    FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
    FOREIGN KEY (claimant_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL);
CREATE TABLE audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, changed_by INTEGER NOT NULL,
    old_status TEXT NOT NULL, new_status TEXT NOT NULL, notes TEXT, timestamp TEXT NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by) REFERENCES users (id) ON DELETE CASCADE);
"""


def legacy_hash(pw):
    salt = b"0123456789abcdef"
    return binascii.hexlify(salt).decode() + "$" + binascii.hexlify(hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100000)).decode()


class TestDatabaseMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="findback-mig-")
        self.db = os.path.join(self.tmp, "legacy.sqlite")
        c = sqlite3.connect(self.db)
        c.executescript(LEGACY_SCHEMA)
        t = "2026-10-20T10:00:00.000000"
        c.execute("INSERT INTO users VALUES (1,'Old Admin','boss@findback.edu',?,'admin',?)", (legacy_hash("OldAdminPass1!"), t))
        c.execute("INSERT INTO users VALUES (2,'Old Student','old.s@campus.edu',?,'user',?)", (legacy_hash("OldStudent1!"), t))
        c.execute("INSERT INTO users VALUES (3,'Other Student','other@campus.edu',?,'user',?)", (legacy_hash("OldStudent1!"), t))
        c.execute("INSERT INTO reports (id,user_id,report_type,item_name,category,description,date_occurred,location,distinguishing_features,private_contact,status,created_at,updated_at) VALUES (1,3,'found','Silver Laptop','Electronics','desc','2026-10-19','Library','SECRET','PRIV','Returned',?,?)", (t, t))
        c.execute("INSERT INTO reports (id,user_id,report_type,item_name,category,description,date_occurred,location,status,created_at,updated_at) VALUES (2,2,'lost','My Laptop','Electronics','desc','2026-10-19','Library','Open',?,?)", (t, t))
        c.execute("INSERT INTO claims VALUES (1,1,2,'{\"x\":1}','999','approved ok','Approved',?,?,1)", (t, "2026-10-21T09:00:00.000000"))
        c.execute("INSERT INTO audit_logs VALUES (1,1,1,'Verified','Returned','handover','2026-10-22T09:00:00.000000')")
        c.commit(); c.close()
        init = __import__("models")
        self.models = init
        init.init_db(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def q(self, sql, p=()):
        c = self.models.get_db(self.db)
        try:
            return [dict(r) for r in c.execute(sql, p).fetchall()]
        finally:
            c.close()

    def test_all_existing_records_preserved(self):
        self.assertEqual(len(self.q("SELECT * FROM users")), 3)
        self.assertEqual(self.q("SELECT item_name, distinguishing_features, status FROM reports WHERE id=1"),
                         [{"item_name": "Silver Laptop", "distinguishing_features": "SECRET", "status": "Returned"}])
        self.assertEqual(self.q("SELECT challenge_answers, verification_notes, status FROM claims"),
                         [{"challenge_answers": '{"x":1}', "verification_notes": "approved ok", "status": "Approved"}])
        self.assertEqual(len(self.q("SELECT * FROM audit_logs")), 1)
        self.assertEqual(self.models.get_schema_version(self.db), 1)

    def test_backup_created_before_migration(self):
        backups = [f for f in os.listdir(self.tmp) if ".pre-erp-migration-" in f]
        self.assertEqual(len(backups), 1)
        b = sqlite3.connect(os.path.join(self.tmp, backups[0]))
        self.assertEqual(b.execute("SELECT COUNT(*) FROM users").fetchone()[0], 3)
        self.assertNotIn("roll_number", [r[1] for r in b.execute("PRAGMA table_info(users)")])
        b.close()

    def test_legacy_admin_gets_username_and_must_change_password(self):
        a = self.q("SELECT * FROM users WHERE id=1")[0]
        self.assertEqual((a["username"], a["must_change_password"], a["is_active"]), ("boss", 1, 1))
        self.assertTrue(self.models.verify_password(a["password_hash"], "OldAdminPass1!"))   # legacy hash still valid

    def test_legacy_students_kept_but_disabled_until_admin_completes_profile(self):
        for s in self.q("SELECT * FROM users WHERE role='user'"):
            self.assertEqual((s["is_active"], s["must_change_password"], s["roll_number"]), (0, 1, None))
        with self.assertRaises(self.models.ValidationError):
            self.models.set_user_active(2, True, 1, self.db)                      # no roll/mobile yet
        self.models.update_student(2, {"roll_number": "20CS050", "name": "Old Student", "mobile": "9811122233"}, 1, self.db)
        self.models.set_user_active(2, True, 1, self.db)
        self.models.reset_student_password(2, 1, "ID checked", self.db)
        self.assertTrue(self.models.verify_password(self.q("SELECT password_hash h FROM users WHERE id=2")[0]["h"], "9811122233"))
        # their old report is still theirs
        self.assertEqual(self.q("SELECT user_id u FROM reports WHERE id=2")[0]["u"], 2)

    def test_lifecycle_timestamps_and_history_backfilled(self):
        r = self.q("SELECT * FROM reports WHERE id=1")[0]
        self.assertEqual(r["returned_at"], "2026-10-22T09:00:00.000000")
        self.assertEqual(r["returned_by"], 1)
        acts = [a["action"] for a in self.q("SELECT action FROM activity_log")]
        for a in ("report.found_created", "report.lost_created", "claim.submitted", "claim.approved",
                  "report.status_changed", "account.migrated"):
            self.assertIn(a, acts)

    def test_migration_is_idempotent(self):
        before = self.q("SELECT COUNT(*) n FROM activity_log")[0]["n"]
        self.models.init_db(self.db)
        self.models.init_db(self.db)
        self.assertEqual(self.q("SELECT COUNT(*) n FROM activity_log")[0]["n"], before)
        self.assertEqual(len(self.q("SELECT * FROM schema_migrations")), 1)
        self.assertEqual(len([f for f in os.listdir(self.tmp) if ".pre-erp-migration-" in f]), 1)

    def test_constraints_installed(self):
        c = self.models.get_db(self.db)
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE users SET username='boss' WHERE id=2")
        with self.assertRaises(sqlite3.DatabaseError):
            c.execute("UPDATE users SET role='superuser' WHERE id=2")
        c.close()

    def test_app_boots_on_migrated_db_and_legacy_admin_can_log_in(self):
        from app import create_app
        app = create_app({"TESTING": True, "DATABASE": self.db, "UPLOAD_FOLDER": os.path.join(self.tmp, "u"),
                          "CAPTCHA_PROVIDER": "disabled", "CSRF_ENABLED": False, "SECRET_KEY": "k" * 40})
        c = app.test_client()
        r = c.post("/auth/login?portal=staff", data={"username": "boss", "password": "OldAdminPass1!"})
        self.assertIn("/auth/change-password", r.headers["Location"])
        r = c.post("/auth/change-password", data={"current_password": "OldAdminPass1!", "new_password": "BrandNew12345",
                                                   "confirm_password": "BrandNew12345"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/admin/dashboard").status_code, 200)
        self.assertIn("Silver Laptop", c.get("/admin/reports").data.decode())


if __name__ == "__main__":
    unittest.main()
