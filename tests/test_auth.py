import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import init_db, create_user, get_user_by_email, verify_password, hash_password

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        init_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_password_hashing(self):
        raw = "SecurePassword123!"
        hashed = hash_password(raw)
        self.assertNotEqual(raw, hashed)
        self.assertTrue(verify_password(hashed, raw))
        self.assertFalse(verify_password(hashed, "WrongPassword"))

    def test_create_and_retrieve_user(self):
        uid = create_user("Test Student", "student@test.edu", "MySecret123!", role="user", db_path=self.db_path)
        self.assertIsNotNone(uid)

        user = get_user_by_email("student@test.edu", db_path=self.db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user['name'], "Test Student")
        self.assertEqual(user['role'], "user")

    def test_admin_user_role(self):
        admin_id = create_user("Security Chief", "admin@test.edu", "AdminPass123!", role="admin", db_path=self.db_path)
        admin = get_user_by_email("admin@test.edu", db_path=self.db_path)
        self.assertEqual(admin['role'], "admin")

    def test_duplicate_email_fails(self):
        create_user("User 1", "same@test.edu", "Pass1", db_path=self.db_path)
        with self.assertRaises(Exception):
            create_user("User 2", "same@test.edu", "Pass2", db_path=self.db_path)

if __name__ == '__main__':
    unittest.main()
