import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import init_db, create_user, create_report, get_report_by_id, get_reports

class TestReports(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        init_db(self.db_path)
        self.user_id = create_user("Alice", "alice@campus.edu", "AlicePass123!", db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_create_lost_report(self):
        rep_id = create_report(
            user_id=self.user_id,
            report_type='lost',
            item_name='Blue HydroFlask',
            category='Bottles & Flasks',
            description='32oz cobalt blue water bottle with dent on base',
            date_occurred='2026-10-21',
            location='Gym Basketball Court',
            distinguishing_features='Sticker of Yosemite National Park',
            private_contact='alice@campus.edu / Room 204',
            db_path=self.db_path
        )
        self.assertIsNotNone(rep_id)

        rep = get_report_by_id(rep_id, db_path=self.db_path)
        self.assertEqual(rep['item_name'], 'Blue HydroFlask')
        self.assertEqual(rep['status'], 'Open')
        self.assertEqual(rep['category'], 'Bottles & Flasks')

    def test_search_and_filtering(self):
        create_report(
            user_id=self.user_id,
            report_type='lost',
            item_name='MacBook Pro M2',
            category='Electronics',
            description='Space gray laptop in black sleeve',
            date_occurred='2026-10-20',
            location='Engineering Hall Room 101',
            db_path=self.db_path
        )
        create_report(
            user_id=self.user_id,
            report_type='found',
            item_name='Leather Keychain with Fob',
            category='Keys',
            description='Honda car key with black fob',
            date_occurred='2026-10-21',
            location='Parking Lot A',
            db_path=self.db_path
        )

        # Filter by category
        res = get_reports(category='Electronics', db_path=self.db_path)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['item_name'], 'MacBook Pro M2')

        # Filter by keyword
        res2 = get_reports(keyword='Honda', db_path=self.db_path)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]['category'], 'Keys')

        # Filter by report type
        found_only = get_reports(report_type='found', db_path=self.db_path)
        self.assertEqual(len(found_only), 1)
        self.assertEqual(found_only[0]['item_name'], 'Leather Keychain with Fob')

if __name__ == '__main__':
    unittest.main()
