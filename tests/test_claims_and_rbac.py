import unittest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import (
    init_db, create_user, create_report, create_claim,
    get_claim_by_id, review_claim, get_report_by_id,
    get_audit_logs, update_report_status
)

class TestClaimsAndRBAC(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        init_db(self.db_path)
        self.finder_id = create_user("Bob Finder", "bob@campus.edu", "Pass123!", role="user", db_path=self.db_path)
        self.claimant_id = create_user("Clara Claimant", "clara@campus.edu", "Pass123!", role="user", db_path=self.db_path)
        self.admin_id = create_user("Security Admin", "admin@campus.edu", "AdminPass123!", role="admin", db_path=self.db_path)

        # Create found item
        self.report_id = create_report(
            user_id=self.finder_id,
            report_type='found',
            item_name='Silver Dell XPS 15',
            category='Electronics',
            description='Found silver laptop in library',
            date_occurred='2026-10-21',
            location='Library 2nd Floor',
            distinguishing_features='Linux sticker on palmrest, service tag ending 8X99',
            db_path=self.db_path
        )

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_claim_submission_advances_status(self):
        rep_before = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep_before['status'], 'Open')

        proof = json.dumps({"secret_mark": "Linux sticker on palmrest"})
        claim_id = create_claim(
            report_id=self.report_id,
            claimant_id=self.claimant_id,
            challenge_answers=proof,
            claimant_contact="+1 555-019-2834",
            db_path=self.db_path
        )
        self.assertIsNotNone(claim_id)

        # Verify report transitioned to 'Claim Pending'
        rep_after = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep_after['status'], 'Claim Pending')

        # Verify claim saved
        claim = get_claim_by_id(claim_id, db_path=self.db_path)
        self.assertEqual(claim['status'], 'Pending')
        self.assertEqual(claim['claimant_id'], self.claimant_id)

    def test_admin_approve_claim_verifies_item(self):
        proof = json.dumps({"secret_mark": "Linux sticker on palmrest"})
        claim_id = create_claim(
            report_id=self.report_id,
            claimant_id=self.claimant_id,
            challenge_answers=proof,
            claimant_contact="+1 555-019-2834",
            db_path=self.db_path
        )

        # Admin approves
        success = review_claim(
            claim_id=claim_id,
            reviewer_id=self.admin_id,
            action='Approved',
            notes="Physical inspection of laptop service tag matched 8X99.",
            db_path=self.db_path
        )
        self.assertTrue(success)

        # Report should now be 'Verified'
        rep = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep['status'], 'Verified')

        # Check audit trail recorded
        audits = get_audit_logs(self.report_id, db_path=self.db_path)
        self.assertGreaterEqual(len(audits), 2)
        latest_audit = audits[-1]
        self.assertEqual(latest_audit['new_status'], 'Verified')
        self.assertIn("Physical inspection", latest_audit['notes'])

    def test_admin_reject_claim_resets_status(self):
        proof = json.dumps({"secret_mark": "Wrong answer"})
        claim_id = create_claim(
            report_id=self.report_id,
            claimant_id=self.claimant_id,
            challenge_answers=proof,
            claimant_contact="+1 555-019-2834",
            db_path=self.db_path
        )

        success = review_claim(
            claim_id=claim_id,
            reviewer_id=self.admin_id,
            action='Rejected',
            notes="Claimant could not describe sticker or serial number.",
            db_path=self.db_path
        )
        self.assertTrue(success)

        # Report should revert to 'Open'
        rep = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep['status'], 'Open')

    def test_full_return_workflow_cycle(self):
        # Open -> Potential Match -> Claim Pending -> Verified -> Returned -> Closed
        update_report_status(self.report_id, 'Potential Match', self.admin_id, "Smart match flagged", db_path=self.db_path)
        rep = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep['status'], 'Potential Match')

        update_report_status(self.report_id, 'Returned', self.admin_id, "Handover completed at security desk", db_path=self.db_path)
        rep = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep['status'], 'Returned')

        update_report_status(self.report_id, 'Closed', self.admin_id, "Case resolved and archived", db_path=self.db_path)
        rep = get_report_by_id(self.report_id, db_path=self.db_path)
        self.assertEqual(rep['status'], 'Closed')

if __name__ == '__main__':
    unittest.main()
