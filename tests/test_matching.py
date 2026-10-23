import unittest
import sys
import os

# Ensure findback is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from matching import (
    calculate_match,
    calculate_category_score,
    calculate_location_score,
    calculate_date_score,
    calculate_content_similarity,
    find_matches_for_report
)

class TestMatchingAlgorithm(unittest.TestCase):
    def test_exact_category_match(self):
        score, exp = calculate_category_score('Electronics', 'Electronics')
        self.assertEqual(score, 1.0)
        self.assertIn("Exact category match", exp)

    def test_synonym_category_match(self):
        score, exp = calculate_category_score('Electronics', 'Tech')
        self.assertEqual(score, 0.7)
        self.assertIn("Related category cluster", exp)

    def test_different_category(self):
        score, exp = calculate_category_score('Electronics', 'Books & Stationery')
        self.assertEqual(score, 0.0)

    def test_location_proximity(self):
        # Substring match
        score, exp, shared = calculate_location_score("Main Library 2nd Floor", "Library 2nd Floor East")
        self.assertGreaterEqual(score, 0.4)
        self.assertIn("library", shared)

    def test_date_proximity_same_day(self):
        score, exp = calculate_date_score("2026-10-22", "2026-10-22")
        self.assertEqual(score, 1.0)

    def test_date_proximity_few_days(self):
        score, exp = calculate_date_score("2026-10-20", "2026-10-22")
        self.assertEqual(score, 0.75)

    def test_high_confidence_match(self):
        lost = {
            'id': 1,
            'report_type': 'lost',
            'category': 'Electronics',
            'item_name': 'Dell XPS 15 Laptop',
            'description': 'Silver Dell laptop with programming stickers',
            'location': 'Main Library 2nd Floor Silent Room',
            'distinguishing_features': 'Linux penguin sticker on palmrest',
            'date_occurred': '2026-10-20'
        }
        found = {
            'id': 2,
            'report_type': 'found',
            'category': 'Electronics',
            'item_name': 'Silver Dell XPS',
            'description': 'Found a silver Dell laptop left on table',
            'location': 'Library 2nd Floor',
            'distinguishing_features': 'Linux penguin decal on keyboard',
            'date_occurred': '2026-10-21'
        }

        result = calculate_match(lost, found)
        self.assertGreaterEqual(result['score'], 75)
        self.assertEqual(result['confidence'], 'High')
        self.assertEqual(len(result['explanations']), 4)
        self.assertIn('dell', result['shared_keywords'])

    def test_unrelated_items_low_score(self):
        lost = {
            'id': 1,
            'report_type': 'lost',
            'category': 'Keys',
            'item_name': 'Car Key with Hyundai Fob',
            'description': 'Black key fob with silver key ring',
            'location': 'Parking Lot B',
            'distinguishing_features': 'Gym tag 104',
            'date_occurred': '2026-10-01'
        }
        found = {
            'id': 3,
            'report_type': 'found',
            'category': 'Clothing & Apparel',
            'item_name': 'Red Nike Hoodie',
            'description': 'Red hoodie sweatshirt size large',
            'location': 'Gym Locker Room',
            'distinguishing_features': '',
            'date_occurred': '2026-10-22'
        }

        result = calculate_match(lost, found)
        self.assertLess(result['score'], 25)
        self.assertEqual(result['confidence'], 'Unlikely')

if __name__ == '__main__':
    unittest.main()
