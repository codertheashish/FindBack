import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_all_tests():
    test_loader = unittest.TestLoader()
    test_dir = os.path.dirname(__file__)
    suite = test_loader.discover(start_dir=test_dir, pattern='test_*.py')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print("FINDBACK (SS-15) TEST EXECUTION SUMMARY:")
    print(f"Total Tests Run : {result.testsRun}")
    print(f"Failures        : {len(result.failures)}")
    print(f"Errors          : {len(result.errors)}")
    print(f"Skipped         : {len(result.skipped)}")
    print("Status          : " + ("ALL TESTS PASSED [✓]" if result.wasSuccessful() else "TESTS FAILED [✕]"))
    print("=" * 60)

    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_all_tests())
