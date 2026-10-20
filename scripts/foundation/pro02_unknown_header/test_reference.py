"""Data-only final outcome accounting; never spawn a backend or actor."""
import importlib.util
from pathlib import Path
import unittest


class OutcomeTests(unittest.TestCase):
    def test_only_executed_cases_with_successful_cleanup_and_lifecycle_pass(self):
        path = Path(__file__).with_name("run_reference.py")
        spec = importlib.util.spec_from_file_location("unknown_header_reference", path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        for executed, success, status, passed, failed, blocked in [
                (0, False, "BLOCKED", 0, 0, 1), (1, False, "FAIL", 0, 1, 0),
                (1, True, "PASS", 1, 0, 0), (0, True, "BLOCKED", 0, 0, 1)]:
            with self.subTest(executed=executed, success=success):
                self.assertEqual(runner.case_outcome(executed, success), dict(
                    status=status, selected=1, executed=executed, passed=passed, failed=failed, blocked=blocked))


if __name__ == "__main__":
    unittest.main()
