"""Root-only focused control entry; inert on import."""
import sys
import unittest


if __name__ == '__main__':
    assert sys.argv[1:] == [] and sys.dont_write_bytecode is True
    from test_measurement import MeasurementControls
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MeasurementControls)
    assert suite.countTestCases() == 8
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert result.testsRun == 8 and result.wasSuccessful() and not result.skipped
