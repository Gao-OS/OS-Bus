"""Execute the guest driver's cleanup boundary without starting a VM."""
from pathlib import Path
import json
import re
import subprocess
import tempfile
import unittest


class GuestCleanupTests(unittest.TestCase):
    def test_nix_input_excludes_unbound_python_bytecode(self):
        source = Path(__file__).with_name('packaged_test.nix').read_text()
        expression = re.search(r'fixtures = (builtins.path \{.*?\});', source, re.S)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'actor.py').write_text('bound source\n')
            (root / '__pycache__').mkdir()
            (root / '__pycache__/actor.cpython-313.pyc').write_bytes(b'unbound cached code')
            expression = expression.replace('path = ./.;', 'path = builtins.toPath ' + json.dumps(directory) + ';')
            result = subprocess.run(['nix-instantiate', '--eval', '--read-write-mode', '--strict', '--expr', 'toString (' + expression + ')'],
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            stored = Path(json.loads(result.stdout))
            self.assertEqual((stored / 'actor.py').read_bytes(), (root / 'actor.py').read_bytes())
            self.assertFalse((stored / '__pycache__').exists(), 'unbound bytecode could replace hashed source')

    def run_script(self, fail_at):
        source = Path(__file__).with_name('packaged_test.nix').read_text()
        script = source.split("  testScript = ''\n", 1)[1].rsplit("  '';", 1)[0]
        script = re.sub(r'\$\{[^}]*\}', '10', script)
        script = '\n'.join(line[4:] for line in script.splitlines())
        calls = []

        class Machine:
            def wait_for_unit(self, unit):
                calls.append(('wait', unit))
                if fail_at == 'wait':
                    raise RuntimeError('unit wait failed')

            def succeed(self, command, **options):
                calls.append(('command', command))
                if fail_at == 'setup' and command.startswith('install -d'):
                    raise RuntimeError('setup failed')
                if fail_at == 'controller' and 'packaged_qualify.py' in command:
                    raise RuntimeError('controller failed')
                return 'captured'

            def copy_from_vm(self, path, target):
                calls.append(('copy', path))
                if fail_at == 'export':
                    raise RuntimeError('export failed')

            def shutdown(self):
                calls.append(('shutdown',))

        def start_all():
            calls.append(('start',))
            if fail_at == 'start':
                raise RuntimeError('startup failed')

        namespace = {'machine': Machine(), 'start_all': start_all, 'print': lambda *args: None}
        if fail_at:
            with self.assertRaises(RuntimeError):
                exec(compile(script, 'packaged_test.nix:testScript', 'exec'), namespace)
        else:
            exec(compile(script, 'packaged_test.nix:testScript', 'exec'), namespace)
        return calls

    def test_start_and_setup_failures_still_attempt_export_and_poweroff(self):
        for stage in ('start', 'wait', 'setup', 'controller'):
            with self.subTest(stage=stage):
                calls = self.run_script(stage)
                self.assertIn(('copy', '/var/lib/osbus-p08-evidence'), calls)
                self.assertEqual(calls[-1], ('shutdown',))

    def test_export_failure_is_fatal_and_still_powers_off(self):
        calls = self.run_script('export')
        self.assertEqual(calls[-1], ('shutdown',))

    def test_success_exports_before_poweroff(self):
        calls = self.run_script(None)
        self.assertIn(('copy', '/var/lib/osbus-p08-evidence'), calls)
        self.assertEqual(calls[-1], ('shutdown',))


if __name__ == '__main__':
    unittest.main()
