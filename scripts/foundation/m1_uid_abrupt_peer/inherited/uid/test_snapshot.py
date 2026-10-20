"""Replay one saved live baseline through the actual validator; no OS peers.

Historical /proc text substitutes only for the now-dead guest process. This
does not qualify current kernel identity, quota trials, timing or VM cleanup.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get('UID_SNAPSHOT_SOURCE', str(HERE / 'run.py')))
spec = importlib.util.spec_from_file_location('uid_snapshot_validator', SOURCE)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
sample = json.loads((HERE.parent / 'reference-repair1/baseline-sample1.json').read_text())


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.state = copy.deepcopy(sample['state'])
        self.actors = copy.deepcopy(sample['actors'])
        self.peer = self.state['peers'][0]['peer']

    def recorded_identity(self, pid, uid):
        self.assertEqual(pid, sample['actors'][0]['identity']['pid'])
        self.assertEqual(uid, sample['actors'][0]['identity']['uid'])
        for key in ('Uid:', 'Gid:'):
            line = next(x for x in sample['proc_status'].splitlines() if x.startswith(key))
            self.assertEqual([int(x) for x in line.split()[1:]], [uid] * 4)
        return sample['proc_status']

    def validate(self):
        with patch.object(runner, 'identity', self.recorded_identity):
            return runner.validate(self.state, self.actors,
                                   sample['state']['uid_authorities']['authorities'])

    def require_baseline(self):
        joined = self.validate()
        self.assertEqual(set(joined), {self.peer})
        self.assertEqual(joined[self.peer]['identity'], sample['actors'][0]['identity'])
        self.assertEqual(joined[self.peer]['unique'], sample['actors'][0]['unique'])
        self.assertEqual(joined[self.peer]['proc_status'], sample['proc_status'])

    def test_actual_elixir_admission_entry_and_local_monitors_join(self):
        self.require_baseline()

    def test_short_alias_is_rejected_at_every_reference_position(self):
        self.require_baseline()
        for location in ('admission', 'entry', 'name_monitor', 'match_monitor'):
            with self.subTest(location=location):
                self.state = copy.deepcopy(sample['state'])
                self.actors = copy.deepcopy(sample['actors'])
                extra = self.state['uid_authorities']
                if location == 'admission':
                    extra['accounting']['peers'][self.peer]['monitor'] = '#Ref<0.1.2.3>'
                elif location == 'entry':
                    extra['matches']['entries'][0][1] = '#Ref<0.1.2.3>'
                else:
                    kind = 'names' if location == 'name_monitor' else 'matches'
                    extra[kind]['peers'][self.peer]['monitor'] = '#Ref<0.1.2.3>'
                with self.assertRaises(AssertionError):
                    self.validate()

    def test_admission_incarnation_and_cached_identity_are_required(self):
        self.require_baseline()
        for field, replacement in [('admission', '#Reference<0.1.2.3>'), ('uid', 1100)]:
            with self.subTest(field=field):
                self.state = copy.deepcopy(sample['state'])
                self.actors = copy.deepcopy(sample['actors'])
                self.state['uid_authorities']['names']['peers'][self.peer][field] = replacement
                with self.assertRaises(AssertionError):
                    self.validate()

    def test_retained_entries_determine_exact_uid_credit(self):
        self.require_baseline()
        for kind in ('names', 'matches'):
            with self.subTest(kind=kind):
                self.state = copy.deepcopy(sample['state'])
                self.actors = copy.deepcopy(sample['actors'])
                self.state['uid_authorities'][kind]['uid_counts']['0'] = 2
                with self.assertRaisesRegex(AssertionError, 'UID count differs'):
                    self.validate()


if __name__ == '__main__':
    unittest.main()
