"""Exact native-only SEC16 fixture projection; all backend checks are retained."""
import hashlib
import stat

SELECTION = 'complete_core_gao_v1'
RESULT = 'passed_native_core_SEC16_runtime_pending_independent_review'
PATCHES = {
    'contract.py': [
        ("SELECTED = [SCENARIO + '/' + backend + '/core' for backend in BACKENDS]",
         "EXECUTION_BACKENDS = ['gao_bus']\nEXECUTION_SELECTION = 'complete_core_gao_v1'\nSELECTED = [SCENARIO + '/' + backend + '/core' for backend in EXECUTION_BACKENDS]"),
        ('\n\ndef bounded(value, maximum):',
         "\n\nEXECUTION_SCOPE = dict(version=1, backend_order=EXECUTION_BACKENDS, selected=SELECTED,\n                      case_order=CASES, positive_controls=2, actors=8, bounds=BOUNDS)\n\ndef bounded(value, maximum):"),
        ("    assert report['selected'] == SELECTED and [b['backend'] for b in report['backends']] == BACKENDS",
         "    assert report['version'] == 2 and report['fixture'] == 'complete-core-sec16-native-v1'\n    assert report['execution_selection'] == EXECUTION_SELECTION\n    assert report['execution_scope'] == EXECUTION_SCOPE and report['workload_role'] == 'original-paired-corpus'\n    assert report['selected'] == SELECTED and [b['backend'] for b in report['backends']] == EXECUTION_BACKENDS"),
        ("    assert report['counts'] == dict(selected=2, executed=2, passed=2, failed=0, blocked=0, skipped=0)",
         "    assert report['counts'] == dict(selected=1, executed=1, passed=1, failed=0, blocked=0, skipped=0)"),
        ('passed_complete_core_SEC16_runtime_pending_independent_review', RESULT),
    ],
    'run.py': [
        ("                current['receipts'].append(receipt)\n                persist()\n                assert time.monotonic() <= limit, 'SEC16 request exceeded fixed caller deadline'",
         "                current['receipts'].append(receipt)\n                assert time.monotonic() <= limit, 'SEC16 request exceeded fixed caller deadline'"),
        ('from contract import (BUS, SCENARIO, BACKENDS, SELECTED, CASES, OBSERVER,',
         'from contract import (BUS, SCENARIO, SELECTED, CASES, OBSERVER,\n                      EXECUTION_BACKENDS, EXECUTION_SELECTION, EXECUTION_SCOPE,'),
        ("    assert selection == 'complete_core' and sys.flags.optimize == 0",
         '    assert selection == EXECUTION_SELECTION and sys.flags.optimize == 0'),
        ("    report = dict(version=1, fixture='complete-core-sec16', selected=SELECTED,",
         "    report = dict(version=2, fixture='complete-core-sec16-native-v1', selected=SELECTED,\n                  execution_selection=selection, execution_scope=EXECUTION_SCOPE,\n                  workload_role='original-paired-corpus',"),
        ("        report['counts'] = dict(selected=2, executed=passed+failed, passed=passed,\n                               failed=failed, blocked=2-passed-failed, skipped=0)",
         "        report['counts'] = dict(selected=len(EXECUTION_BACKENDS), executed=passed+failed, passed=passed,\n                               failed=failed, blocked=len(EXECUTION_BACKENDS)-passed-failed, skipped=0)"),
        ('        for backend in BACKENDS:', '        for backend in EXECUTION_BACKENDS:'),
        ('passed_complete_core_SEC16_runtime_pending_independent_review', RESULT),
    ],
    'test_contract.py': [
        ('    return dict(selected=contract.SELECTED,backends=[backend(name) for name in contract.BACKENDS],counts=dict(selected=2,executed=2,passed=2,failed=0,blocked=0,skipped=0),bounds=contract.BOUNDS,',
         "    return dict(version=2,fixture='complete-core-sec16-native-v1',execution_selection=contract.EXECUTION_SELECTION,execution_scope=contract.EXECUTION_SCOPE,workload_role='original-paired-corpus',selected=contract.SELECTED,backends=[backend(name) for name in contract.EXECUTION_BACKENDS],counts=dict(selected=1,executed=1,passed=1,failed=0,blocked=0,skipped=0),bounds=contract.BOUNDS,"),
        ('passed_complete_core_SEC16_runtime_pending_independent_review', RESULT),
        ("value=complete();value['counts']['executed']=1;self.rejects(contract.validate_complete,value)",
         "value=complete();value['counts']['executed']+=1;self.rejects(contract.validate_complete,value)"),
        ('class Sec16Controls(unittest.TestCase):\n',
         "class Sec16Controls(unittest.TestCase):\n    def test_native_selection_is_exact(self):\n        value=complete();contract.validate_complete(value)\n        self.assertEqual(contract.EXECUTION_BACKENDS,['gao_bus'])\n        self.assertEqual(contract.SELECTED,[contract.SCENARIO+'/gao_bus/core'])\n        for selection in ('complete_core','reference','',None):\n            value=complete();value['execution_selection']=selection;self.rejects(contract.validate_complete,value)\n\n    def test_native_rejects_wrong_execution_scope_or_count(self):\n        for count in (0,2):\n            value=complete();value['counts']['executed']=count;self.rejects(contract.validate_complete,value)\n            value=complete();value['counts']['selected']=count;self.rejects(contract.validate_complete,value)\n        for backends in ([],[backend('reference')],[backend('gao_bus'),backend('gao_bus')],[backend('reference'),backend('gao_bus')]):\n            value=complete();value['backends']=backends;self.rejects(contract.validate_complete,value)\n        value=complete();value['execution_scope']=dict(contract.EXECUTION_SCOPE,actors=7);self.rejects(contract.validate_complete,value)\n        value=complete();value['workload_role']='native-runtime';self.rejects(contract.validate_complete,value)\n\n"),
    ],
}


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), mode=stat.S_IMODE(path.stat().st_mode),
                sha256=hashlib.sha256(raw).hexdigest())


def project(copied):
    provenance = {}
    for name, replacements in PATCHES.items():
        path = copied / name
        before = pin(path)
        original = path.read_bytes()
        patched = original
        for old, new in replacements:
            old, new = old.encode(), new.encode()
            assert patched.count(old) == 1 and new not in patched, name
            patched = patched.replace(old, new)
        restored = patched
        for old, new in reversed(replacements):
            old, new = old.encode(), new.encode()
            assert restored.count(new) == 1, name
            restored = restored.replace(new, old)
        assert restored == original, name
        path.chmod(0o644)
        path.write_bytes(patched)
        path.chmod(before['mode'])
        provenance[name] = dict(before=before, after=pin(path),
            replacements=[dict(original=old, replacement=new) for old, new in replacements],
            inverse_byte_exact=True)
    return provenance
