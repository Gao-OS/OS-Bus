"""Candidate17 FD03 mixed fixture, composing the unchanged strict oracle."""
import ast
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
def argument(name, default):
    return Path(sys.argv[sys.argv.index(name)+1]) if name in sys.argv else default
SHARED = argument('--shared', ROOT / 'scripts/foundation/p08_fd01_singleton_resources')
BUNDLES = argument('--bundles', ROOT / 'scripts/foundation/p08_fd03_different_bundles')
BUNDLE_CONTROLLER_SHA = '6c9c572e731dd44c66543c473b5c994fd48e11338dc0d5501304e06cfb86288a'
assert hashlib.sha256((BUNDLES / 'qualify.py').read_bytes()).hexdigest() == BUNDLE_CONTROLLER_SHA, 'original bundle controller drift'
old_argv = sys.argv
try:
    sys.argv = [*sys.argv, '--shared', str(SHARED)] if '--shared' not in sys.argv else sys.argv
    spec = importlib.util.spec_from_file_location('fd03_mixed_original_controller', BUNDLES / 'qualify.py')
    Q = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(Q)
finally:
    sys.argv = old_argv
S = Q.S
WORKLOAD = json.loads((HERE / 'workload.json').read_text())
expected = copy.deepcopy(Q.WORKLOAD)
expected.update(subcase='mixed-fd-no-fd', candidate_manifest_sha256='a27888106012b209b8941a4c7e5b9611764c7ceaa3ff2e27ebe9c753783a6c77')
expected['bundles']['serials'] = [100, 102]
expected['marker'] = dict(serial=101, member='Marker', signature='', body_hex='', rights=0, header9='absent')
expected['authority_seconds'] = 60
assert WORKLOAD == expected, 'mixed workload/cap/deadline drift'
PASS = 'passed_independent_fd03_mixed_fd_no_fd_core'
SELECTION = ['FD-03/core/mixed-fd-no-fd/gao', 'FD-03/core/mixed-fd-no-fd/reference']
NAMES = {'actor': 'actor.py', 'actor_test': 'actor_test.py', 'qualify': 'qualify.py', 'oracle_test': 'oracle_test.py',
         'workload': 'workload.json', 'test_nix': 'test.nix', 'readme': 'README.md'}
BUNDLE_FILES = {'bundle_'+key: BUNDLES / filename for key, filename in NAMES.items()}
INPUT_KEYS = Q.INPUT_KEYS | set(BUNDLE_FILES)
SHAPES = {}
NS = dict(Q.NS)
NS.update(HERE=HERE, WORKLOAD=WORKLOAD, PASS=PASS, SELECTION=SELECTION, INPUT_KEYS=INPUT_KEYS,
          S=S, SHARED=SHARED, SHARED_FILES=Q.SHARED_FILES, ORIGINAL_SHA=Q.ORIGINAL_SHA, ACTOR_SHA=Q.ACTOR_SHA)

def rebound(fn, namespace):
    return types.FunctionType(fn.__code__, namespace, fn.__name__, fn.__defaults__, fn.__closure__)

def record_authority(report):
    started = report['started_monotonic']
    finished = time.monotonic()
    report['authority'] = dict(limit_seconds=WORKLOAD['authority_seconds'], started_monotonic=started,
                               finished_monotonic=finished, elapsed_seconds=finished-started)

def assert_authority(report):
    authority = report['authority']
    assert set(authority) == {'limit_seconds', 'started_monotonic', 'finished_monotonic', 'elapsed_seconds'}
    assert type(authority['limit_seconds']) is int and authority['limit_seconds'] == WORKLOAD['authority_seconds'] == 60
    assert authority['started_monotonic'] == report['started_monotonic']
    for key in ('started_monotonic', 'finished_monotonic'):
        assert type(authority[key]) in (int, float) and S.math.isfinite(authority[key])
    assert authority['elapsed_seconds'] == authority['finished_monotonic']-authority['started_monotonic']
    S.latency(authority['elapsed_seconds'], WORKLOAD['authority_seconds'])
    assert authority['elapsed_seconds'] <= report['elapsed_seconds']

@contextmanager
def authority_budget(report):
    # Both sequential backends share the one original report start. A new
    # backend never obtains a fresh60s budget. SIGALRM interrupts blocked work;
    # the unchanged backend finally still contains its owned processes/logs.
    remaining = report['started_monotonic'] + WORKLOAD['authority_seconds'] - time.monotonic()
    assert remaining > 0, 'FD03 authority60 deadline'
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'occupied authority timer'
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_number, _frame):
        raise TimeoutError('FD03 authority60 deadline')
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        record_authority(report)

# Reuse the existing exact per-resource oracle. Ordinals0/2 map serial100/102;
# this namespace changes no raw receipt and retains every index/identity check.
transfer_ns = dict(Q.NS)
transfer_ns['CONTENTS'] = {0: b'FD-A', 2: b'FD-B'}
original_transfer = rebound(Q._assert_transfer, transfer_ns)
def assert_transfer(row, ordinal):
    assert type(ordinal) is int and ordinal in (0, 1)
    return original_transfer(row, 2*ordinal)
bundle_ns = dict(Q.assert_exercise.__globals__)
bundle_ns['_assert_transfer'] = assert_transfer
original_exercise = rebound(Q.assert_exercise, bundle_ns)

def assert_marker(row, connections):
    assert set(row) == {'sent', 'received'}, 'missing/unexpected marker data'
    source, target = connections
    for direction in ('sent', 'received'):
        event = row[direction]
        frame = S.assert_wire(event)
        fields = {'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Marker', '6': target['name'], '8': ''}
        if direction == 'received':
            fields['7'] = source['name']
            assert event['fd_targets'] == [], 'marker received an FD'
        assert frame == dict(type=4, serial=101, fields=fields, body_hex='', flags=0), 'marker raw wire/header mismatch'
        assert event['role'] == ('source' if direction == 'sent' else 'target')
        assert event['phase'] == 'active' and event['direction'] == direction and event['rights'] == 0
    assert row['sent']['send_operation'] == 'sendall'
    assert row['sent']['completed_bytes'] == row['sent']['wire_bytes']

def assert_exercise(row):
    original_exercise(row)
    assert_marker(row['marker'], row['connections'])

f = Q.function('assert_closed')
f = Q.replace_statement(f, "t=exercise['transfer']", "transfers=exercise['transfers']")
f = Q.replace_statement(f, "owned=[('received',t['received_fd']),('original',t['source_fd'])]",
                        "owned=[(f'received-{i}',t['received_fd']) for i,t in enumerate(transfers)]+[(f'original-{i}',t['source_fd']) for i,t in enumerate(transfers)]")
f = Q.replace_statement(f, "active={'source':[exercise['health'][0]['received']], 'target':[t['received'],exercise['health'][1]['received']]}",
                        "active={'source':[exercise['health'][0]['received']], 'target':[transfers[0]['received'],exercise['marker']['received'],transfers[1]['received'],exercise['health'][1]['received']]}")
def compile_function(name, fn):
    SHAPES[fn.name] = dict(original_function=name,
                           original_ast_sha256=hashlib.sha256(ast.dump(Q.function(name), include_attributes=False).encode()).hexdigest(),
                           executed_ast_sha256=hashlib.sha256(ast.dump(fn, include_attributes=False).encode()).hexdigest())
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), str(HERE / 'qualify.py'), 'exec'), NS)
    return NS[fn.name]
assert_closed = compile_function('assert_closed', f)

def probe_retired(wrapper, actual, waited, returncode, timed_out=False, errors=()):
    record = dict(wrapper_pid=wrapper, actual_pid=actual, wrapper_waited=waited, wrapper_returncode=returncode,
                  timed_out=timed_out, errors=list(errors), pid_absent=False, actor_pid_absent=False, group_absent=False)
    try:
        record['pid_absent'] = not Path('/proc', str(wrapper)).exists()
        record['actor_pid_absent'] = actual is not None and not Path('/proc', str(actual)).exists()
        record['group_members'] = S.group_members(wrapper)
        record['group_absent'] = record['group_members'] == []
    except Exception as error:
        record['errors'].append(repr(error))
    return record

def assert_retired(record, wrapper, actual, accepted_codes=(0,)):
    assert record['wrapper_pid'] == wrapper and record['actual_pid'] == actual
    assert record['wrapper_waited'] is True and record['wrapper_returncode'] in accepted_codes
    assert record['timed_out'] is False and record['errors'] == []
    assert record['pid_absent'] is record['actor_pid_absent'] is record['group_absent'] is True
    assert record['group_members'] == []

def stop_channel(channel, actual_pid, deadline):
    waited, returncode, timed_out, errors = False, None, False, []
    try:
        channel.process.stdin.close()
        remaining = deadline-time.monotonic()
        assert remaining > 0, 'pre-containment teardown deadline'
        try:
            returncode = channel.process.wait(timeout=remaining)
            waited = True
        except subprocess.TimeoutExpired:
            timed_out = True
    except Exception as error:
        errors.append(repr(error))
    before = probe_retired(channel.process.pid, actual_pid, waited, returncode, timed_out, errors)
    # Original containment/log draining remains unconditional and cannot certify
    # the pre-containment record, even when its final groups are absent.
    result = channel.stop(grace=0)
    result['before_containment'] = before
    return result

NS.update(assert_exercise=assert_exercise, assert_closed=assert_closed, stop_channel=stop_channel,
          probe_retired=probe_retired, assert_retired=assert_retired, resources=Q.resources)
f = Q.function('assert_report')
f = Q.replace_statement(f, "assert (report['schema'],report['requirement'],report['subcase'],report['profile'])==(1,'FD-01','pipe','core')",
                        "assert (report['schema'],report['requirement'],report['subcase'],report['profile'])==(1,'FD-03','mixed-fd-no-fd','core')")
f = Q.replace_statement(f, "resources=[c['exercise']['transfer'][key] for key in ('source_fd','received_fd')]",
                        "resources=[t[key] for t in c['exercise']['transfers'] for key in ('source_fd','received_fd')]")
f = Q.replace_statement(f, "assert len({(r['dev'],r['ino'],r['target']) for r in resources})==1",
                        "assert len(resources)==4 and len({(r['dev'],r['ino'],r['target']) for r in resources})==2")
base_report = compile_function('assert_report', f)
def assert_report(report):
    base_report(report)
    assert_authority(report)
    assert report['adapter_provenance'] == ADAPTER_PROVENANCE
    assert report['inputs_before']['shared_qualify']['sha256'] == Q.ORIGINAL_SHA
    assert report['inputs_before']['shared_actor']['sha256'] == Q.ACTOR_SHA
    assert report['inputs_before']['bundle_qualify']['sha256'] == BUNDLE_CONTROLLER_SHA
    for combination in report['combinations']:
        teardown = combination['teardown']
        assert_retired(teardown['actor']['before_containment'], combination['launcher']['pid'], combination['actor']['pid'])
        codes = (0,) if combination['backend'] == 'gao' else (0, -15)
        assert_retired(teardown['backend']['before_containment'], combination['broker']['pid'], combination['broker']['pid'], codes)

def capture_inputs(args, manifest):
    assert args.shared.resolve() == SHARED.resolve() and args.bundles.resolve() == BUNDLES.resolve()
    base = rebound(Q.capture_inputs, NS)(args, manifest)
    for key, path in BUNDLE_FILES.items():
        assert path.is_absolute() and path.is_file()
        base[key] = dict(path=str(path), sha256=S.sha(path))
    assert set(base) == INPUT_KEYS
    assert base['bundle_qualify']['sha256'] == BUNDLE_CONTROLLER_SHA
    return base
NS.update(assert_report=assert_report, capture_inputs=capture_inputs)

f = Q.function('run_backend')
f = Q.replace_statement(f, "command=[inputs['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir)]",
                        "command=[inputs['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir),str(args.shared),str(args.bundles)]")
f = Q.replace_statement(f, "for key in ('source_fd','received_fd'):\n resource=receipt['transfer'][key]\n assert resource in row['actor']['fds']\n assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])",
                        "for resource in resources(receipt):\n assert resource in row['actor']['fds']\n assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])")
f = Q.replace_statement(f, "st['actor']=actor.stop(grace=1)", "st['actor']=stop_channel(actor,actor_pid,started+1)")
f = Q.replace_statement(f, "st['backend']=daemon.stop(grace=1)", "st['backend']=stop_channel(daemon,broker_pid,started+1)")
f = Q.replace_statement(f, "st['backend']=dict(pid=reference.pid,method='kill' if st.get('backend_timeout') else 'sigterm',returncode=reference.returncode,command=reference.args)",
                        "st['backend']=dict(pid=reference.pid,method='kill' if st.get('backend_timeout') else 'sigterm',returncode=reference.returncode,command=reference.args)\nst['backend']['before_containment']=probe_retired(reference.pid,broker_pid,reference.poll() is not None,reference.returncode,st.get('backend_timeout',False))")
f = Q.replace_statement(f, "success=(stop.get('method')=='eof' and stop.get('returncode')==0 if backend=='gao' else stop.get('method')=='sigterm' and stop.get('returncode') in (0,-15))",
                        "success=(stop.get('method')=='eof' and stop.get('returncode')==0 if backend=='gao' else stop.get('method')=='sigterm' and stop.get('returncode') in (0,-15))\ntry:\n assert_retired(actor_stop['before_containment'],actor.process.pid,actor_pid)\n assert_retired(stop['before_containment'],broker_pid,broker_pid,(0,) if backend=='gao' else (0,-15))\nexcept Exception as error:\n c['status']='failed'\n c.setdefault('error','pre-containment teardown acceptance failed: '+repr(error))")
base_run_backend = compile_function('run_backend', f)
def run_backend(args, report, backend, channels, save):
    before = len(report['combinations'])
    try:
        with authority_budget(report):
            result = base_run_backend(args, report, backend, channels, save)
        S.latency(report['authority']['elapsed_seconds'], WORKLOAD['authority_seconds'])
        return result
    except Exception as error:
        record_authority(report)
        if len(report['combinations']) == before:
            report['combinations'].append(dict(backend=backend, status='blocked', reason=repr(error)))
        else:
            report['combinations'][-1].update(status='failed', error=repr(error))
        save()
        return False
NS.update(run_backend=run_backend, record_authority=record_authority)

f = Q.function('main')
f = Q.replace_statement(f, "for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope'):\n parser.add_argument('--'+name,required=True,type=Path)",
                        "for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','shared','bundles'):\n parser.add_argument('--'+name,required=True,type=Path)")
f = Q.replace_statement(f, "report['elapsed_seconds']=time.monotonic()-report['started_monotonic']",
                        "record_authority(report)\nreport['elapsed_seconds']=time.monotonic()-report['started_monotonic']")
class MainLabels(ast.NodeTransformer):
    def __init__(self):
        self.counts = {'FD-01': 0, 'pipe': 0}
    def visit_Constant(self, node):
        if node.value in self.counts:
            self.counts[node.value] += 1
            return ast.Constant(value='FD-03' if node.value == 'FD-01' else 'mixed-fd-no-fd')
        return node
labels = MainLabels()
f = labels.visit(f)
assert labels.counts == {'FD-01': 1, 'pipe': 1}
reports = [n for n in f.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'report' for t in n.targets)]
assert len(reports) == 1
reports[0].value.keywords.append(ast.keyword(arg='adapter_provenance', value=ast.Name(id='ADAPTER_PROVENANCE', ctx=ast.Load())))
main = compile_function('main', f)
ADAPTER_PROVENANCE = dict(original_bundle_controller_sha256=BUNDLE_CONTROLLER_SHA,
                          original_bundle_adaptation=Q.ADAPTER_PROVENANCE,
                          executed_adapter_sha256=S.sha(HERE / 'qualify.py'), frozen_exact_node_adaptations=SHAPES,
                          resource_oracle_ordinals=[0, 2])
NS['ADAPTER_PROVENANCE'] = ADAPTER_PROVENANCE

if __name__ == '__main__':
    main()
