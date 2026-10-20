"""Inert complete-report and retirement controls; zero broker/VM executions."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
controller = HERE / 'qualify.py'
if '--before-authority' in sys.argv:
    index = sys.argv.index('--before-authority')
    controller = Path(sys.argv[index+1]) / 'qualify.py'
    del sys.argv[index:index+2]
Q = load('fd03_mixed_oracle_controls', controller)
O = load('fd03_mixed_original_synthetic_controls', Q.BUNDLES / 'oracle_test.py')
for option in ('--shared', '--bundles'):
    if option in sys.argv:
        index = sys.argv.index(option)
        del sys.argv[index:index+2]
PREDECESSOR = '--predecessor' in sys.argv
if PREDECESSOR:
    sys.argv.remove('--predecessor')

def exercise(before):
    row = copy.deepcopy(before)
    transfer = row['transfers'][1]
    transfer['serial'] = 102
    for direction in ('sent', 'received'):
        event = transfer[direction]
        raw = bytearray.fromhex(event['wire_hex'])
        struct.pack_into('<I', raw, 8, 102)
        event.update(serial=102, wire_hex=raw.hex(), wire_sha256=hashlib.sha256(raw).hexdigest())
    source, target = row['connections']
    fields = [(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Marker'),(6,'s',target['name']),(8,'g','')]
    sent = O.O.message('source', 'sent', 4, 101, fields, b'', 0)
    sent.update(completed_bytes=sent['wire_bytes'], send_operation='sendall')
    received = O.O.message('target', 'received', 4, 101, fields+[(7,'s',source['name'])], b'', 0, targets=[])
    row['marker'] = dict(sent=sent, received=received)
    return row

def closed(row, op='close'):
    result = O.closed(row, op)
    result['events']['target'].insert(len(row['connections'][1]['setup'])+1, row['marker']['received'])
    return result

def retired(wrapper, actual, code=0):
    return dict(wrapper_pid=wrapper, actual_pid=actual, wrapper_waited=True, wrapper_returncode=code,
                timed_out=False, errors=[], pid_absent=True, actor_pid_absent=True, group_absent=True, group_members=[])

def valid_report():
    report = O.valid_report()
    report.update(subcase='mixed-fd-no-fd', workload=copy.deepcopy(Q.WORKLOAD), selection=Q.SELECTION,
                  result=Q.PASS, adapter_provenance=copy.deepcopy(Q.ADAPTER_PROVENANCE),
                  synthetic=True, runtime_execution=dict(broker=0, vm=0))
    report['started_monotonic'] = 100
    report['authority'] = dict(limit_seconds=60, started_monotonic=100,
                               finished_monotonic=101, elapsed_seconds=1)
    report['inputs_before']['candidate_manifest']['sha256'] = Q.WORKLOAD['candidate_manifest_sha256']
    for key, path in Q.BUNDLE_FILES.items():
        report['inputs_before'][key] = dict(path=str(path), sha256=Q.S.sha(path))
    report['inputs_after'] = copy.deepcopy(report['inputs_before'])
    for combination in report['combinations']:
        for key in ('exercise',):
            combination[key] = exercise(combination[key])
        combination['close'] = closed(combination['exercise'])
        warmup = combination['warmup']
        warmup['exercise'] = exercise(warmup['exercise'])
        warmup['close'] = closed(warmup['exercise'], 'warmup-close')
        for operation, key in zip(combination['operations'], ('warmup','open','exercise','close')):
            operation['response'] = {'ok': True, 'result': combination[key]}
        teardown = combination['teardown']
        teardown['actor']['before_containment'] = retired(combination['launcher']['pid'], combination['actor']['pid'])
        teardown['backend']['before_containment'] = retired(combination['broker']['pid'], combination['broker']['pid'])
    return report

def checked_report(report):
    # Explicit unchanged-predecessor comparison, not synthetic runtime evidence.
    return (O.Q.assert_report if PREDECESSOR else Q.assert_report)(report)

class CompleteReport(unittest.TestCase):
    def test_complete_mixed_synthetic_report(self):
        checked_report(valid_report())
    def test_actual_marker_is_in_both_warmup_and_active_transcripts(self):
        report = valid_report(); checked_report(report)
        for c in report['combinations']:
            self.assertEqual([event['serial'] for event in c['close']['events']['target'][-4:]], [100,101,102,1111])
    def test_inherited_full_oracle_controls_remain_effective(self):
        for name in O.BASE_CONTROLS:
            with self.subTest(control=name):
                report = valid_report(); Q.assert_report(report)
                O.O.MUTATIONS[name](report)
                with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError,struct.error)):
                    Q.assert_report(report)
    def test_all_predecessor_bundle_mutations_reject_complete_mixed_reports(self):
        attempted = []
        for name, mutate in sorted(O.MUTATIONS.items()):
            with self.subTest(control=name):
                report = valid_report(); Q.assert_report(report)
                mutate(report)  # Mutation/setup errors are outside expected rejection.
                attempted.append(name)
                with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError,struct.error)):
                    Q.assert_report(report)
        self.assertEqual(attempted, sorted(O.MUTATIONS))
    def test_complete_report_accepts_measured_bounded_authority(self):
        report = valid_report()
        report.update(elapsed_seconds=60)
        report['authority'].update(finished_monotonic=160, elapsed_seconds=60)
        Q.assert_report(report)
    def test_otherwise_valid61s_authority_cannot_qualify_under_guest120(self):
        report = valid_report()
        report.update(elapsed_seconds=61)
        report['authority'].update(finished_monotonic=161, elapsed_seconds=61)
        Q.base_report(report)  # Every retained old assertion, including120s, passes.
        with self.assertRaises(AssertionError): Q.assert_report(report)
    def test_authority_measurement_binding_cannot_be_fabricated(self):
        for change in ({'limit_seconds':120}, {'started_monotonic':99}, {'elapsed_seconds':0},
                       {'finished_monotonic':float('nan')}):
            report = valid_report(); report['authority'].update(change)
            with self.assertRaises(AssertionError): Q.assert_report(report)
    def test_marker_header_right_and_order_mutations_reject_complete_report(self):
        for mutate in (
            lambda c: c['exercise']['marker']['received'].update(rights=1,fd_targets=[c['exercise']['transfers'][0]['received_fd']]),
            lambda c: c['exercise']['marker']['received']['fields'].update({'9':0}),
            lambda c: c['exercise']['marker']['received'].update(serial=100),
            lambda c: c['exercise']['marker']['received'].update(body_hex='58'),
            lambda c: c['close']['events']['target'].pop(-3),
            lambda c: c['close']['events']['target'].__setitem__(-3,c['exercise']['transfers'][1]['received']),
        ):
            report = valid_report(); Q.assert_report(report); mutate(report['combinations'][0])
            with self.assertRaises((AssertionError,KeyError)): Q.assert_report(report)
    def test_coherent_marker_wire_mutations_cannot_hide_new_contract_violation(self):
        for field, value in (('9',0),('9',1),('3','Resource'),('7',':1.999'),('8','h')):
            with self.subTest(field=field,value=value):
                report = valid_report(); Q.assert_report(report)
                before = report['combinations'][0]['exercise']['marker']['received']
                after = copy.deepcopy(before); after['fields'][field] = value
                signatures = {'1':'o','2':'s','3':'s','6':'s','7':'s','8':'g','9':'u'}
                raw = O.O.frame(4,101,[(int(k),signatures[k],v) for k,v in after['fields'].items()],b'')
                after.update(wire_hex=raw.hex(),wire_sha256=hashlib.sha256(raw).hexdigest(),wire_bytes=len(raw))
                if field == '9' and value == 1:
                    after.update(rights=1,fd_targets=[report['combinations'][0]['exercise']['transfers'][0]['received_fd']])
                O.coherent(report,before,after)
                with self.assertRaises(AssertionError): Q.assert_report(report)
    def test_six_roles_keep_exact_ebadf_closure_and_warmed_recovery(self):
        report = valid_report(); checked_report(report)
        for c in report['combinations']:
            self.assertEqual(len(c['close']['closure']), 6)
            self.assertEqual(c['closed']['actor'], c['warmed']['actor'])
            self.assertEqual(c['closed']['broker'], c['warmed']['broker'])
    def test_precontainment_missing_or_residual_cannot_become_pass(self):
        for owner in ('actor','backend'):
            for mutation in ({'group_absent':False,'group_members':[999]}, {'actor_pid_absent':False},
                             {'wrapper_waited':False}, {'timed_out':True}, {'errors':['probe failed']}):
                with self.subTest(owner=owner, mutation=mutation):
                    report = valid_report(); Q.assert_report(report)
                    report['combinations'][0]['teardown'][owner]['before_containment'].update(mutation)
                    with self.assertRaises(AssertionError): Q.assert_report(report)

class AuthorityBudgetControls(unittest.TestCase):
    def test_runtime_timer_uses_remaining_shared_budget_and_restores_handler(self):
        report = valid_report()
        with patch.object(Q.time,'monotonic',side_effect=[110,111,120,121]), \
                patch.object(Q.signal,'getitimer',return_value=(0.0,0.0)), \
                patch.object(Q.signal,'getsignal',return_value='previous-handler'), \
                patch.object(Q.signal,'signal') as handlers, patch.object(Q.signal,'setitimer') as timers:
            with Q.authority_budget(report): pass
            with Q.authority_budget(report): pass
        self.assertEqual([call.args for call in timers.call_args_list],
                         [(Q.signal.ITIMER_REAL,50),(Q.signal.ITIMER_REAL,0),
                          (Q.signal.ITIMER_REAL,40),(Q.signal.ITIMER_REAL,0)])
        self.assertEqual(handlers.call_args_list[1].args,(Q.signal.SIGALRM,'previous-handler'))
        self.assertEqual(handlers.call_args_list[3].args,(Q.signal.SIGALRM,'previous-handler'))
        self.assertEqual(report['authority']['elapsed_seconds'],21)
    def test_runtime_deadline_interrupts_work_then_records_failure_duration(self):
        report = valid_report()
        with patch.object(Q.time,'monotonic',side_effect=[110,161]), \
                patch.object(Q.signal,'getitimer',return_value=(0.0,0.0)), \
                patch.object(Q.signal,'getsignal',return_value='previous-handler'), \
                patch.object(Q.signal,'signal') as handlers, patch.object(Q.signal,'setitimer') as timers:
            with self.assertRaisesRegex(TimeoutError,'authority60 deadline'):
                with Q.authority_budget(report):
                    handler = handlers.call_args_list[0].args[1]
                    handler(Q.signal.SIGALRM,None)
        timers.assert_called_with(Q.signal.ITIMER_REAL,0)
        self.assertEqual(report['authority']['elapsed_seconds'],61)
    def test_expired_budget_never_launches_backend_or_installs_timer(self):
        report = valid_report()
        with patch.object(Q.time,'monotonic',return_value=161), patch.object(Q.signal,'setitimer') as timers:
            with self.assertRaisesRegex(AssertionError,'authority60 deadline'):
                with Q.authority_budget(report): self.fail('expired runtime budget yielded')
        timers.assert_not_called()

class RetirementControls(unittest.TestCase):
    def test_retirement_predicate_accepts_only_observed_precontainment_success(self):
        Q.assert_retired(retired(199,200), 199,200)
        for mutation in ({'wrapper_returncode':-9}, {'wrapper_pid':198}, {'actual_pid':201},
                         {'group_members':[200]}, {'pid_absent':False}, {'errors':['denied']}, {'timed_out':True}):
            row = retired(199,200); row.update(mutation)
            with self.assertRaises(AssertionError): Q.assert_retired(row,199,200)
    def test_probe_records_permission_error_as_failure(self):
        with patch.object(Q,'Path') as paths, patch.object(Q.S,'group_members',side_effect=PermissionError('probe denied')):
            paths.return_value.exists.return_value = False
            row = Q.probe_retired(199,200,True,0)
        self.assertTrue(row['errors'])
        with self.assertRaises(AssertionError): Q.assert_retired(row,199,200)
    def test_success_wait_and_probe_precede_original_containment(self):
        channel = Mock(); channel.process.pid = 199
        channel.process.wait.return_value = 0
        order = []
        channel.process.stdin.close.side_effect = lambda: order.append('eof')
        channel.process.wait.side_effect = lambda **kwargs: order.append('wait') or 0
        channel.stop.side_effect = lambda **kwargs: order.append('contain') or dict(pid=199,method='eof',returncode=0)
        with patch.object(Q,'probe_retired',side_effect=lambda *args: order.append('probe') or retired(199,200)), patch.object(Q.time,'monotonic',return_value=0):
            result = Q.stop_channel(channel,200,1)
        self.assertEqual(order,['eof','wait','probe','contain'])
        channel.stop.assert_called_once_with(grace=0)
        Q.assert_retired(result['before_containment'],199,200)
    def test_timeout_still_contains_but_original_eof_label_cannot_certify(self):
        channel = Mock(); channel.process.pid = 199
        channel.process.wait.side_effect = subprocess.TimeoutExpired('wrapper',1)
        channel.stop.return_value = dict(pid=199,method='eof',returncode=0)
        def observe(wrapper,actual,waited,code,timeout,errors):
            return {**retired(wrapper,actual),'wrapper_waited':waited,'wrapper_returncode':code,'timed_out':timeout,'errors':errors}
        with patch.object(Q,'probe_retired',side_effect=observe), patch.object(Q.time,'monotonic',return_value=0):
            result = Q.stop_channel(channel,200,1)
        channel.stop.assert_called_once_with(grace=0)
        self.assertTrue(result['before_containment']['timed_out'])
        with self.assertRaises(AssertionError): Q.assert_retired(result['before_containment'],199,200)
    def test_residual_group_before_containment_cannot_be_certified_by_eof_label(self):
        channel = Mock(); channel.process.pid = 199
        channel.process.wait.return_value = 0
        channel.stop.return_value = dict(pid=199,method='eof',returncode=0)
        with patch.object(Q,'Path') as paths, patch.object(Q.S,'group_members',return_value=[200]), patch.object(Q.time,'monotonic',return_value=0):
            paths.return_value.exists.return_value = False
            result = Q.stop_channel(channel,200,1)
        channel.stop.assert_called_once_with(grace=0)
        self.assertEqual(result['before_containment']['group_members'],[200])
        with self.assertRaises(AssertionError): Q.assert_retired(result['before_containment'],199,200)

if __name__ == '__main__':
    unittest.main(verbosity=2)
