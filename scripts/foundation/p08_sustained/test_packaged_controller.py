"""Completion and whole-accounting oracles for the packaged workload."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile
import threading

AUTHORITIES = set((
    "GaoBus.Supervisor GaoBus.Ids GaoBus.PeerRegistry GaoBus.Limits GaoBus.Policy "
    "GaoBus.NameRegistry GaoBus.MatchRules GaoBus.Policy.Capability GaoBus.Router "
    "GaoBus.Activation.HelperSupervisor GaoBus.Activation GaoBus.PeerSupervisor GaoBus.Listener"
).split())

WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
spec = importlib.util.find_spec('packaged_qualify')
if spec:
    implementation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(implementation)
else:
    implementation = None


def health_receipt(started=0.0, finished=700.0):
    observations = []
    for index in range(round((finished - started) / .05) + 1):
        due = started + index * .05
        actual_start, end = due + .001, due + .020
        observations.append(dict(index=index, due=due, requested=due, started=actual_start,
                                 finished=end, dispatch_lag_ms=(actual_start-due)*1000,
                                 actual_ms=(end-actual_start)*1000,
                                 latency_ms=(end-due)*1000, actor=dict(latency_ms=10.0)))
    return dict(started=started, finished=finished, count=len(observations),
                max_ms=max(row['latency_ms'] for row in observations), errors=[],
                observations=observations)


def completion():
    counts = {kind: 14 for kind in WORKLOAD['operations']}
    counts['transfer'] += 2
    thousand = {kind: 142 for kind in WORKLOAD['operations']}
    thousand['transfer'] += 6
    return dict(mode='soak', duration_seconds=600, warmup_counts=counts,
                batches=[dict(number=n, operations=1000, counts=thousand, status='passed',
                              verified_at=40 + n * 20) for n in range(1, 4)],
                sustained=dict(started=100.0, finished=700.0, counts=counts, operations=100),
                healthy=health_receipt(), warmup_started=1.0,
                operation_count=3200, sampled_operations=list(range(100, 3201, 100)),
                final_sample_operation=3200, worker_barriers=[100, 1100, 2100, 3100, 3200])


def sample():
    metrics = ('connections authenticating ingress_messages ingress_bytes ingress_fds '
               'egress_messages egress_bytes egress_fds frame_bytes frame_fds '
               'activation_messages activation_bytes activation_fds').split()
    counts = {key: int(key == 'connections') for key in metrics}
    peer = '#PID<0.100.0>'
    queue_keys = ('buffer_bytes incoming_fds output_messages output_fds output_bytes '
                  'current_output route_wait auth_continuing messages_continuing '
                  'read_scheduled frame_timer pending_fd_timer mailbox').split()
    usage = dict(global_=counts, uids={'1101': counts}, peers={peer: counts}, reservations=0,
                 reload_reservations=0, limits={'global': {'connections': 8}},
                 xml=dict(limits={'max_completed_connections': 7}, queues={'max_outgoing_bytes': 262144},
                          global_=dict(incomplete=0, completed=1), uids={'1101': 1}))
    usage['global'] = usage.pop('global_')
    usage['xml']['global'] = usage['xml'].pop('global_')
    # Valid ETF identity is independently round-tripped in the Elixir fixture;
    # here the oracle must reject altered bytes/hash/length before interpreting it.
    data = b'\x83t\x00\x00\x00\x00'
    state = dict(usage=usage, usage_etf=dict(encoding='erlang-external-term/base64',
                  base64=base64.b64encode(data).decode(), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()),
                peers=[dict(peer=peer, uid=1101, gid=100, groups=[100], name=':1.42')],
                pending=0, retired=0, bound_handles=0, names=['org.freedesktop.DBus', ':1.42'],
                names_by_peer={peer: 1}, matches_by_peer={}, matches=0, capabilities=0,
                accounting=dict(pending=0, retired=0, bound_handles=0, reload=0, activation=0),
                peer_queues={peer: {key: 0 for key in queue_keys}},
                queues={name: 0 for name in AUTHORITIES}, memory=1000, atoms=100, processes=10, ports=2,
                authorities={name: '#PID<0.%d.0>' % (10+i) for i,name in enumerate(sorted(AUTHORITIES))},
                startup_plan=dict(listener=dict(pending_peer=0), peer_supervisor=dict(active=1)),
                external=dict(fds=20, fd_targets=['socket:[42]'], rss_bytes=1000))
    # The original placeholder ETF contained only an empty map. Bind the full
    # independent pinned-Elixir vector before asserting semantic equality.
    vector = json.loads(Path(__file__).with_name('packaged_usage_vector.json').read_text())
    state.update(copy.deepcopy(vector))
    state['accounting'].update({key: copy.deepcopy(state[key])
                               for key in ('usage', 'peers', 'peer_queues', 'authorities')})
    return state


class CompletionTests(unittest.TestCase):
    def verify(self, record):
        # The development runner stops after three batches, without this oracle.
        if implementation:
            implementation.validate_completion(record)

    def test_complete_frozen_workload_passes(self):
        self.verify(completion())

    def test_three_batches_without_sustained_work_cannot_pass(self):
        record = completion()
        record['sustained'] = dict(started=100, finished=100, operations=0, counts={})
        with self.assertRaises(AssertionError):
            self.verify(record)

    def test_599_999_seconds_cannot_pass_even_if_entire_run_is_longer(self):
        record = completion()
        record['sustained']['finished'] = 699.999
        record['elapsed_seconds'] = 900
        with self.assertRaises(AssertionError):
            self.verify(record)

    def test_missing_work_health_samples_and_changed_duration_fail(self):
        mutations = [lambda r: r['batches'].pop(), lambda r: r.update(duration_seconds=599),
                     lambda r: r['warmup_counts'].update(transfer=0),
                     lambda r: r['batches'][1].update(operations=999),
                     lambda r: r['sustained']['counts'].update(churn=0),
                     lambda r: r['healthy'].update(count=0),
                     lambda r: r['healthy'].update(max_ms=1000.001),
                     lambda r: r['healthy']['errors'].append('missed health'),
                     lambda r: r['sampled_operations'].remove(1000),
                     lambda r: r.update(final_sample_operation=3199),
                     lambda r: r.update(operation_count=3199)]
        for mutate in mutations:
            record = copy.deepcopy(completion())
            mutate(record)
            with self.subTest(record=record), self.assertRaises(AssertionError):
                self.verify(record)

    def test_short_preflight_is_explicitly_nonqualifying(self):
        record = completion()
        record.update(mode='preflight', duration_seconds=10)
        record['sustained']['finished'] = 110
        self.verify(record)
        if implementation:
            self.assertFalse(implementation.qualifies_res06(record))

    def test_early_sustained_clock_or_wrong_worker_barrier_cannot_pass(self):
        for mutate in [lambda r: r['batches'][2].update(verified_at=100.001),
                       lambda r: r['worker_barriers'].__setitem__(2, 2099),
                       lambda r: r['worker_barriers'].pop()]:
            record = copy.deepcopy(completion())
            mutate(record)
            with self.subTest(record=record), self.assertRaises(AssertionError):
                self.verify(record)


class AccountingTests(unittest.TestCase):
    def verify(self, state):
        if implementation:
            implementation.verify_sample(state)

    def test_complete_quiescent_sample_passes(self):
        self.verify(sample())

    def test_nonzero_missing_or_stale_counter_at_every_scope_fails(self):
        mutations = [lambda s: s['usage']['global'].update(frame_fds=1),
                     lambda s: s['usage']['uids']['1101'].update(egress_bytes=1),
                     lambda s: s['usage']['peers']['#PID<0.100.0>'].update(activation_messages=1),
                     lambda s: s['usage'].update(reload_reservations=1),
                     lambda s: s['usage']['xml']['global'].update(incomplete=1),
                     lambda s: s['usage']['xml']['uids'].update({'42': 0}),
                     lambda s: s['usage']['uids'].clear(), lambda s: s['usage']['peers'].clear(),
                     lambda s: s.update(retired=1), lambda s: s.update(bound_handles=1),
                     lambda s: s['accounting'].update(activation=1),
                     lambda s: s['peer_queues']['#PID<0.100.0>'].update(current_output=1),
                     lambda s: s['usage']['global'].pop('authenticating')]
        for mutate in mutations:
            state = copy.deepcopy(sample())
            mutate(state)
            with self.subTest(state=state), self.assertRaises(AssertionError):
                self.verify(state)

    def test_etf_corruption_and_observation_ceilings_fail(self):
        mutations = [lambda s: s['usage_etf'].update(bytes=1000),
                     lambda s: s['usage_etf'].update(sha256='0' * 64),
                     lambda s: s['external'].update(rss_bytes=WORKLOAD['ceilings']['rss_bytes'] + 1),
                     lambda s: s.update(memory=WORKLOAD['ceilings']['memory_bytes'] + 1),
                     lambda s: s['queues'].update(Router=WORKLOAD['queue']['global_messages'] + 1),
                     lambda s: s.update(matches=WORKLOAD['max_match_entries'] + 1),
                     lambda s: s['names_by_peer'].update({'#PID<0.100.0>': 5})]
        for mutate in mutations:
            state = copy.deepcopy(sample())
            mutate(state)
            with self.subTest(state=state), self.assertRaises(AssertionError):
                self.verify(state)

    def test_hash_valid_wrong_etf_and_accounting_substitution_cannot_pass(self):
        state = sample()
        data = b'\x83t\x00\x00\x00\x00'
        state['usage_etf'].update(base64=base64.b64encode(data).decode(), bytes=len(data),
                                  sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaises(AssertionError):
            self.verify(state)
        for key in ('usage', 'peers', 'peer_queues', 'authorities'):
            state = sample()
            state['accounting'][key] = {}
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.verify(state)

    def test_opaque_remote_trailing_and_unbounded_etf_terms_reject(self):
        if not implementation:
            self.fail('packaged ETF decoder missing')
        vector = sample()['usage_etf']
        data = base64.b64decode(vector['base64'])
        for bad in [data + b'\0', data.replace(b'nonode@nohost', b'remote@host0x'),
                    b'\x83\x70\0\0\0\0', b'\x83\x74\xff\xff\xff\xff',
                    b'\x83' + b'\x68\x01' * 66 + b'\x6a']:
            with self.subTest(data=bad[:20]), self.assertRaises(AssertionError):
                implementation.ETF(bad).decode()

    def test_bool_counter_substitutions_reject_even_with_valid_etf(self):
        for key in ('pending', 'retired', 'bound_handles'):
            state = sample()
            state[key] = state['accounting'][key] = False
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.verify(state)



# Synthetic runtime receipts bind the real pure packaged plan; usage ETF remains
# separately checked against the unchanged pinned-Elixir golden vector above.
def runtime_fixture():
    import packaged_capture as capture
    frozen = capture.ROOT/'test/reports/foundation/continuation-20261011-full-goal/environment/p08-packaged-current-capture/frozen8'
    plan = capture.preview_plan(frozen, Path(__file__).with_name('packaged_policy.xml'))
    semantic, expected = plan['semantic'], plan['display']['compiled_policy_semantic']
    manifest = dict(runtime_plan=dict(semantic=semantic, compiled_policy_semantic=expected),
                    startup=capture.startup_contract(), capacities=dict(packaged=plan['capacities']),
                    accounts=capture.account_contract(), runtime_code_expected=plan['runtime_code_expected'],
                    xml=dict(sha256=capture.digest(Path(__file__).with_name('packaged_policy.xml'))))
    state = sample()
    state['usage']['limits'] = copy.deepcopy(semantic['safety_limits'])
    state['usage']['xml']['limits'] = {key: semantic['xml_limits'][key] for key in
                                      ['max_completed_connections','max_incomplete_connections',
                                       'max_connections_per_user','auth_timeout']}
    state['usage']['xml']['queues'] = {key: semantic['xml_limits'][key] for key in
                                      ['max_incoming_bytes','max_outgoing_bytes',
                                       'max_incoming_unix_fds','max_outgoing_unix_fds']}
    state.update(configuration=copy.deepcopy(expected['configuration']), compiled_policy=copy.deepcopy(expected),
                 pending_limits=dict(semantic['router_options'])['pending_limits'],
                 node='nonode@nohost', applications=['gao_bus','ex_d_bus'],
                 code_identity={k:v for k,v in plan['runtime_code_expected'].items() if k in
                   ['Elixir.GaoBus.Application','Elixir.GaoBus.Router','Elixir.GaoBus.Peer','Elixir.GaoBus.Limits']})
    # Preview captures retain a temporary map key; a guest receipt uses the exact
    # private XML path in both the compiled and published configuration records.
    for config in [state['configuration'], state['compiled_policy']['configuration']]:
        files = config['captures']['files']
        assert len(files) == 1
        config['captures']['files'] = {manifest['startup']['environment']['OS_BUS_CONFIG']:next(iter(files.values()))}
    state['startup_plan'].update(profile='system', lifecycle='release',
      native_identity=dict(uid=4,real_uid=4,gid=4,real_gid=4),
      safety_limits=copy.deepcopy(semantic['safety_limits']), xml_limits=semantic['xml_limits'],
      pending_limits=state['pending_limits'],max_output_bytes=dict(semantic['router_options'])['max_output_bytes'],
      peer_supervisor=dict(max_children=dict(semantic['peer_supervisor_options'])['max_children'],active=1),
      listener=dict(socket_path=manifest['startup']['socket'],peer_options=semantic['peer_options'],
                    inherited=False,pending_peer=0),
      names=dict(max_names_per_peer=4,max_name_entries=8192,**{'xml_limits?':True}),
      matches=dict(max_matches_per_peer=4,max_match_entries=8192,**{'xml_limits?':True}))
    return state, manifest


class AcceptanceRepairTests(unittest.TestCase):
    def test_listener_and_supervisor_must_cover_registered_peers(self):
        for key, value in [('pending_peer',1),('pending_peer',False),('active',0),('active',2),('active',True)]:
            state = sample()
            consumer = state['startup_plan']['listener' if key == 'pending_peer' else 'peer_supervisor']
            consumer[key] = value
            with self.subTest(key=key,value=value), self.assertRaises(AssertionError):
                implementation.verify_sample(state)

    def test_all_authority_mailboxes_are_required(self):
        for mutate in [lambda s:s.update(queues={}),lambda s:s['queues'].pop('GaoBus.Listener'),
                       lambda s:s['queues'].update({'unknown':0}),
                       lambda s:s['queues'].update({'GaoBus.Router':False})]:
            state=sample();mutate(state)
            with self.subTest(queues=state['queues']),self.assertRaises(AssertionError):
                implementation.verify_sample(state)

    def test_actual_full_xml_consumer_maps_are_bound(self):
        state, manifest = runtime_fixture()
        implementation.verify_runtime(state,manifest)
        for section in ['limits','queues']:
            for key in state['usage']['xml'][section]:
                for mutate in [lambda row,key=key:row.update({key:99999}),
                               lambda row,key=key:row.pop(key),lambda row:row.update(extra=1)]:
                    changed=copy.deepcopy(state);mutate(changed['usage']['xml'][section])
                    with self.subTest(section=section,key=key),self.assertRaises(AssertionError):
                        implementation.verify_runtime(changed,manifest)

    def test_one_health_probe_cannot_cover600s(self):
        record=completion();record['healthy']['observations']=record['healthy']['observations'][:1]
        record['healthy']['count']=1
        with self.assertRaises(AssertionError):implementation.validate_completion(record)

    def test_health_due_coverage_receipts_and_derived_max_are_required(self):
        mutations=[lambda h:h['observations'].pop(20), lambda h:h.update(count=20),
          lambda h:h['observations'][20].update(due=1.001),
          lambda h:h['observations'][20].update(index=21),
          lambda h:h.update(started=101.0),lambda h:h.update(finished=699.0),
          lambda h:h.update(max_ms=1.0),lambda h:h['observations'][20].update(started=.9),
          lambda h:h['observations'][20].update(requested=.9),
          lambda h:h['observations'][20].update(finished=2.1),
          lambda h:h['observations'][20].update(dispatch_lag_ms=0.0),
          lambda h:h['observations'][20].update(actual_ms=0.0),
          lambda h:h['observations'][20].update(latency_ms=0.0),
          lambda h:h['observations'][20]['actor'].update(latency_ms=1001.0)]
        for mutate in mutations:
            record=completion();mutate(record['healthy'])
            with self.subTest(health=record['healthy'].get('count')),self.assertRaises(AssertionError):
                implementation.validate_completion(record)

    def test_probe_budget_includes_lock_and_dispatch_lag(self):
        class Lock:
            def __enter__(self):clock[0]+=.7
            def __exit__(self,*args):pass
        class Observer:
            def request(self,**request):clock[0]+=.4;return dict(latency_ms=400)
        guest=object.__new__(implementation.Guest)
        guest.health=dict(started=0.0,count=0,max_ms=0.0,errors=[],observations=[])
        guest.health_lock=Lock();clock=[0.0]
        with patch.object(implementation.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaises(AssertionError):guest.health_probe(Observer())
        self.assertEqual(guest.health['count'],1)
        self.assertAlmostEqual(guest.health['max_ms'],1100.0)
        self.assertEqual(guest.health['observations'][0]['due'],0.0)
        self.assertAlmostEqual(guest.health['observations'][0]['started'],.7)
        self.assertAlmostEqual(guest.health['observations'][0]['finished'],1.1)

    def test_actual_iex_lookup_requires_passwd_home_and_absent_init(self):
        guard=getattr(implementation,'verify_iex_initialization',None)
        self.assertIsNotNone(guard,'actual IEx lookup guard missing')
        with tempfile.TemporaryDirectory() as directory:
            home,work=Path(directory)/'home',Path(directory)/'work';home.mkdir();work.mkdir()
            env={'HOME':str(home)}
            result=guard(env,str(home),work)
            self.assertEqual(result['lookup_home'],str(home))
            for bad in [{'HOME':str(work)}, {'HOME':str(home),'IEX_HOME':str(work)},{}]:
                with self.subTest(environment=bad),self.assertRaises(AssertionError):guard(bad,str(home),work)
            for selected in [home,work]:
                (selected/'.iex.exs').write_text('raise "unrequested init"')
                with self.subTest(path=selected),self.assertRaises(AssertionError):guard(env,str(home),work)
                (selected/'.iex.exs').unlink()

    def test_console_cleanup_requires_complete_tail_and_owned_cgroup(self):
        unit='osbus-p08-console.service'
        receipt=dict(returncode=0,method='console-System.stop',tail_eof=True,
                     service_cgroup_cleanup_required=True)
        manager=dict(main_gone=True,cgroup='/system.slice/'+unit,cgroup_pids=[],socket_removed=True,
                     properties={'MainPID':'0','ControlGroup':'','ActiveState':'inactive'})
        class Channel:
            def stop(self,grace):return copy.deepcopy(selected)
        guest=object.__new__(implementation.Guest);guest.report=dict(cleanup=[])
        guest.identities={unit:dict(cgroup='/system.slice/'+unit)}
        guest.stopped=lambda actual:copy.deepcopy(observed)
        for mutation in ['valid','tail_error','tail_eof','cleanup_required','wrong_cgroup','live_cgroup']:
            selected,observed=copy.deepcopy(receipt),copy.deepcopy(manager)
            if mutation=='tail_error':selected['tail_error']='deadline'
            elif mutation=='tail_eof':selected['tail_eof']=False
            elif mutation=='cleanup_required':selected['service_cgroup_cleanup_required']=False
            elif mutation=='wrong_cgroup':observed['cgroup']='/system.slice/unrelated.service'
            elif mutation=='live_cgroup':observed['cgroup_pids']=['42']
            if mutation=='valid':guest.shutdown(unit,Channel(),console=True)
            else:
                with self.subTest(mutation=mutation),self.assertRaises(AssertionError):
                    guest.shutdown(unit,Channel(),console=True)

    def test_absolute_schedule_does_not_reset_after_response_time(self):
        clock=[0.0]
        class Event:
            stopped=False
            def is_set(self):return self.stopped
            def wait(self,delay):
                clock[0]+=delay
                if clock[0]>=.15-1e-9:
                    guest.health['finished']=.15;self.stopped=True;return True
                return False
        class Thread:
            def __init__(self,target,name):self.target=target
            def start(self):self.target()
        class Observer:
            def request(self,**request):clock[0]+=.010;return dict(latency_ms=10.0)
        guest=object.__new__(implementation.Guest)
        guest.health=dict(count=0,max_ms=0.0,errors=[],observations=[])
        guest.health_lock=threading.Lock();guest.stop=Event()
        with patch.object(implementation.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(implementation.threading,'Thread',Thread):
            guest.start_health(Observer())
        self.assertEqual(guest.health['count'],4)
        self.assertEqual([round(r['due'],6) for r in guest.health['observations']],[0.0,.05,.1,.15])
        guard=getattr(implementation,'verify_health',None)
        self.assertIsNotNone(guard,'absolute health receipt oracle missing')
        guard(guest.health,0.0,dict(started=0.0,finished=.15))

    def test_immediate_post_kill_probe_does_not_consume_scheduled_due(self):
        import inspect
        self.assertIn('regular',inspect.signature(implementation.Guest.health_probe).parameters,
                      'post-kill receipt must not consume or race a regular health due index')
        clock=[.02]
        class Observer:
            def request(self,**request):clock[0]+=.01;return dict(latency_ms=10.0)
        guest=object.__new__(implementation.Guest)
        guest.health=dict(started=0.0,count=0,max_ms=0.0,errors=[],observations=[])
        guest.health_lock=threading.Lock()
        with patch.object(implementation.time,'monotonic',side_effect=lambda:clock[0]):
            receipt=guest.health_probe(Observer(),regular=False)
        self.assertEqual(guest.health['count'],0)
        self.assertEqual(guest.health['observations'],[])
        self.assertEqual(receipt['index'],None)
        self.assertAlmostEqual(receipt['due'],.02)
        self.assertAlmostEqual(receipt['latency_ms'],10.0)

    def test_stopped_rejects_unowned_cgroup_before_reading_processes(self):
        guest=object.__new__(implementation.Guest)
        guest.identities={'osbus-p08-console.service':dict(cgroup='/system.slice/unrelated.service')}
        with self.assertRaises(AssertionError):guest.stopped('osbus-p08-console.service')

    def test_valid_completion_reports_planned_and_observed_coverage(self):
        record=completion();implementation.validate_completion(record)
        coverage=record.get('health_coverage')
        self.assertIsNotNone(coverage,'planned/observed health coverage is not retained')
        self.assertEqual(coverage['planned_count'],14001)
        self.assertEqual(coverage['observed_count'],14001)
        self.assertEqual(coverage['first_due'],0.0)
        self.assertEqual(coverage['last_due'],700.0)
        self.assertEqual(coverage['coverage_until'],700.0)
        self.assertAlmostEqual(coverage['observed_until'],700.020)
        self.assertEqual(record['sample_coverage'],dict(planned=32,observed=32,final_operation=3200))


if __name__ == '__main__':
    unittest.main()
