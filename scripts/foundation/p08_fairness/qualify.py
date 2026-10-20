"""Scoped RES-04, frozen-artifact VM only. No Mix or existing workload edits."""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

from actor import payload
from channel import Actor, Channel

FIXTURES = Path(__file__).resolve().parent
WORKLOAD = json.loads((FIXTURES / 'workload.json').read_text())
MANIFEST_SHA = 'a92bcd102a9bec38d73f5f218ef8a63f7b5339a5b50fb228c057800d9318462f'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def external(pid):
    root = Path('/proc') / str(pid)
    targets = []
    for path in (root / 'fd').iterdir():
        try:
            targets.append(os.readlink(path))
        except FileNotFoundError:
            pass
    rss = int(next(line.split()[1] for line in (root / 'status').read_text().splitlines() if line.startswith('VmRSS:'))) * 1024
    return {'fds': len(targets), 'targets': sorted(targets), 'rss_bytes': rss}


def receiver_peer_map(peers, receiver_names):
    selected = [row for row in peers if row['name'] in receiver_names]
    targets = {row['name']: row['peer'] for row in selected}
    assert (len(selected) == len(receiver_names) == WORKLOAD['receivers'] and set(targets) == receiver_names
            and len(set(targets.values())) == len(receiver_names)), 'receiver identity mismatch'
    return targets


def audit_dispositions(trace, senders, targets):
    admitted = [row for row in trace['rows'] if row['member'] == 'FairPulse']
    rejected = [row for row in trace['failures'] if row['bytes'] > 65536]
    assert not [row for row in trace['failures'] if row['bytes'] <= 65536], 'control/call enqueue failure'
    intended = {(sender, 100000 + index * 1000 + n) for index, sender in enumerate(senders) for n in range(64)}
    seen = set()
    for row in admitted:
        key = (row['target'], row['sender'], row['serial'])
        assert row['target'] in targets and (row['sender'], row['serial']) in intended, 'unintended admission'
        assert key not in seen, 'duplicate admission'
        seen.add(key)
        expected = payload(row['sender'], row['serial']).encode()
        assert row['bytes'] == 65536 and row['sha256'] == hashlib.sha256(expected).hexdigest(), 'admission bytes'
    for row in rejected:
        assert row['target'] in targets and row['fds'] == 0
        assert row['scope'] in ('peer', 'uid', 'global') and row['metric'] in ('egress_bytes', 'egress_messages')
    for target in targets:
        assert sum(row['target'] == target for row in admitted + rejected) == 128, 'unexplained receiver disposition'
    assert len(admitted) + len(rejected) == 1024, 'unexplained fanout disposition'
    return admitted, rejected


def main(candidate, evidence, diagnostic_no_trace=False, timing_observer=False):
    if timing_observer:
        diagnostic_no_trace = True
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-fairness'
    manifest_path = candidate / 'candidate.json'
    assert sha(manifest_path) == MANIFEST_SHA
    manifest = json.loads(manifest_path.read_text())
    for name, expected in manifest['files'].items():
        assert sha(candidate / name) == expected, name
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(FIXTURES / 'daemon.exs'), str(evidence / 'bus')]
    if timing_observer:
        command.append('--diagnostic-timing')
    elif diagnostic_no_trace:
        command.append('--diagnostic-no-trace')
    success_result = 'diagnostic_completed_not_qualification' if diagnostic_no_trace else 'passed_scoped_RES04'
    report = {'result': 'running', 'diagnostic_only': diagnostic_no_trace,
              'qualification_eligible': not diagnostic_no_trace,
              'missing_evidence': ['admission dispositions', 'rejection dispositions', 'complete delivery proof'] if diagnostic_no_trace else [], 'requirement': 'RES-04 scoped development', 'workload': WORKLOAD,
              'candidate_manifest_sha256': MANIFEST_SHA, 'candidate': manifest,
              'commands': [command], 'actors': [], 'samples': [], 'cleanup': [],
              'limitations': 'Rights0; fullP08/P09/readiness open/L0; not FD09/FD10/RES06/package acceptance'}
    def save():
        (evidence / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    def timing(event, **fields):
        if timing_observer:
            with (evidence / 'timing-controller.jsonl').open('a') as output:
                output.write(json.dumps({'event': event, 'monotonic_ns': time.monotonic_ns(),
                                         'realtime_ns': time.time_ns(), **fields}) + '\n')
    report['timing_observer'] = timing_observer
    sampler_running = False
    daemon = None
    actors = []
    producers, receivers = [], []
    victim = None
    stop, active = threading.Event(), threading.Event()
    health = {'count': 0, 'active_count': 0, 'max_ms': 0, 'errors': [], 'samples': []}
    health_lock = threading.Lock()
    thread = None
    started = time.monotonic()
    try:
        daemon = Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        report['ready'] = daemon.read()
        pid = report['ready']['pid']
        def actor(role, index, user='foundationB'):
            actor_file = 'timing_actor.py' if timing_observer else ('diagnostic_actor.py' if diagnostic_no_trace else 'actor.py')
            if timing_observer and role == 'healthy':
                path = evidence / 'timing-health.jsonl'
                path.touch()
                os.chown(path, 1100, 1100)
            args = ['runuser', '-u', user, '--', 'python3', str(FIXTURES / actor_file), str(evidence / 'bus'), role, str(index)]
            worker = Actor(args, evidence / ('%s-%s.log' % (role, index)))
            actors.append(worker)
            identity = worker.read()
            assert identity['ok'], identity
            worker.identity = identity['result']
            report['actors'].append(worker.identity)
            report['commands'].append(args)
            return worker
        producers = [actor('producer', index) for index in range(2)]
        receivers = [actor('receiver', index) for index in range(8)]
        observer = actor('healthy', 0, 'foundationA')
        senders = [worker.identity['name'] for worker in producers]
        for worker in receivers:
            worker.request(op='configure', senders=senders)
        for worker in receivers[:7]:
            worker.request(op='start')
        def probe():
            while not stop.is_set():
                try:
                    with health_lock:
                        result = observer.request(op='health')
                    health['count'] += 1
                    health['max_ms'] = max(health['max_ms'], result['latency_ms'])
                    if active.is_set():
                        health['active_count'] += 1
                        health['samples'].append({'elapsed_seconds': time.monotonic() - started, **result})
                    assert result['latency_ms'] <= WORKLOAD['healthy_probe_ms'], 'healthy deadline'
                except Exception as error:
                    health['errors'].append(repr(error))
                    return
                stop.wait(WORKLOAD['health_interval_ms'] / 1000)
        thread = threading.Thread(target=probe)
        thread.start()
        def sample(command='inspect'):
            timing('snapshot_begin', command=command)
            with health_lock:
                timing('snapshot_lock_acquired', command=command)
                state = daemon.write(command)
                timing('snapshot_return', command=command, pending=state['pending'], router_mailbox=state['router_mailbox'])
            state['external'] = external(pid)
            state['elapsed_seconds'] = time.monotonic() - started
            assert state['external']['rss_bytes'] <= WORKLOAD['rss_max_bytes'], 'RSS ceiling'
            assert state['memory'] <= WORKLOAD['memory_max_bytes'], 'BEAM memory ceiling'
            assert state['router_mailbox'] <= WORKLOAD['router_mailbox_max_messages']
            assert all(row.get('mailbox', 0) <= WORKLOAD['peer_mailbox_max_messages'] for row in state['peers'])
            assert all(row.get('queue', 0) <= WORKLOAD['egress']['peer_messages'] for row in state['peers'])
            assert not health['errors'], health['errors']
            report['samples'].append(state)
            save()
            return state
        baseline = sample('metrics')
        assert baseline['matches'] == 256 and baseline['usage']['global']['connections'] == 11
        report['baseline'] = baseline
        victim = actor('victim', 0)
        report['stall'] = daemon.write('stall ' + receivers[7].identity['name'])
        callee = receivers[0].identity['name']
        if timing_observer:
            timing('sampler_start_begin')
            report['timing_sampler_start'] = daemon.write('timing-start')
            sampler_running = True
            timing('sampler_start_end')
        phase_started = time.monotonic()
        active.set()
        for worker in producers:
            timing('load_begin', sender=worker.identity['name'])
            worker.begin(op='load', callee=callee)
        sample()
        loads = []
        for worker in producers:
            loads.append(worker.finish())
            timing('load_return', sender=worker.identity['name'])
        report['loads'] = loads
        assert sum(row['attempted'] for row in loads) == 128
        for worker in producers:
            timing('barrier_begin', sender=worker.identity['name'])
            worker.request(op='barrier')
            timing('barrier_return', sender=worker.identity['name'])
        queued = sample()
        assert queued['pending'] == 16, ('required real pending workload absent', queued['pending'])
        stalled = next(row for row in queued['peers'] if row['name'] == receivers[7].identity['name'])
        assert stalled['current_output'] and stalled['current_output']['blocked'], 'actual blocked writer absent'
        assert stalled['queue'] > 0, 'required actual queued output absent'
        assert stalled['current_output']['offset'] < stalled['current_output']['bytes']
        assert queued['usage']['global']['egress_messages'] > 0
        assert queued['usage']['global']['connections'] == 12
        report['active_queued'] = queued
        if diagnostic_no_trace:
            with health_lock:
                probe_at_backlog = observer.request(op='health')
            assert probe_at_backlog['latency_ms'] <= WORKLOAD['healthy_probe_ms'], 'backlog healthy deadline'
            report['diagnostic_backlog_health_probe'] = probe_at_backlog
            report['diagnostic_after_health_backlog'] = sample()
            assert report['diagnostic_after_health_backlog']['pending'] == 16
            after_stalled = next(row for row in report['diagnostic_after_health_backlog']['peers']
                                 if row['name'] == receivers[7].identity['name'])
            assert after_stalled['current_output']['blocked'] and after_stalled['current_output']['offset'] > 0
            assert after_stalled['queue'] > 0
        report['kill'] = daemon.write('kill ' + victim.identity['name'])
        assert report['kill']['monitor'] == 'DOWN:killed'
        assert report['kill']['before']['pending'] == 16 and report['kill']['after']['pending'] == 16
        assert report['kill']['after']['capabilities'] == 0
        victim.request(op='closed')
        if diagnostic_no_trace:
            report['trace_before_drain'] = 'NOT_MEASURED'
            admitted = rejected = None
            receivers[7].request(op='start')
            drain_deadline = time.monotonic() + WORKLOAD['cleanup_ms'] / 1000
            while True:
                drain_state = sample()
                if drain_state['usage']['global']['egress_messages'] == 0:
                    break
                assert time.monotonic() < drain_deadline, 'diagnostic output drain deadline'
            delivered = []
            for index, worker in enumerate(receivers):
                result = worker.request(op='diagnostic_observed', calls=16 if index == 0 else 0)
                delivered += result['delivered']
                report.setdefault('receiver_results', {})[worker.identity['name']] = result
            report['diagnostic_raw_deliveries_observed'] = len(delivered)
        else:
            trace = daemon.write('trace')
            report['trace_before_drain'] = trace
            receiver_peers = receiver_peer_map(queued['peers'],
                {worker.identity['name'] for worker in receivers})
            admitted, rejected = audit_dispositions(trace, senders, set(receiver_peers.values()))
            delivered = []
            # Drain the stalled receiver first, before its finite writer expires.
            for index in [7] + list(range(7)):
                worker = receivers[index]
                target = receiver_peers[worker.identity['name']]
                expected = [row['sender'] + ':' + str(row['serial']) for row in admitted if row['target'] == target]
                result = worker.request(op='finish', expected=expected, calls=16 if index == 0 else 0)
                delivered += result['delivered']
                report.setdefault('receiver_results', {})[worker.identity['name']] = result
            assert len(delivered) == len(admitted)
        assert receivers[0].request(op='release')['released'] == 16
        report['replies'] = [worker.request(op='collect', serials=row['calls'], callee=callee)
                             for worker, row in zip(producers, loads)]
        assert sum(len(row['replies']) for row in report['replies']) == 16
        if sampler_running:
            report['timing_sampler_stop'] = daemon.write('timing-stop')
            sampler_running = False
        final = sample('metrics')
        report['final'] = final
        for key in ['authorities', 'names', 'matches', 'capabilities', 'usage', 'processes', 'ports']:
            assert final[key] == baseline[key], ('baseline/final differs', key, baseline[key], final[key])
        assert final['external']['fds'] == baseline['external']['fds'], 'FD growth'
        assert final['atoms'] <= baseline['atoms'] + WORKLOAD['atom_growth_max'], 'atom growth'
        assert final['pending'] == 0 and final['usage']['reservations'] == 0
        assert time.monotonic() - phase_started <= WORKLOAD['phase_max_seconds'], 'active phase duration ceiling'
        assert health['active_count'] > 0 and not health['errors'], health
        active.clear()
        if diagnostic_no_trace:
            report['trace_final'] = 'NOT_MEASURED'
        else:
            report['trace_final'] = daemon.write('trace')
            assert report['trace_final']['peak_queue'] <= WORKLOAD['trace_queue_max_messages']
            assert report['trace_final']['seen'] <= WORKLOAD['trace_summary_max_rows']
            assert report['trace_final']['peak_router_mailbox'] <= WORKLOAD['router_mailbox_max_messages']
        report['counts'] = {'attempted_broadcasts': 128, 'delivery_opportunities': 1024,
                            'admitted_broadcast_deliveries': 'NOT_MEASURED' if admitted is None else len(admitted),
                            'delivered': 'NOT_MEASURED' if diagnostic_no_trace else len(delivered),
                            'rejected_before_enqueue': 'NOT_MEASURED' if rejected is None else len(rejected), 'cancelled_after_admission': 'NOT_MEASURED' if diagnostic_no_trace else 0,
                            'attempted_calls': 16, 'pending_observed': 16, 'replies_delivered': 16,
                            'victim_kills': 1}
        report['phase_seconds'] = time.monotonic() - phase_started
        report['result'] = success_result
    except Exception as error:
        timing('controller_error', error_type=type(error).__name__)
        report.update(result='failed', error=repr(error))
        raise
    finally:
        stop.set()
        if thread:
            thread.join(timeout=15)
            assert not thread.is_alive(), 'health thread did not stop'
        report['healthy'] = health
        if sampler_running and daemon:
            try:
                timing('sampler_stop_begin')
                report['timing_sampler_stop'] = daemon.write('timing-stop')
                timing('sampler_stop_end')
                sampler_running = False
            except Exception as error:
                report['timing_sampler_stop_error'] = repr(error)
        for worker in actors:
            report['cleanup'].append(worker.stop())
        if daemon:
            report['cleanup'].append(daemon.stop())
        report['elapsed_seconds'] = time.monotonic() - started
        report['candidate_hashes_after'] = sha(manifest_path) == MANIFEST_SHA and all(sha(candidate / name) == value for name, value in manifest['files'].items())
        if not report['candidate_hashes_after'] or not all(row['returncode'] == 0 and row['method'] == 'eof' for row in report['cleanup']):
            report.update(result='failed', shutdown_error='candidate mutation or unsuccessful graceful cleanup')
        save()
    assert report['result'] == success_result, report.get('error')
    print(json.dumps({'result': report['result'], 'counts': report['counts'], 'healthy': {key: value for key, value in health.items() if key != 'samples'}}))


if __name__ == '__main__':
    assert len(sys.argv) == 3 or sys.argv[3:] in [['--diagnostic-no-trace'], ['--diagnostic-timing']]
    main(Path(sys.argv[1]), Path(sys.argv[2]), len(sys.argv) == 4, sys.argv[3:] == ['--diagnostic-timing'])
