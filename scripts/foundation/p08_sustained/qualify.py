"""VM-only immutable-candidate batch runner. Packaged soak is a separate gate."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time

# Reuse the existing process/channel cleanup and isolated backend contract.
from channel import Actor, Channel

FIXTURES = Path(__file__).resolve().parent
WORKLOAD = json.loads((FIXTURES / 'workload.json').read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def external(pid):
    root = Path('/proc') / str(pid)
    targets = []
    for fd in (root / 'fd').iterdir():
        try:
            targets.append(os.readlink(fd))
        except FileNotFoundError:
            pass
    status = (root / 'status').read_text()
    rss = int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:'))) * 1024
    return {'fds': len(targets), 'fd_targets': sorted(targets), 'rss_bytes': rss}


def verify_settled(state, baseline):
    for key in ['authorities', 'names', 'matches', 'pending', 'usage', 'capabilities', 'processes', 'ports']:
        assert state[key] == baseline[key], ('post-quiescence state growth/change', key, state[key], baseline[key])
    assert state['external']['fds'] <= baseline['external']['fds'], 'post-quiescence FD growth'
    assert state['atoms'] <= baseline['atoms'] + WORKLOAD['ceilings']['atom_post_quiescence_growth'], 'atom growth'


def main(candidate, evidence):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-p08'
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['version'] == 1 and manifest['not_a_release'], 'development candidate required'
    for name, expected in manifest['files'].items():
        assert digest(candidate / name) == expected, ('candidate artifact changed', name)
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(FIXTURES / 'daemon.exs'), str(evidence / 'bus'), str(FIXTURES / 'policy.exs')]
    report = {'result': 'running', 'workload': WORKLOAD, 'candidate': manifest,
              'candidate_manifest_sha256': digest(candidate / 'candidate.json'),
              'fixture_sha256': {p.name: digest(p) for p in FIXTURES.iterdir() if p.is_file()},
              'scope': 'Disposable VM development artifact batches; not packaged acceptance',
              'RES-06': {'status': 'blocked', 'reason': 'P11 packaged release absent; no600s development substitute'},
              'samples': [], 'batches': [], 'actors': [], 'cleanup': [], 'commands': [command]}
    def save():
        (evidence / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    daemon = worker = observer = None
    stop = threading.Event()
    health = {'count': 0, 'max_ms': 0, 'errors': []}
    health_lock = threading.Lock()
    thread = None
    started = time.monotonic()
    try:
        daemon = Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        ready = daemon.read()
        pid = ready['pid']
        report['ready'] = ready
        for user, mode in [('foundationB', 'worker'), ('foundationA', 'healthy')]:
            actor_command = ['runuser', '-u', user, '--', 'python3', str(FIXTURES / 'actor.py'), str(evidence / 'bus'), mode]
            report['commands'].append(actor_command)
            actor = Actor(actor_command, evidence / (mode + '.log'))
            report['actors'].append(actor.read())
            if mode == 'worker':
                worker = actor
            else:
                observer = actor
        def probe():
            while not stop.is_set():
                try:
                    with health_lock:
                        sample = observer.request(op='health')
                    health['count'] += 1
                    health['max_ms'] = max(health['max_ms'], sample['latency_ms'])
                    assert sample['latency_ms'] <= WORKLOAD['healthy_probe_ms'], 'healthy deadline'
                except Exception as error:
                    health['errors'].append(repr(error))
                    return
                # Workload pacing, never a cleanup/race synchronization barrier.
                stop.wait(WORKLOAD['health_interval_ms'] / 1000)
        thread = threading.Thread(target=probe)
        thread.start()
        def snapshot(command='metrics'):
            with health_lock:
                state = daemon.write(command)
            state['external'] = external(pid)
            state['elapsed_seconds'] = time.monotonic() - started
            assert state['external']['rss_bytes'] <= WORKLOAD['ceilings']['rss_bytes'], 'RSS ceiling'
            assert state['memory'] <= WORKLOAD['ceilings']['memory_bytes'], 'BEAM memory ceiling'
            assert state['usage']['global']['connections'] <= WORKLOAD['active_connection_ceiling'], 'connections ceiling'
            assert max(state['queues'].values()) <= WORKLOAD['queue']['global_messages'], 'authority queue ceiling'
            assert not health['errors'], health['errors']
            return state
        def operations(count):
            counts = {kind: 0 for kind in WORKLOAD['operations']}
            for _ in range(count):
                assert time.monotonic() - started < WORKLOAD['development_duration_max_seconds'], 'development duration ceiling'
                result = worker.request(op='operation')
                if result['kind'] == 'abrupt_kill':
                    killed = daemon.write('kill ' + result['victim'])
                    assert killed['monitor'] == 'DOWN:killed'
                    worker.request(op='killed')
                counts[result['kind']] += 1
                # Call-based authoritative barrier observes monitored cleanup,
                # expires real pending requests and retires native egress credit.
                daemon.write('quiescent')
                if sum(counts.values()) % 100 == 0:
                    sample = snapshot('snapshot')
                    if 'baseline' in report:
                        assert sample['external']['fds'] <= report['baseline']['external']['fds'] + WORKLOAD['ceilings']['fd_above_baseline']
                    report['samples'].append(sample)
                    save()
            worker.request(op='barrier')
            return counts
        report['warmup_counts'] = operations(WORKLOAD['warmup_operations'])
        baseline = snapshot()
        report['baseline'] = baseline
        save()
        for index in range(WORKLOAD['batches']):
            batch_started = time.monotonic()
            counts = operations(WORKLOAD['operations_per_batch'])
            state = snapshot()
            verify_settled(state, baseline)
            assert sum(counts.values()) == WORKLOAD['operations_per_batch'] and all(counts.values()), counts
            report['batches'].append({'number': index + 1, 'operations': sum(counts.values()), 'counts': counts,
                                      'duration_seconds': time.monotonic() - batch_started, 'final': state, 'status': 'passed'})
            save()
        assert len(report['batches']) == 3 and health['count'] > 0 and not health['errors']
        report['result'] = 'passed_development_batches'
    except Exception as error:
        report.update(result='failed', error=repr(error))
        raise
    finally:
        stop.set()
        if thread:
            thread.join(timeout=15)
            assert not thread.is_alive(), 'health worker failed to stop'
        report['healthy'] = health
        for actor in [worker, observer, daemon]:
            if actor:
                report['cleanup'].append(actor.stop())
        report['elapsed_seconds'] = time.monotonic() - started
        report['candidate_hashes_after'] = all(digest(candidate / p) == expected for p, expected in manifest['files'].items())
        if not report['candidate_hashes_after'] or not all(row['method'] == 'eof' and row['returncode'] == 0 for row in report['cleanup']):
            report.update(result='failed', cleanup_error='candidate mutation or unsuccessful graceful shutdown')
        save()
    assert report['result'] == 'passed_development_batches', report
    print(json.dumps({'result': report['result'], 'batches': len(report['batches']), 'healthy': health}))


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))
