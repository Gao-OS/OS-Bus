"""One valid incomplete-frame owner death, in the existing isolated quota harness."""
import json
import os
from pathlib import Path
import sys
import time

from actor import WORKLOAD, digest
from channel import Actor, Channel
from contract import PASS, ROLES, assert_report, assert_state

HERE = Path(__file__).resolve().parent


def sha(path):
    return digest(path.read_bytes())


def external(pid):
    root = Path('/proc') / str(pid)
    targets, resources = [], []
    for entry in (root / 'fd').iterdir():
        try:
            target = os.readlink(entry)
            targets.append(target)
            if '/memfd:' in target:
                info = entry.stat()
                resources.append(dict(dev=info.st_dev, ino=info.st_ino, mode=info.st_mode,
                                      size=info.st_size, target=target))
        except FileNotFoundError:
            pass
    values = {line.split(':', 1)[0]: line.split(':', 1)[1].split()
              for line in (root / 'status').read_text().splitlines() if ':' in line}
    return dict(pid=int(values['Pid'][0]), uids=list(map(int, values['Uid'])),
                gids=list(map(int, values['Gid'])), fds=len(targets), targets=sorted(targets),
                memfds=sorted(x for x in targets if '/memfd:' in x),
                resources=sorted(resources, key=lambda x: (x['dev'], x['ino'])))


def main(candidate, evidence, helpers, quota_dir, collector):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-fd-quotas' and not (evidence / 'bus').exists()
    assert not (evidence / 'report.json').exists()
    manifest_path = candidate / 'candidate.json'
    manifest = json.loads(manifest_path.read_text())
    assert sha(manifest_path) == WORKLOAD['candidate_manifest_sha256']
    assert manifest['not_a_release'] and len(manifest['files']) == 80 and len(manifest['sources']) == 71

    def candidate_ok():
        return sha(manifest_path) == WORKLOAD['candidate_manifest_sha256'] and all(sha(candidate / p) == h for p, h in manifest['files'].items())

    assert candidate_ok()
    immutable = [helpers / 'transport.py', helpers / 'channel.py', quota_dir / 'daemon.exs', collector]
    immutable += [p for p in HERE.iterdir() if p.is_file()]
    report = dict(schema=1, requirement='SEC-17', subcase='valid-incomplete-frame-peer-death',
                  result='running', not_a_release=True, workload=WORKLOAD,
                  helpers_before={str(p): sha(p) for p in immutable}, cleanup=[], attempts={},
                  phases={}, phase_order=[], commands=[])

    def save():
        (evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

    def mark(phase):
        report['phase_order'].append(phase)
        save()

    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(HERE / 'daemon.exs'), str(evidence / 'bus'), str(collector), str(quota_dir / 'daemon.exs')]
    actors, daemon = {}, None
    started = time.monotonic()
    try:
        report['commands'].append(command)
        daemon = Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        report['ready'] = daemon.read()
        for role in ROLES:
            cmd = ['runuser', '-u', 'foundationA' if WORKLOAD['roles'][role] == 1100 else 'foundationB',
                   '--', 'python3', '-B', str(HERE / 'actor.py'), str(evidence / 'bus'), role]
            report['commands'].append(cmd)
            actor = Actor(cmd, evidence / ('actor-%s.log' % role))
            actors[role] = actor
            actor.identity = actor.finish()

        def sample(op='inspect'):
            state = daemon.write(op)
            state['external'] = external(int(state['pid']))
            state['actors'] = {role: external(a.identity['pid']) for role, a in actors.items()}
            return state

        def connect():
            for actor in actors.values():
                actor.identity.update(actor.request(op='connect'))
            identities = {role: a.identity.copy() for role, a in actors.items()}
            state = sample()
            mapping = {}
            for role, identity in identities.items():
                peer, = [p for p in state['peers'] if p['name'] == identity['name']]
                assert peer['credentials'] == {k: identity[k] for k in ('pid', 'uid', 'gid')} and peer['negotiated']
                mapping[role] = peer['peer']
            return identities, mapping

        def observe(phase, present, holding=False, deadline=None):
            deadline = deadline if deadline is not None else time.monotonic() + WORKLOAD['cleanup_ms'] / 1000
            report['attempts'][phase] = []
            while True:
                assert time.monotonic() < deadline, ('snapshot deadline', phase)
                state = sample('metrics' if phase == 'final' else 'inspect')
                report['attempts'][phase].append(state)
                try:
                    assert_state(state, present, holding, report)
                except AssertionError:
                    save()
                    assert time.monotonic() < deadline, ('snapshot deadline', phase)
                    continue
                assert time.monotonic() <= deadline
                report['phases'][phase] = state
                mark(phase)
                return state

        report['warm_identities'], _ = connect()
        actors['observer'].begin(op='warm_receive')
        report['warm_send'] = actors['source'].request(op='warm_send', target=report['warm_identities']['observer']['name'])
        report['warm_receive'] = actors['observer'].finish()
        mark('warmup')
        for actor in actors.values():
            actor.request(op='close')
        report['baseline'] = sample('metrics')
        mark('baseline')
        report['identities'], report['peer_map'] = connect()
        observe('connected', ROLES)
        report['watch'] = daemon.write('watch ' + report['identities']['source']['name'])
        mark('watch')
        report['prefix'] = actors['source'].request(op='prefix', target=report['identities']['observer']['name'])
        mark('prefix')
        observe('held', ROLES, True)
        name = report['identities']['source']['name']
        report['frame_guard'] = daemon.write('frame ' + name)
        mark('frame_guard')
        tick = time.monotonic()
        report['kill'] = daemon.write('kill %s %s' % (name, name))
        mark('kill')
        observe('reclaimed', ('observer',), deadline=tick + WORKLOAD['cleanup_ms'] / 1000)
        report['cleanup_elapsed_ms'] = (time.monotonic() - tick) * 1000
        tick = time.monotonic()
        actors['observer'].begin(op='health')
        response = actors['observer'].read(timeout=WORKLOAD['healthy_ms'] / 1000)
        assert response['ok'], response
        report['health'] = response['result']
        report['health_elapsed_ms'] = (time.monotonic() - tick) * 1000
        mark('health')
        observe('after_health', ('observer',))
        report['source_eof'] = actors['source'].request(op='eof')
        mark('source_eof')
        tick = time.monotonic()
        report['actor_final'] = {role: actor.request(op='close') for role, actor in actors.items()}
        mark('close')
        observe('final', (), deadline=tick + WORKLOAD['cleanup_ms'] / 1000)
        report['final_cleanup_elapsed_ms'] = (time.monotonic() - tick) * 1000
        report['counts'] = dict(warmup=1, prefix=1, killed=1, health=1)
        report['result'] = PASS
    except Exception as error:
        report.update(result='failed', error=repr(error))
    finally:
        for role, actor in actors.items():
            try:
                report['cleanup'].append(dict(role=role, **actor.stop()))
            except Exception as error:
                report['cleanup'].append(dict(role=role, error=repr(error)))
        if daemon:
            try:
                report['cleanup'].append(dict(role='daemon', **daemon.stop()))
                for line in (evidence / 'daemon.log').read_text().splitlines():
                    if line.startswith('FIXTURE '):
                        event = json.loads(line[len('FIXTURE '):])
                        if event.get('event') == 'watcher_stopped':
                            report['watcher_shutdown'] = event
                        elif event.get('event') == 'collector_stopped':
                            report['collector_shutdown'] = event
            except Exception as error:
                report['cleanup'].append(dict(role='daemon', error=repr(error)))
        report['elapsed_seconds'] = time.monotonic() - started
        report['candidate_hashes_after'] = candidate_ok()
        report['helpers_after'] = {str(p): sha(p) for p in immutable}
        try:
            assert_report(report)
        except Exception as error:
            report.update(result='failed', completion_error=repr(error))
        save()
    assert report['result'] == PASS, report.get('completion_error', report.get('error'))
    print(json.dumps(dict(result=PASS, counts=report['counts'], not_a_release=True)))


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))
