"""Inactive standalone real-UID qualification; only a disposable guest may run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from collections import Counter

HERE = Path(__file__).resolve().parent
BUS = 'org.freedesktop.DBus'
LIMIT = BUS + '.Error.LimitsExceeded'
SOCKET = '/run/osbus-security/uid-authorities/bus'
OBSERVER = 'org.foundation.Root.Observer'
CONTROLS = dict(max_names_per_uid=2, max_matches_per_uid=2,
                max_names_per_peer=4, max_matches_per_peer=4,
                max_name_entries=16, max_match_entries=16)
ORIGINAL_PINS = {
    'daemon.exs': 'cba75169efa99be884ae758d64a690cc3a6e5fd28576adc5faf06260cdcd88fb',
    'actor.py': '1300769a2946b8b518deabd4899ce78fe7a8a7e048d0e9a33ef19f0e242d9772',
    'run.py': '292b89b5ecf7b39254b21f612ac99bfb8063790b96c244a67c45652462d2de1c',
    'state.ex': 'e3af1bf540aeaf881b60ec0ee7019f68866d6d167d80275ce644a21ff5f1f4d0',
    'policy.exs': '21d8c5d9f4312157e45aae628218799b5d3b20fa50eb46507d66572bb65fddd6',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(pid, uid):
    text = Path(f'/proc/{pid}/status').read_text()
    for key in ('Uid:', 'Gid:'):
        line = next(line for line in text.splitlines() if line.startswith(key))
        assert [int(value) for value in line.split()[1:]] == [uid] * 4, 'kernel identity drift'
    return text


def state_key(state):
    value = dict(state)
    value['peers'] = sorted(state['peers'], key=lambda row: row['peer'])
    value['names'] = sorted(state['names'])
    value['queues'] = sorted(state['queues'], key=lambda row: row['name'])
    value['usage'] = dict(state['usage'])
    for key in ('peers', 'uids'):
        value['usage'][key] = sorted(state['usage'][key], key=lambda row: str(row))
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def validate(state, actors, authorities):
    """Join the original snapshot, accepted kernel credentials and UID ledgers."""
    extra = state['uid_authorities']
    if authorities is not None:
        assert extra['authorities'] == authorities, 'authority restart'
    assert all(pid.startswith('#PID<') for pid in extra['authorities'].values())
    assert state['router'] == extra['authorities']['GaoBus.Router']
    children = {row['peer']: row for row in extra['children']}
    router = {row['peer']: row for row in state['peers']}
    account, usage = extra['accounting'], extra['limits']
    assert len(children) == len(extra['children']) == len(actors)
    assert len(router) == len(state['peers']) == len(actors)
    assert set(children) == set(router) == set(account['peers']) == set(usage['peers'])
    assert extra['supervised'] == dict(active=len(actors), specs=len(actors), workers=len(actors), supervisors=0)
    assert account['retired'] == account['reservations'] == account['bound_handles'] == account['accept_observers'] == {}
    assert account['reload'] is None and usage['reservations'] == usage['reload_reservations'] == 0
    assert usage['xml'] == {'limits': None, 'queues': None,
                            'global': {'incomplete': 0, 'completed': 0}, 'uids': {}}
    joins, totals, uids = {}, Counter(), {}
    assert len({actor['identity']['pid'] for actor in actors}) == len(actors)
    for actor in actors:
        accepted = actor['identity']
        proc = identity(accepted['pid'], accepted['uid'])
        matches = [row for row in children.values() if row.get('credentials', {}).get('pid') == accepted['pid']]
        assert len(matches) == 1, 'accepted credential join missing/duplicate'
        child = matches[0]
        peer = child['peer']
        assert child['phase'] == child['auth_phase'] == 'connected'
        assert child['unique'] == router[peer]['name'] == actor['unique']
        for key in ('pid', 'uid', 'gid'):
            assert child['credentials'][key] == router[peer]['credentials'][key] == accepted[key]
        admission = account['peers'][peer]
        assert admission['uid'] == accepted['uid'] and admission['monitor'].startswith('#Reference<')
        assert admission['tokens'] == {'map': {}} and admission['ingress_waiting'] is False
        assert admission['xml_completed'] is False
        assert admission['counts'] == usage['peers'][peer]
        counts = admission['counts']
        assert set(counts) == set(usage['global'])
        assert counts['connections'] == 1 and counts['authenticating'] == 0
        assert all(value == 0 for key, value in counts.items() if key != 'connections')
        totals.update(counts)
        uids.setdefault(str(accepted['uid']), Counter()).update(counts)
        joined = dict(peer=peer, identity=accepted, proc_status=proc,
                      unique=actor['unique'], admission=admission['monitor'])
        if 'join' in actor:
            assert {k: joined[k] for k in ('peer', 'identity', 'unique', 'admission')} == actor['join'], 'peer incarnation drift'
        else:
            actor['join'] = {k: joined[k] for k in ('peer', 'identity', 'unique', 'admission')}
        joins[peer] = joined
    assert set(joins) == set(children), 'incomplete actor coverage'
    assert dict(totals) == usage['global'] and {uid: dict(counts) for uid, counts in uids.items()} == usage['uids']
    assert state['usage']['global'] == usage['global'] and state['usage']['reservations'] == 0
    assert {row['peer']: row['counts'] for row in state['usage']['peers']} == usage['peers']
    assert {str(row['uid']): row['counts'] for row in state['usage']['uids']} == usage['uids']
    for scope, limits in (('global', {'connections': 6, 'authenticating': 3}), ('uid', {'connections': 4, 'authenticating': 2})):
        assert all(usage['limits'][scope][key] == value for key, value in limits.items())
    names, rules = extra['names'], extra['matches']
    for key, value in CONTROLS.items():
        assert (names if 'name' in key else rules)[key] == value
    assert names['xml_limits'] is rules['xml_limits'] is False
    uniques = sorted([actor['unique'], actor['join']['peer']] for actor in actors)
    assert names['uniques'] == uniques
    reverse = [[peer, unique] for unique, peer in uniques]
    name_counts = Counter()
    for name, owner, unique, flags, queue in names['names']:
        assert router[owner]['name'] == unique and isinstance(flags, int)
        associated = [owner]
        for peer, queued_unique, queued_flags in queue:
            assert router[peer]['name'] == queued_unique and isinstance(queued_flags, int)
            associated.append(peer)
        assert len(set(associated)) == len(associated), 'duplicate owner/queue association'
        for peer in associated:
            reverse.append([peer, name])
            name_counts[peer] += 1
    assert sorted(reverse) == sorted(names['pid_names'])
    queues = [dict(name=n, owner=p, unique=u, flags=f,
                   queue=[dict(peer=q, unique=v, flags=g) for q, v, g in qs])
              for n, p, u, f, qs in names['names']]
    assert sorted(state['queues'], key=lambda row: row['name']) == queues
    assert sorted(state['names']) == sorted([BUS] + [row[0] for row in names['names']] + [row[0] for row in uniques])
    match_counts = Counter(entry[0] for entry in rules['entries'])
    assert len({entry[1] for entry in rules['entries']}) == len(rules['entries'])
    assert all(p in joins and ref.startswith('#Reference<') and isinstance(rule, dict) and isinstance(raw, str)
               for p, ref, rule, raw in rules['entries'])
    for kind, counts in ((names, name_counts), (rules, match_counts)):
        assert set(kind['peers']) == set(counts)
        derived = Counter()
        monitors = []
        for peer, count in counts.items():
            cached, admitted = kind['peers'][peer], joins[peer]
            assert cached['uid'] == admitted['identity']['uid'] and cached['admission'] == admitted['admission']
            assert cached['count'] == count and cached['monitor'].startswith('#Reference<')
            assert cached['monitor'] != cached['admission']
            monitors.append(cached['monitor'])
            derived[str(cached['uid'])] += count
        assert len(set(monitors)) == len(monitors)
        assert dict(derived) == kind['uid_counts'], 'UID count differs from retained entries'
    return joins


def main(candidate, original, evidence, selection='all'):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security/uid-authorities'
    assert evidence.stat().st_uid == 0 and stat.S_IMODE(evidence.stat().st_mode) == 0o755
    assert not (evidence / 'qualification.json').exists() and not Path(SOCKET).exists()
    assert selection in ('all', 'uid_names', 'uid_matches')
    selected = ['uid_names', 'uid_matches'] if selection == 'all' else [selection]
    report = dict(version=1, fixture='standalone-uid-authorities', selected=selected,
                  outcomes={key: dict(status='blocked', reason='not_executed') for key in selected},
                  bounds=dict(authority_seconds=60, guest_seconds=120, host_seconds=900,
                              request_ms=1000, settled_phase_ms=1000, healthy_probe_ms=1000),
                  controls=CONTROLS, commands=[], actors=[], receipts=[], snapshots=[], probes=[],
                  actors_shutdown=[], shutdown_errors=[], result='failed', product_qualified=False, readiness='L0',
                  limitations='Separate native UID names/matches only; no eight-case RES01, XML, P12 or product acceptance')

    persistence_deferred = False

    def persist():
        statuses = [row['status'] for row in report['outcomes'].values()]
        report['counts'] = dict(selected=len(selected), executed=sum(s in ('passed', 'failed') for s in statuses),
                                passed=statuses.count('passed'), failed=statuses.count('failed'),
                                blocked=sum(s in ('blocked', 'running') for s in statuses), skipped=0)
        if persistence_deferred:
            return
        temporary = evidence / 'qualification.json.tmp'
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        temporary.replace(evidence / 'qualification.json')

    persist()
    for name, pin in ORIGINAL_PINS.items():
        assert not (original / name).is_symlink() and digest(original / name) == pin, ('original drift', name)
    sys.path.insert(0, str(original))
    spec = importlib.util.spec_from_file_location('uid_original_transport', original / 'run.py')
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['version'] == 1 and manifest['not_a_release'] is True
    for name, pin in manifest['files'].items():
        file = candidate / name
        mode = manifest['file_modes'][name]
        assert isinstance(mode, int) and 0 <= mode <= 0o777
        assert stat.S_ISREG(file.lstat().st_mode) and not file.is_symlink()
        assert stat.S_IMODE(file.stat().st_mode) == (0o555 if mode & 0o111 else 0o444)
        assert digest(file) == pin, ('candidate artifact drift', name)
    report.update(candidate=manifest, candidate_manifest_sha256=digest(candidate / 'candidate.json'),
                  original_pins=ORIGINAL_PINS, fixture_pins={p.name: digest(p) for p in HERE.iterdir() if p.is_file()})
    policy = evidence / 'policy.exs'
    overlay = ('original = elem(Code.eval_file(' + json.dumps(str(original / 'policy.exs')) + '), 0)\n'
               'original ++ [%{action: :own, effect: :allow, match: %{uid: 1100, name: {:prefix, "org.foundation.Uid"}}}, '
               '%{action: :own, effect: :allow, match: %{uid: 1101, name: {:prefix, "org.foundation.Uid"}}}]\n')
    policy.write_text(overlay)
    policy.chmod(0o600)
    assert policy.stat().st_uid == 0 and stat.S_IMODE(policy.stat().st_mode) == 0o600
    report['policy'] = dict(original_bytes=(original / 'policy.exs').read_text(), overlay_bytes=overlay,
                            overlay_sha256=digest(policy))
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(HERE / 'launcher.exs'), SOCKET, str(policy)]
    report['commands'].append(command)
    os.environ['UID_AUTHORITIES_ORIGINAL'] = str(original)
    started = time.monotonic()
    deadline = started + 60
    daemon, observer, authorities = None, None, None
    actors = []

    def remaining(bound=None):
        seconds = min(deadline, bound if bound is not None else deadline) - time.monotonic()
        assert seconds > 0, 'UID fixture deadline'
        return seconds

    def request(actor, **values):
        bound = time.monotonic() + 1
        actor['channel'].begin(**values)
        response = actor['channel'].read(timeout=remaining(bound))
        report['receipts'].append(dict(identity=actor['identity'], request=values, response=response))
        assert response['ok'], response
        return response['result']

    def call(actor, member, signature='', body=(), expected=None, error=None):
        actor['serial'] += 1
        response = request(actor, op='call', member=member, signature=signature, body=body)
        assert response['reply_serial'] == actor['serial'] and response['sender'] == BUS
        assert response['type'] == (3 if error else 2) and response['error'] == error, response
        if expected is not None:
            assert response['body'] == expected, response
        return response

    def live():
        return [actor for actor in actors if actor['active']]

    def settle():
        bound = min(deadline, time.monotonic() + 1)
        previous = None
        for _ in range(128):
            daemon.process.stdin.write(b'snapshot\n')
            daemon.process.stdin.flush()
            state = daemon.read(timeout=remaining(bound))
            sample = dict(state=state)
            report['snapshots'].append(sample)
            try:
                sample['joins'] = validate(state, live(), authorities)
            except (AssertionError, KeyError) as error:
                sample['unsettled'] = repr(error)
                previous = None
                continue
            key = state_key(state)
            if key == previous:
                assert time.monotonic() <= bound
                return state
            previous = key
        raise AssertionError('UID bounded settled readbacks exhausted')

    def healthy():
        begin = time.monotonic()
        call(observer, 'GetNameOwner', 's', [OBSERVER], expected=[observer['unique']])
        response = call(observer, 'GetId')
        if 'bus_id' not in report:
            report['bus_id'] = response['body']
        assert response['body'] == report['bus_id']
        elapsed = (time.monotonic() - begin) * 1000
        assert elapsed <= 1000
        report['probes'].append(dict(identity=observer['identity'], unique=observer['unique'], elapsed_ms=elapsed))

    def phase(row, label, names=0, matches=0, other_names=0, other_matches=0):
        state = settle()
        for kind, expected in (('names', {0: 1, 1100: names, 1101: other_names}),
                               ('matches', {0: 1, 1100: matches, 1101: other_matches})):
            assert state['uid_authorities'][kind]['uid_counts'] == {str(uid): n for uid, n in expected.items() if n}
        row.setdefault('phases', {})[label] = state
        healthy()
        persist()
        return state

    def spawn(uid):
        user = {0: 'root', 1100: 'foundationA', 1101: 'foundationB'}[uid]
        launch = ['runuser', '-u', user, '--', 'python3', str(original / 'actor.py'), SOCKET]
        channel = legacy.Actor(launch, evidence / f'actor-{len(actors)}.log')
        actor = dict(channel=channel, identity=None, unique=None, serial=1, active=False)
        actors.append(actor)
        report['commands'].append(launch)
        actor['identity'] = channel.read(timeout=remaining(time.monotonic() + 1))
        assert actor['identity']['uid'] == actor['identity']['gid'] == uid and actor['identity']['pid'] > 1
        report['actors'].append(dict(identity=actor['identity'], proc_status=identity(actor['identity']['pid'], uid)))
        response = request(actor, op='register')
        assert response['type'] == 2 and response['reply_serial'] == 1 and response['body'][0].startswith(':')
        actor['unique'] = response['body'][0]
        actor['active'] = True
        return actor

    def stop_channel(channel, accepted):
        before = dict(stdin_closed=False, wrapper_waited=False, wrapper_returncode=None,
                      pid_absent=False, actor_pid_absent=False, group_absent=False,
                      timed_out=False, errors=[])
        observed_start = time.monotonic()
        try:
            channel.process.stdin.close()
            before['stdin_closed'] = True
            try:
                before['wrapper_returncode'] = channel.process.wait(timeout=5)
                before['wrapper_waited'] = True
            except subprocess.TimeoutExpired:
                before['timed_out'] = True
            group_deadline = time.monotonic() + 1
            while True:
                before['pid_absent'] = not Path('/proc', str(channel.process.pid)).exists()
                before['actor_pid_absent'] = accepted is not None and not Path('/proc', str(accepted['pid'])).exists()
                try:
                    os.killpg(channel.process.pid, 0)
                except ProcessLookupError:
                    before['group_absent'] = True
                else:
                    before['group_absent'] = False
                if (before['pid_absent'] and before['actor_pid_absent'] and before['group_absent']
                        or before['timed_out'] or time.monotonic() >= group_deadline):
                    break
        except Exception as error:
            before['errors'].append(repr(error))
        finally:
            before['elapsed_ms'] = (time.monotonic() - observed_start) * 1000
            # Preserve the original final containment and raw-log draining.
            # Its EOF/exit0 label alone does not prove descendant retirement.
            result = channel.stop()
        result['before_containment'] = before
        group_deadline = time.monotonic() + 1
        while True:
            try:
                os.killpg(channel.process.pid, 0)
            except ProcessLookupError:
                result['group_absent'] = True
                break
            if time.monotonic() >= group_deadline:
                result['group_absent'] = False
                break
        result.update(identity=accepted, pid_absent=not Path('/proc', str(channel.process.pid)).exists(),
                      actor_pid_absent=accepted is not None and not Path('/proc', str(accepted['pid'])).exists())
        return result

    def stop(actor):
        if 'shutdown' in actor:
            return actor['shutdown']
        result = stop_channel(actor['channel'], actor['identity'])
        actor.update(shutdown=result, active=False)
        report['actors_shutdown'].append(result)
        return result

    def retire(actor):
        result = stop(actor)
        assert result['method'] == 'eof' and result['returncode'] == 0
        assert result['pid_absent'] is result['actor_pid_absent'] is result['group_absent'] is True
        before = result['before_containment']
        assert before['stdin_closed'] is before['wrapper_waited'] is True and before['wrapper_returncode'] == 0
        assert before['pid_absent'] is before['actor_pid_absent'] is before['group_absent'] is True
        assert before['timed_out'] is False and not before['errors']

    def poll(actor):
        return request(actor, op='poll', timeout=0.05)

    def drain():
        for actor in live():
            poll(actor)

    def denied(row, actor, member, signature, body):
        before = settle()
        kind = 'names' if member == 'RequestName' else 'matches'
        ledger = before['uid_authorities'][kind]
        peer_count = ledger['peers'].get(actor['join']['peer'], {}).get('count', 0)
        total = sum(peer['count'] for peer in ledger['peers'].values())
        assert ledger['uid_counts'][str(actor['identity']['uid'])] == 2
        assert peer_count < 4 and total < 16, 'UID denial confounded by peer/global ceiling'
        drain()
        call(actor, member, signature, body, error=LIMIT)
        healthy()
        after = settle()
        assert state_key(before) == state_key(after), 'denial mutated retained state or admission monitors'
        signals = [message for current in live() for message in poll(current)]
        assert not any(message['type'] == 4 and message['interface'] == BUS and
                       message['member'] in ('NameOwnerChanged', 'NameAcquired', 'NameLost') for message in signals), 'denial emitted name effects'
        row.setdefault('denials', []).append(dict(actor=actor['identity'], member=member, body=body,
                                                  headroom=dict(uid=0, peer=4-peer_count, global_entries=16-total),
                                                  before=before, after=after, signals=signals))

    def emit(member, token, expected):
        drain()
        observer['serial'] += 1
        sent = request(observer, op='send', message_type=4, destination=None,
                       path='/org/foundation/UidSignal', interface='org.foundation.UidSignal',
                       member=member, signature='s', body=[token])
        assert sent['sent'] == observer['serial']
        deliveries = {}
        for actor in live():
            messages = [message for message in poll(actor) if message['type'] == 4 and
                        message['interface'] == 'org.foundation.UidSignal' and message['member'] == member and message['body'] == [token]]
            assert len(messages) == int(actor in expected), ('unexpected delivery', actor['identity'], messages)
            assert all(message['sender'] == observer['unique'] for message in messages)
            deliveries[str(actor['identity']['pid'])] = messages
        return dict(member=member, token=token, deliveries=deliveries)

    def names_case(row):
        a, b, c, d = spawn(1100), spawn(1100), spawn(1100), spawn(1101)
        shared, refused, independent = 'org.foundation.Uid.Shared', 'org.foundation.Uid.Refused', 'org.foundation.Uid.Independent'
        phase(row, 'before')
        call(a, 'RequestName', 'su', [shared, 0], expected=[1])
        call(b, 'RequestName', 'su', [shared, 0], expected=[2])
        phase(row, 'N', names=2)
        denied(row, c, 'RequestName', 'su', [refused, 0])
        denied(row, c, 'RequestName', 'su', [shared, 0])
        phase(row, 'N_plus_1_denied', names=2)
        call(a, 'RequestName', 'su', [shared, 0], expected=[4])
        call(b, 'RequestName', 'su', [shared, 0], expected=[2])
        phase(row, 'repeats_uncharged', names=2)
        call(d, 'RequestName', 'su', [independent, 0], expected=[1])
        phase(row, 'other_uid_admitted', names=2, other_names=1)
        call(a, 'ReleaseName', 's', [shared], expected=[1])
        call(observer, 'GetNameOwner', 's', [shared], expected=[b['unique']])
        phase(row, 'release_promoted', names=1, other_names=1)
        call(a, 'RequestName', 'su', [shared, 0], expected=[2])
        before_death = phase(row, 'queue_reused', names=2, other_names=1)
        retire(b)
        after_death = phase(row, 'owner_death_promoted', names=1, other_names=1)
        for survivor in (a, d, observer):
            peer = survivor['join']['peer']
            assert after_death['uid_authorities']['names']['peers'][peer] == before_death['uid_authorities']['names']['peers'][peer]
        call(observer, 'GetNameOwner', 's', [shared], expected=[a['unique']])
        call(c, 'RequestName', 'su', [refused, 0], expected=[1])
        phase(row, 'owner_credit_reused', names=2, other_names=1)
        denied(row, a, 'RequestName', 'su', ['org.foundation.Uid.Third', 0])
        call(c, 'ReleaseName', 's', [refused], expected=[1])
        call(c, 'RequestName', 'su', [shared, 0], expected=[2])
        before_death = phase(row, 'queued_before_death', names=2, other_names=1)
        retire(c)
        after_death = phase(row, 'queued_death_reclaimed', names=1, other_names=1)
        for survivor in (a, d, observer):
            peer = survivor['join']['peer']
            assert after_death['uid_authorities']['names']['peers'][peer] == before_death['uid_authorities']['names']['peers'][peer]
        call(observer, 'GetNameOwner', 's', [shared], expected=[a['unique']])
        call(a, 'RequestName', 'su', [refused, 0], expected=[1])
        phase(row, 'queued_credit_reused', names=2, other_names=1)
        denied(row, a, 'RequestName', 'su', ['org.foundation.Uid.Third', 0])
        retire(a)
        phase(row, 'two_owner_entries_reclaimed', other_names=1)
        retire(d)
        phase(row, 'baseline_recovered')

    def matches_case(row):
        a, b, c, d = spawn(1100), spawn(1100), spawn(1100), spawn(1101)
        rule = "type='signal',interface='org.foundation.UidSignal',member='Retained'"
        duplicate = "member='Retained', interface='org.foundation.UidSignal', type='signal'"
        refused = "type='signal',interface='org.foundation.UidSignal',member='Refused'"
        phase(row, 'before')
        call(a, 'AddMatch', 's', [rule], expected=[])
        call(b, 'AddMatch', 's', [rule], expected=[])
        phase(row, 'N', matches=2)
        denied(row, a, 'AddMatch', 's', [refused])
        denied(row, c, 'AddMatch', 's', [refused])
        call(d, 'AddMatch', 's', [refused], expected=[])
        phase(row, 'other_uid_admitted', matches=2, other_matches=1)
        row.setdefault('deliveries', []).append(emit('Refused', 'denied-uid-independent', [d]))
        row['deliveries'].append(emit('Retained', 'retained-shared-peers', [a, b]))
        call(b, 'RemoveMatch', 's', [rule], expected=[])
        phase(row, 'one_removed', matches=1, other_matches=1)
        call(a, 'AddMatch', 's', [duplicate], expected=[])
        state = phase(row, 'canonical_duplicate_N', matches=2, other_matches=1)
        entries = [entry for entry in state['uid_authorities']['matches']['entries'] if entry[0] == a['join']['peer']]
        assert len(entries) == 2 and entries[0][2] == entries[1][2] and entries[0][1] != entries[1][1]
        row['deliveries'].append(emit('Retained', 'deduplicated-delivery', [a]))
        call(a, 'RemoveMatch', 's', [rule], expected=[])
        state = phase(row, 'one_duplicate_removed', matches=1, other_matches=1)
        survivors = [entry for entry in state['uid_authorities']['matches']['entries'] if entry[0] == a['join']['peer']]
        assert len(survivors) == 1 and survivors[0] in entries
        row['deliveries'].append(emit('Retained', 'surviving-duplicate-delivers', [a]))
        call(b, 'AddMatch', 's', [refused], expected=[])
        before_death = phase(row, 'exact_single_credit_reused', matches=2, other_matches=1)
        denied(row, c, 'AddMatch', 's', [rule])
        retire(a)
        after_death = phase(row, 'death_reclaimed_one', matches=1, other_matches=1)
        for survivor in (b, d, observer):
            peer = survivor['join']['peer']
            old = before_death['uid_authorities']['matches']
            new = after_death['uid_authorities']['matches']
            assert new['peers'][peer] == old['peers'][peer]
            assert [entry for entry in new['entries'] if entry[0] == peer] == [entry for entry in old['entries'] if entry[0] == peer]
        call(c, 'AddMatch', 's', [rule], expected=[])
        phase(row, 'death_credit_reused', matches=2, other_matches=1)
        denied(row, c, 'AddMatch', 's', [refused])
        row['deliveries'].append(emit('Refused', 'surviving-other-uid', [b, d]))
        row['deliveries'].append(emit('Retained', 'new-peer-after-death', [c]))
        for actor in (b, c, d):
            retire(actor)
        phase(row, 'baseline_recovered')

    try:
        daemon = legacy.Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        provenance = report['provenance'] = daemon.read(timeout=remaining())
        ready = report['daemon'] = daemon.read(timeout=remaining())
        assert provenance['event'] == 'uid_authorities_provenance' and provenance['original_sha256'] == ORIGINAL_PINS['daemon.exs']
        transformed = provenance['transformed_sha256']
        assert len(transformed) == 64 and all(c in '0123456789abcdef' for c in transformed)
        assert transformed != provenance['original_sha256']
        assert provenance['transformation'] == 'uid-two-defaults-one-readonly-snapshot-v1'
        assert provenance['defaults_replaced'] == 2 and provenance['snapshot_insertions'] == 1
        assert provenance['authorities'] == CONTROLS and provenance['lifecycle'] == 'embedded'
        assert provenance['config_file'] is None and provenance['inherited_listener'] is False
        assert provenance['max_connections'] == 256
        profile = {scope: dict(values) for scope, values in provenance['defaults_profile'].items()}
        profile['global'].update(connections=6, authenticating=3)
        profile['uid'].update(connections=4, authenticating=2)
        assert provenance['profile'] == profile == ready['configuration']['resource_limits']
        assert ready['event'] == 'ready' and int(ready['pid']) == daemon.process.pid
        assert ready['identity']['uid'] == ready['identity']['gid'] == 0
        report['daemon_proc_status'] = identity(daemon.process.pid, 0)
        assert ready['configuration']['auth_limits'] == dict(timeout_ms=1500, idle_timeout_ms=500)
        assert ready['configuration']['socket_path'] == SOCKET and ready['configuration']['profile'] == 'system'
        assert ready['configuration']['cluster'] is ready['configuration']['capability_restrictions'] is False
        assert Path(SOCKET).stat().st_uid == 0 and stat.S_ISSOCK(Path(SOCKET).stat().st_mode)
        assert stat.S_IMODE(Path(SOCKET).stat().st_mode) == 0o666
        observer = spawn(0)
        call(observer, 'RequestName', 'su', [OBSERVER, 0], expected=[1])
        call(observer, 'AddMatch', 's', ["type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'"], expected=[])
        baseline = settle()
        authorities = baseline['uid_authorities']['authorities']
        report['baseline'] = baseline
        healthy()
        for case in selected:
            row = report['outcomes'][case]
            row['status'] = 'running'
            persist()
            previous_deferral = persistence_deferred
            persistence_deferred = True
            try:
                {'uid_names': names_case, 'uid_matches': matches_case}[case](row)
                assert state_key(row['phases']['baseline_recovered']) == state_key(baseline)
                row.update(status='passed', reason='passed_selected_standalone_scope')
            except Exception as error:
                row.update(status='failed', reason=repr(error))
                raise
            finally:
                persistence_deferred = previous_deferral
                persist()
        report['final_baseline'] = settle()
        assert state_key(report['final_baseline']) == state_key(baseline)
    except Exception as error:
        report['failure'] = repr(error)
        persist()
        raise
    finally:
        for actor in actors:
            try:
                stop(actor)
            except Exception as error:
                report['shutdown_errors'].append(repr(error))
        if daemon is not None:
            try:
                daemon.process.stdin.write(b'quit\n')
                daemon.process.stdin.flush()
                report['quit_flushed'] = True
            except Exception as error:
                report['quit_flushed'] = False
                report['shutdown_errors'].append(repr(error))
            try:
                report['daemon_shutdown'] = stop_channel(daemon, dict(pid=daemon.process.pid, uid=0, gid=0))
                report['socket_removed'] = not Path(SOCKET).exists()
            except Exception as error:
                report['shutdown_errors'].append(repr(error))
        report['authority_elapsed_ms'] = (time.monotonic() - started) * 1000
        persist()
    try:
        assert report['selected'] and all(row['status'] == 'passed' for row in report['outcomes'].values())
        assert not report['shutdown_errors'] and report['quit_flushed'] is report['socket_removed'] is True
        assert len(report['actors_shutdown']) == len(actors) == len(report['actors'])
        for shutdown in report['actors_shutdown'] + [report['daemon_shutdown']]:
            assert shutdown['method'] == 'eof' and shutdown['returncode'] == 0
            assert shutdown['pid_absent'] is shutdown['actor_pid_absent'] is shutdown['group_absent'] is True
            before = shutdown['before_containment']
            assert before['stdin_closed'] is before['wrapper_waited'] is True and before['wrapper_returncode'] == 0
            assert before['pid_absent'] is before['actor_pid_absent'] is before['group_absent'] is True
            assert before['timed_out'] is False and not before['errors']
        assert report['authority_elapsed_ms'] <= 60_000
    except Exception as error:
        report['acceptance_failure'] = repr(error)
        persist()
        raise
    report['result'] = 'passed_selected_standalone_scope'
    persist()
    print(json.dumps(dict(result=report['result'], counts=report['counts'], product_qualified=False, readiness='L0')))


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] if len(sys.argv) == 5 else 'all')
