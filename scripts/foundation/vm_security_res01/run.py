"""Eight real-UID native boundaries; only a disposable guest may execute."""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
cleanup_spec = importlib.util.spec_from_file_location('res01_cleanup', HERE / 'cleanup.py')
cleanup = importlib.util.module_from_spec(cleanup_spec)
cleanup_spec.loader.exec_module(cleanup)
stop_channel = cleanup.stop_channel
WORKLOAD = json.loads((HERE / 'workload.json').read_text())
SELECTED = WORKLOAD['selected']
BUS = 'org.freedesktop.DBus'
LIMIT = BUS + '.Error.LimitsExceeded'
PHASES = ('before', 'N', 'rejected', 'released', 'reused', 'baseline', 'baseline_repeated')
METRICS = {'connections', 'authenticating', 'ingress_messages', 'ingress_bytes', 'ingress_fds',
           'egress_messages', 'egress_bytes', 'egress_fds', 'frame_bytes', 'frame_fds',
           'activation_messages', 'activation_bytes', 'activation_fds'}
TRIALS = {
    'uid_connections': ('1100', '1101'), 'global_connections': ('mixed',),
    'uid_authenticating': ('1100', '1101'), 'global_authenticating': ('mixed',),
    'peer_names': ('1100', '1101'), 'global_names': ('queued',),
    'peer_matches': ('1100', '1101', 'duplicate'), 'global_matches': ('mixed',),
}


def guard_source(source):
    for anchor, count in [('GaoBus.Limits.defaults()', 2),
                          ('Application.put_env(:gao_bus, :resource_limits, GaoBus.Limits.defaults())', 1),
                          ('    resource_limits: GaoBus.Limits.defaults()', 1),
                          ('Stream.repeatedly(fn -> IO.read(:stdio, :line) end)', 1)]:
        assert source.count(anchor) == count, ('source anchor/count drift', anchor)


def validate_provenance(provenance, ready):
    assert provenance['event'] == 'res01_provenance'
    assert provenance['original_sha256'] == WORKLOAD['original_pins']['daemon.exs']
    transformed = provenance['transformed_sha256']
    assert len(transformed) == 64 and all(c in '0123456789abcdef' for c in transformed)
    assert transformed != provenance['original_sha256'], 'dishonest unmodified execution claim'
    assert provenance['transformation'] == 'res01-two-defaults-one-readonly-snapshot-v1'
    assert provenance['defaults_replaced'] == 2 and provenance['snapshot_insertions'] == 1
    assert provenance['authorities'] == WORKLOAD['authorities']
    assert provenance['lifecycle'] == 'embedded' and provenance['config_file'] is None
    assert provenance['inherited_listener'] is False and provenance['max_connections'] == 256
    assert ready['configuration']['resource_limits'] == provenance['profile']
    expected_profile = {scope: dict(values) for scope, values in provenance['defaults_profile'].items()}
    for scope, values in WORKLOAD['profile'].items():
        expected_profile[scope].update(values)
    assert provenance['profile'] == expected_profile, 'unrelated default ceiling changed'
    for scope, ceilings in WORKLOAD['profile'].items():
        for metric, ceiling in ceilings.items():
            assert provenance['profile'][scope][metric] == ceiling
    assert ready['configuration']['auth_limits'] == {'timeout_ms': 1500, 'idle_timeout_ms': 500}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def validate_artifact_mode(source_mode, metadata):
    assert isinstance(source_mode, int) and 0 <= source_mode <= 0o777, 'untrusted source mode'
    assert stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), 'candidate leaf must be regular/nonsymlink'
    expected = 0o555 if source_mode & 0o111 else 0o444
    actual = stat.S_IMODE(metadata.st_mode)
    assert actual == expected, ('readonly candidate mode/execute-bit drift', actual, expected)
    return dict(source_mode=source_mode, expected_store_mode=expected, actual_store_mode=actual)


def state_key(state):
    # Keep every original observation; order-only changes are not mutations.
    result = dict(state)
    for key, order in [('peers', 'peer'), ('queues', 'name')]:
        result[key] = sorted(result[key], key=lambda row: row[order])
    result['names'] = sorted(result['names'])
    result['usage'] = dict(result['usage'])
    for key, order in [('peers', 'peer'), ('uids', 'uid')]:
        result['usage'][key] = sorted(result['usage'][key], key=lambda row: row[order])
    return canonical(result)


def reply(result, body=None, error=None):
    message = result['reply']
    assert message['reply_serial'] == result['request_serial'], 'reply serial drift'
    assert message['type'] == (3 if error else 2), message
    assert message['error'] == error, message
    if body is not None:
        assert message['body'] == body, message
    return message


def validate_identity(identity, expected):
    assert expected in (1100, 1101), 'unexpected real UID'
    assert identity['uid'] == expected and identity['gid'] == expected
    assert isinstance(identity['pid'], int) and identity['pid'] > 1
    for key in ('Uid:', 'Gid:'):
        values = next(line for line in identity['proc_status'].splitlines() if line.startswith(key))
        assert [int(item) for item in values.split()[1:]] == [expected] * 4, 'OS identity drift'


def validate_state(state, active, authorities=None):
    """Reconcile independent Router, supervisor, kernel identity and authority tables."""
    extra = state['res01']
    if authorities is not None:
        assert extra['authorities'] == authorities, 'authority restart'
    assert all(pid.startswith('#PID<') for pid in extra['authorities'].values())
    assert state['router'] == extra['authorities']['GaoBus.Router']
    limits = extra['limits']
    assert set(limits['global']) == METRICS, 'incomplete metric observation'
    accounting = extra['accounting']
    assert accounting['retired'] == {}, 'retained ingress tombstone'
    assert accounting['reservations'] == accounting['bound_handles'] == {}
    assert accounting['accept_observers'] == {} and accounting['reload'] is None
    assert limits['reservations'] == limits['reload_reservations'] == 0
    assert limits['xml'] == {'limits': None, 'queues': None, 'global': {'incomplete': 0, 'completed': 0}, 'uids': {}}
    for scope, ceilings in WORKLOAD['profile'].items():
        for metric, ceiling in ceilings.items():
            assert limits['limits'][scope][metric] == ceiling, 'effective Limits profile drift'
    expected_peers = accounting['peers']
    children = {row['peer']: row for row in extra['children']}
    assert len(children) == len(extra['children']) == len(active), 'supervised identity drift'
    assert extra['supervised']['active'] == len(children) == len(expected_peers)
    assert extra['supervised'] == dict(active=len(children), specs=len(children), workers=len(children), supervisors=0)
    assert set(children) == set(expected_peers) == set(limits['peers'])
    active_pids = [actor['identity']['pid'] for actor in active]
    assert len(set(active_pids)) == len(active_pids), 'duplicate active actor PID'
    router = {row['peer']: row for row in state['peers']}
    assert len(router) == len(state['peers'])
    joined = []
    totals = {metric: 0 for metric in limits['global']}
    uid_totals = {}
    for actor in active:
        identity = actor['identity']
        validate_identity(identity, identity['uid'])
        rows = [row for row in children.values() if row.get('credentials', {}).get('pid') == identity['pid']]
        assert len(rows) == 1, 'missing/duplicate trusted actor PID'
        child = rows[0]
        peer = child['peer']
        for key in ('pid', 'uid', 'gid'):
            assert child['credentials'][key] == identity[key], 'trusted credential drift'
        account = expected_peers[peer]
        assert account['uid'] == identity['uid']
        assert account['tokens'] == {'map': {}} and account['ingress_waiting'] is False
        assert account['xml_completed'] is False
        assert account['counts'] == limits['peers'][peer]
        counts = account['counts']
        assert set(counts) == METRICS
        held = actor['unique'] is None
        assert counts['connections'] == 1 and counts['authenticating'] == int(held)
        if held:
            assert peer not in router and child['unique'] is None
            assert child['phase'] == 'authenticating' and child['auth_phase'] == 'authenticated'
        else:
            assert router[peer]['name'] == child['unique'] == actor['unique']
            assert child['phase'] == child['auth_phase'] == 'connected'
            for key in ('pid', 'uid', 'gid'):
                assert router[peer]['credentials'][key] == identity[key]
        for metric, count in counts.items():
            assert isinstance(count, int) and count >= 0
            if metric not in ('connections', 'authenticating'):
                assert count == 0, ('unretired transient credit', metric)
            totals[metric] += count
            uid_totals.setdefault(str(identity['uid']), {name: 0 for name in totals})[metric] += count
        joined.append(dict(identity=identity, peer=peer, unique=actor['unique'], counts=counts, child=child))
    joined_peers = [row['peer'] for row in joined]
    assert len(set(joined_peers)) == len(joined_peers), 'duplicate joined peer identity'
    assert set(joined_peers) == set(children) == set(expected_peers) == set(limits['peers']), 'incomplete trusted peer join coverage'
    assert totals == limits['global'] and uid_totals == limits['uids'], 'global/UID accounting drift'
    assert state['usage']['global'] == totals and state['usage']['reservations'] == 0
    assert {row['peer']: row['counts'] for row in state['usage']['peers']} == limits['peers']
    assert {str(row['uid']): row['counts'] for row in state['usage']['uids']} == uid_totals
    assert set(router) == {row['peer'] for row in joined if row['unique'] is not None}
    names, matches = extra['names'], extra['matches']
    for control, ceiling in WORKLOAD['authorities'].items():
        authority = names if 'name' in control else matches
        assert authority[control] == ceiling, 'initialized name/match profile drift'
        assert authority['xml_limits'] is False
    uniques = sorted([row['unique'], row['peer']] for row in joined if row['unique'] is not None)
    assert names['uniques'] == uniques, 'unique table drift'
    reverse = [[peer, unique] for unique, peer in uniques]
    for name, owner, unique, flags, queue in names['names']:
        assert owner in router and router[owner]['name'] == unique
        reverse.append([owner, name])
        assert isinstance(flags, int)
        seen = {owner}
        for peer, queued_unique, queued_flags in queue:
            assert peer in router and peer not in seen and router[peer]['name'] == queued_unique
            assert isinstance(queued_flags, int)
            seen.add(peer)
            reverse.append([peer, name])
    assert sorted(reverse) == sorted(names['pid_names']), 'name queue/reverse association drift'
    queues = [dict(name=n, owner=p, unique=u, flags=f,
                   queue=[dict(peer=q, unique=v, flags=g) for q, v, g in qs])
              for n, p, u, f, qs in names['names']]
    assert sorted(state['queues'], key=lambda row: row['name']) == queues
    assert sorted(state['names']) == sorted([BUS] + [row[0] for row in names['names']] + [row[0] for row in uniques])
    entries = matches['entries']
    assert len({row[1] for row in entries}) == len(entries), 'duplicate match reference identity'
    assert all(peer in router and reference.startswith('#Ref<') and isinstance(rule, dict) and isinstance(raw, str)
               for peer, reference, rule, raw in entries)
    for peer, row in router.items():
        assert row['match_rules'] == any(entry[0] == peer for entry in entries)
        primary_names = [row['name']] + [name for name, owner, _, _, _ in names['names'] if owner == peer]
        assert sorted(row['names']) == sorted(primary_names), 'unique/primary name observation drift'
        assert row['capabilities'] == 0
    return joined


def headroom(state, peer, uid, dimension, unique=True):
    limits = state['res01']['limits']
    quotas = limits['limits']
    uid_counts = limits['uids'].get(str(uid), {})
    candidates = {}
    for scope, counts in [('uid', uid_counts), ('global', limits['global'])]:
        for metric in ('connections', 'authenticating'):
            candidates[scope + '_' + metric] = quotas[scope][metric] - counts.get(metric, 0)
    names = state['res01']['names']['names']
    associations = [owner for _, owner, _, _, _ in names] + [row[0] for *_, queue in names for row in queue]
    entries = state['res01']['matches']['entries']
    candidates.update(peer_names=2 - associations.count(peer), global_names=4 - len(associations),
                      peer_matches=2 - sum(row[0] == peer for row in entries), global_matches=3 - len(entries))
    relevant = (('uid_connections', 'global_connections', 'uid_authenticating', 'global_authenticating')
                if 'connections' in dimension or 'authenticating' in dimension
                else ('peer_names', 'global_names') if 'names' in dimension else ('peer_matches', 'global_matches'))
    assert candidates[dimension] == 0, ('N not reached', candidates)
    if unique:
        assert all(candidates[key] > 0 for key in relevant if key != dimension), ('nonunique exhaustion', candidates)
    return dict(target=dimension, remaining=candidates, relevant=list(relevant))


def complete(report):
    assert report['selected'] == SELECTED and len(SELECTED) == 8 and len(set(SELECTED)) == 8
    assert set(report['outcomes']) == set(SELECTED), 'missing selected outcomes'
    assert {'baseline', 'authorities', 'bus_id'}.issubset(report), 'missing original observer/authority binding'
    assert report['baseline']['res01']['authorities'] == report['authorities'], 'original authority binding drift'
    observer = next(row for row in report['baseline']['peers'] if 'org.foundation.Observer' in row['names'])

    def validate_observation(observation):
        assert isinstance(observation, dict), 'missing full saved observation'
        joined = validate_state(observation['state'], observation['active'], report['authorities'])
        assert observation['joins'] == joined, 'saved identity/accounting joins drift'
        observed = [row for row in observation['state']['peers'] if row['peer'] == observer['peer']]
        assert len(observed) == 1, 'original observer missing'
        assert observed[0]['name'] == observer['name'] and observed[0]['credentials'] == observer['credentials'], 'observer identity replaced'
        return {row['peer']: row for row in joined}

    for dimension, row in report['outcomes'].items():
        assert row['status'] == 'passed', ('not executed/passed', dimension)
        assert set(row['trials']) == set(TRIALS[dimension]), 'missing real-UID/duplicate trial'
        for label, trial in row['trials'].items():
            expected_uid = int(label) if label in ('1100', '1101') else 1100 if label == 'duplicate' else 1101
            assert trial['target_uid'] == expected_uid, 'required UID trial drift'
            assert set(PHASES).issubset(trial['phases']), 'missing full lifecycle phases'
            phases = trial['phases']
            phase_joins = {}
            for phase in PHASES:
                phase_joins[phase] = validate_observation(phases[phase])
            assert state_key(phases['N']['state']) == state_key(phases['rejected']['state']), 'partial rejected mutation'
            assert state_key(phases['before']['state']) == state_key(phases['baseline']['state']) == state_key(phases['baseline_repeated']['state']), 'retirement drift'
            assert trial['headroom'] == headroom(phases['N']['state'], trial['target_peer'], trial['target_uid'], dimension)
            assert headroom(phases['reused']['state'], trial['reused_peer'], trial['target_uid'], dimension, unique=False)['target'] == dimension
            rejection = trial['rejection']
            if 'connections' in dimension or 'authenticating' in dimension:
                assert rejection['admitted'] is False and rejection['closed'] is True and rejection['begin_sent'] is False
                assert b'OK ' not in bytes.fromhex(rejection['response_hex'])
            else:
                reply(rejection, error=LIMIT)
            expected_allocations = {'global_connections': 5, 'global_authenticating': 3, 'global_names': 3, 'global_matches': 3}.get(dimension, 2)
            if dimension == 'uid_connections':
                expected_allocations = 3 if trial['target_uid'] == 1100 else 4
            if dimension == 'peer_names' and trial['target_uid'] == 1100:
                expected_allocations = 1
            assert len(trial['allocations']) == expected_allocations and all(item['success'] is True for item in trial['allocations'])
            assert trial['reallocation_ms'] <= WORKLOAD['bounds']['reallocate_ms']
            assert trial['probes'] and all(0 <= item['elapsed_ms'] <= 1000 for item in trial['probes'])
            for probe in trial['probes']:
                assert probe['owner']['type'] == probe['bus_id']['type'] == 2
                assert probe['owner']['body'] == [observer['name']] and probe['bus_id']['body'] == report['bus_id']
            assert trial['socket_closes'] and all(item['closed'] is True for item in trial['socket_closes'])
            if dimension in ('uid_connections', 'uid_authenticating'):
                independent = trial['independent']
                independent_joins = validate_observation(independent)
                original = phase_joins['N']
                assert len(independent_joins) == len(original) + 1 and original.keys() <= independent_joins.keys(), 'missing independent admission'
                assert all(independent_joins[peer] == joined for peer, joined in original.items()), 'independence changed saturated actors'
                witness = next(joined for peer, joined in independent_joins.items() if peer not in original)
                assert witness['identity']['uid'] == (1101 if trial['target_uid'] == 1100 else 1100), 'independent witness UID drift'
                held = dimension == 'uid_authenticating'
                assert (witness['unique'] is None) == held, 'independent witness BEGIN phase drift'
                n_limits = phases['N']['state']['res01']['limits']
                independent_limits = independent['state']['res01']['limits']
                uid_key = str(trial['target_uid'])
                metric = 'authenticating' if held else 'connections'
                assert independent_limits['uids'][uid_key] == n_limits['uids'][uid_key], 'saturated UID credit changed'
                assert independent_limits['uids'][uid_key][metric] == WORKLOAD['profile']['uid'][metric], 'independence without target saturation'
                assert independent_limits['global'] == dict(n_limits['global'],
                    connections=n_limits['global']['connections'] + 1,
                    authenticating=n_limits['global']['authenticating'] + int(held)), 'independent witness global credit drift'
            if 'authenticating' in dimension:
                assert 0 < trial['held_elapsed_ms'] <= 400
                assert trial['auth_completed']['connections_unchanged'] is True
                assert trial['auth_completed']['auth_delta'] == -1
                n_counts = phases['N']['state']['res01']['limits']['global']
                released_counts = phases['released']['state']['res01']['limits']['global']
                # UID trials may first admit/complete their independent witness.
                assert released_counts['authenticating'] == n_counts['authenticating'] - 1
                assert released_counts['connections'] == n_counts['connections'] + int(dimension == 'uid_authenticating')
                completed = trial['all_completed']
                completed_joins = validate_observation(completed)
                original, reused = phase_joins['N'], phase_joins['reused']
                assert trial['reused_peer'] not in original and reused.keys() == original.keys() | {trial['reused_peer']}, 'original authentication holders replaced'
                assert reused[trial['reused_peer']]['identity']['uid'] == trial['target_uid'], 'reused authentication UID drift'
                assert all(reused[peer]['identity'] == joined['identity'] for peer, joined in original.items()), 'original authentication holder identity drift'
                assert completed_joins.keys() == reused.keys(), 'missing/substituted completed holder'
                for peer, joined in reused.items():
                    finished = completed_joins[peer]
                    assert finished['identity'] == joined['identity'] and finished['unique'] is not None, 'authentication holder did not complete'
                    if joined['unique'] is not None:
                        assert finished['unique'] == joined['unique'], 'completed unique identity changed'
                    assert finished['counts'] == dict(joined['counts'], authenticating=0), 'completion peer credit drift'
                reused_limits = phases['reused']['state']['res01']['limits']
                completed_limits = completed['state']['res01']['limits']
                assert completed_limits['global'] == dict(reused_limits['global'], authenticating=0), 'completion global connection/auth credit drift'
                assert completed_limits['uids'] == {uid: dict(counts, authenticating=0)
                    for uid, counts in reused_limits['uids'].items()}, 'completion UID connection/auth credit drift'
            elif 'connections' in dimension:
                assert phases['released']['state']['res01']['limits']['global']['connections'] == phases['N']['state']['res01']['limits']['global']['connections'] - 1
            elif 'matches' in dimension:
                n_entries = phases['N']['state']['res01']['matches']['entries']
                released_entries = phases['released']['state']['res01']['matches']['entries']
                assert len(released_entries) == len(n_entries) - 1 and all(entry in n_entries for entry in released_entries)
                if dimension == 'peer_matches' and label == 'duplicate':
                    assert len(n_entries) == 2 and all(entry[0] == trial['target_peer'] for entry in n_entries), 'missing duplicate peer allocations'
                    assert n_entries[0][2] == n_entries[1][2], 'duplicate parsed rules are not canonical equals'
                    references = {entry[1] for entry in n_entries}
                    assert len(references) == 2, 'duplicate allocations share a reference'
                    assert len(released_entries) == 1 and released_entries[0] in n_entries, 'canonical removal lost/replaced surviving reference'
                    reused_entries = phases['reused']['state']['res01']['matches']['entries']
                    assert len(reused_entries) == 2 and released_entries[0] in reused_entries, 'duplicate reuse replaced surviving reference'
                    assert all(entry[0] == trial['target_peer'] and entry[2] == n_entries[0][2] for entry in reused_entries), 'duplicate reuse canonical/peer drift'
                    fresh = [entry for entry in reused_entries if entry[1] != released_entries[0][1]]
                    assert len(fresh) == 1 and fresh[0][1] not in references, 'duplicate reuse did not allocate a fresh reference'
            else:
                count = lambda state: sum(1 + len(row[4]) for row in state['res01']['names']['names'])
                assert count(phases['released']['state']) == count(phases['N']['state']) - 1
    death = report['outcomes']['global_names']['death']
    assert death['actor_dead_pidfd'] is True and death['actor_proc_absent'] is True
    assert death['wrapper_exit'] in (128 + signal.SIGKILL, -signal.SIGKILL) and death['reused'] is True
    assert 0 <= death['reallocation_ms'] <= 1000
    death_joins = {phase: validate_observation(death[phase]) for phase in ('before', 'after', 'repeated', 'reuse')}
    assert state_key(death['after']['state']) == state_key(death['repeated']['state']), 'death cleanup not idempotent'
    victim = death['actual_actor_pid']
    assert not any(row['identity']['pid'] == victim for row in death['after']['active'])
    assert len(death['before']['active']) == len(death['after']['active']) + 1
    victims = [row for row in death_joins['before'].values() if row['identity']['pid'] == victim]
    assert len(victims) == 1, 'missing actual death victim identity'
    victim_join = victims[0]
    victim_peer = victim_join['peer']
    assert victim_join['identity']['uid'] == 1101 and victim_join['unique'] is not None, 'death victim UID/registration drift'
    before, after, reused = (death[phase]['state'] for phase in ('before', 'after', 'reuse'))
    before_names = before['res01']['names']['names']
    assert any(row[1] == victim_peer for row in before_names) and any(any(item[0] == victim_peer for item in row[4]) for row in before_names)
    before_matches = before['res01']['matches']['entries']
    assert any(row[0] == victim_peer for row in before_matches)
    owned = [row for row in before_names if row[1] == victim_peer]
    victim_matches = [row for row in before_matches if row[0] == victim_peer]
    assert len(owned) == len(victim_matches) == 1 and owned[0][4] == [], 'death fixture owned-name/match allocation drift'
    survivors = {peer: row for peer, row in death_joins['before'].items() if peer != victim_peer}
    assert death_joins['after'] == death_joins['repeated'] == survivors, 'death cleanup replaced survivor identity/credit'
    assert after['res01']['limits']['global'] == {metric: count - victim_join['counts'][metric]
        for metric, count in before['res01']['limits']['global'].items()}, 'death credit not retired'
    remaining_names = [[name, owner, unique, flags, [row for row in queue if row[0] != victim_peer]]
        for name, owner, unique, flags, queue in before_names if owner != victim_peer]
    remaining_matches = [row for row in before_matches if row[0] != victim_peer]
    match_order = lambda rows: sorted(rows, key=lambda row: (row[0], row[1]))
    assert after['res01']['names']['names'] == remaining_names, 'death owned/queued name cleanup drift'
    assert after['res01']['names']['uniques'] == [row for row in before['res01']['names']['uniques'] if row[1] != victim_peer], 'death unique allocation retained'
    assert sorted(after['res01']['names']['pid_names']) == sorted(row for row in before['res01']['names']['pid_names'] if row[0] != victim_peer), 'death reverse association cleanup drift'
    assert match_order(after['res01']['matches']['entries']) == match_order(remaining_matches), 'death match cleanup drift'
    assert sorted(after['names']) == sorted(name for name in before['names'] if name not in (victim_join['unique'], owned[0][0])), 'death public name cleanup drift'
    assert sorted(after['peers'], key=lambda row: row['peer']) == sorted((row for row in before['peers'] if row['peer'] != victim_peer), key=lambda row: row['peer']), 'death surviving Router state drift'
    assert after['policy'] == before['policy'], 'death policy drift'
    reuse_joins = death_joins['reuse']
    assert len(reuse_joins) == len(survivors) + 1 and survivors.keys() <= reuse_joins.keys(), 'missing death replacement admission'
    assert all(reuse_joins[peer] == row for peer, row in survivors.items()), 'death reuse replaced survivor identity/credit'
    replacement = next(row for peer, row in reuse_joins.items() if peer not in survivors)
    new_peer, new_unique = replacement['peer'], replacement['unique']
    assert replacement['identity']['uid'] == 1101 and new_unique is not None, 'death replacement UID/registration drift'
    assert replacement['identity']['pid'] not in {row['identity']['pid'] for row in death_joins['before'].values()}, 'death reuse resurrected actor PID'
    assert new_peer not in death_joins['before'] and new_unique not in {row['unique'] for row in death_joins['before'].values()}, 'death reuse resurrected peer/unique'
    assert reused['res01']['limits']['global'] == {metric: count + replacement['counts'][metric]
        for metric, count in after['res01']['limits']['global'].items()}, 'death reallocation credit drift'
    expected_names = remaining_names + [[owned[0][0], new_peer, new_unique, 0, []]]
    assert reused['res01']['names']['names'] == sorted(expected_names, key=lambda row: row[0]), 'death reuse missing name or unexpected queue/ownership'
    assert reused['res01']['names']['uniques'] == sorted(after['res01']['names']['uniques'] + [[new_unique, new_peer]]), 'death reuse unique allocation drift'
    assert sorted(reused['res01']['names']['pid_names']) == sorted(after['res01']['names']['pid_names'] + [[new_peer, new_unique], [new_peer, owned[0][0]]]), 'death reuse reverse association drift'
    assert sorted(reused['names']) == sorted(after['names'] + [new_unique, owned[0][0]]), 'death reuse public name allocation drift'
    new_matches = [row for row in reused['res01']['matches']['entries'] if row[0] == new_peer]
    assert len(new_matches) == 1 and new_matches[0][2] == victim_matches[0][2], 'death reuse missing/different canonical match'
    assert new_matches[0][1] not in {row[1] for row in before_matches}, 'death reuse resurrected match reference'
    assert match_order(reused['res01']['matches']['entries']) == match_order(remaining_matches + new_matches), 'death reuse surviving match drift'
    assert sorted((row for row in reused['peers'] if row['peer'] != new_peer), key=lambda row: row['peer']) == sorted(after['peers'], key=lambda row: row['peer']), 'death reuse surviving Router state drift'
    assert reused['policy'] == after['policy'], 'death reuse policy drift'
    validate_teardown(report)


def validate_teardown(report):
    assert report['quit_flushed'] is True and report['socket_removed'] is True
    assert not report['shutdown_errors'] and report['actors_shutdown']
    killed = []
    for daemon, row in [(True, report['daemon_shutdown'])] + [(False, row) for row in report['actors_shutdown']]:
        identity = row['identity']
        assert all(type(identity[key]) is int and identity[key] > 0
                   for key in ('pid', 'starttime_ticks', 'wrapper_pid', 'wrapper_starttime_ticks', 'pgid'))
        assert row['pid'] == identity['wrapper_pid'] == identity['pgid'], 'owned wrapper/group identity drift'
        assert row['method'] == 'eof' and row['process_group_retired'] is True
        assert all(row[key] is True for key in ('pid_absent', 'actor_pid_absent', 'group_absent'))
        before = row['before_containment']
        assert all(before[key] is True for key in ('stdin_closed', 'wrapper_waited', 'pid_absent', 'actor_pid_absent', 'group_absent'))
        assert before['timed_out'] is False and not before['errors'], 'natural retirement unproven before containment'
        assert before['wrapper_returncode'] == row['returncode']
        if row['returncode'] == 0:
            continue
        assert not daemon and row['returncode'] in (128 + signal.SIGKILL, -signal.SIGKILL)
        death = report['outcomes']['global_names']['death']
        operation = death['operation']
        assert operation in report['deliberate_deaths'] and len(report['deliberate_deaths']) == 1
        assert operation['identity'] == identity and operation['wrapper_pid'] == row['pid'], 'SIGKILL exception belongs only to recorded victim incarnation'
        assert operation['signal'] == signal.SIGKILL and operation['method'] == 'pidfd_send_signal'
        assert operation['identity_checked'] is True and operation['signal_sent'] is True
        assert operation['actor_dead_pidfd'] is True and operation['actor_proc_absent'] is True
        assert death['actual_actor_pid'] == identity['pid'] and death['signal'] == signal.SIGKILL
        assert death['actor_dead_pidfd'] is True and death['actor_proc_absent'] is True
        assert death['wrapper_exit'] == operation['wrapper_exit'] == row['returncode']
        victims = [actor['identity'] for actor in death['before']['active'] if actor['identity']['pid'] == identity['pid']]
        current = operation['current_identity']
        validate_identity(current, identity['uid'])
        fields = ('pid', 'uid', 'gid', 'starttime_ticks', 'wrapper_pid', 'wrapper_starttime_ticks', 'pgid')
        assert len(victims) == 1 and all(victims[0][key] == identity[key] == current[key] for key in fields), 'death trial/current/retirement identity drift'
        killed.append(identity)
    if report.get('deliberate_deaths'):
        assert len(killed) == len(report['deliberate_deaths']) == 1, 'recorded death missing exact victim teardown'


def main(candidate, original, evidence):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security/res01'
    assert evidence.stat().st_uid == 0 and stat.S_IMODE(evidence.stat().st_mode) == 0o755
    # Import the unchanged transports only after verifying their historical bytes.
    import hashlib
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    for name, pin in WORKLOAD['original_pins'].items():
        assert digest(original / name) == pin, ('pinned fixture drift', name)
    guard_source((original / 'daemon.exs').read_text())
    sys.path.insert(0, str(original))
    spec = importlib.util.spec_from_file_location('res01_original_run', original / 'run.py')
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['version'] == 1 and manifest['not_a_release']
    artifact_modes = {}
    for name, pin in manifest['files'].items():
        artifact_modes[name] = validate_artifact_mode(manifest['file_modes'][name], (candidate / name).lstat())
        assert digest(candidate / name) == pin
    policy = evidence / 'policy.exs'
    overlay = ('original = elem(Code.eval_file(' + json.dumps(str(original / 'policy.exs')) + '), 0)\n'
               'original ++ [%{action: :own, effect: :allow, match: %{uid: 1100, name: {:prefix, "org.foundation.Res01A"}}}]\n')
    policy.write_text(overlay)
    policy.chmod(0o600)
    assert policy.stat().st_uid == 0 and stat.S_IMODE(policy.stat().st_mode) == 0o600
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(HERE / 'launcher.exs'), WORKLOAD['socket'], str(policy)]
    os.environ['RES01_ORIGINAL'] = str(original)
    report = dict(version=1, selected=SELECTED, workload=WORKLOAD, candidate=manifest,
                  candidate_manifest_sha256=digest(candidate / 'candidate.json'),
                  original_pins=WORKLOAD['original_pins'], artifact_modes=artifact_modes,
                  fixture_pins={p.name: digest(p) for p in HERE.iterdir() if p.is_file()},
                  policy=dict(original_bytes=(original / 'policy.exs').read_text(), overlay_bytes=overlay,
                              original_sha256=digest(original / 'policy.exs'), overlay_sha256=digest(policy)),
                  outcomes={name: dict(status='blocked', reason='not_executed', trials={}) for name in SELECTED},
                  commands=[command], actors=[], receipts=[], snapshots=[], result='failed',
                  limitations=WORKLOAD['scope'], shutdown_errors=[], actors_shutdown=[], deliberate_deaths=[])
    daemon, actors, active = None, [], []
    shutdown_identities = {}
    started = time.monotonic()
    authority_deadline = started + 60
    checkpoint_deferred = False

    def persist():
        statuses = [row['status'] for row in report['outcomes'].values()]
        report['counts'] = dict(selected=8, executed=sum(row in ('passed', 'failed') for row in statuses),
                                passed=statuses.count('passed'), failed=statuses.count('failed'),
                                blocked=sum(row in ('blocked', 'running') for row in statuses), skipped=0)
        if checkpoint_deferred:
            return
        temporary = evidence / 'qualification.json.tmp'
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        temporary.replace(evidence / 'qualification.json')

    def remaining(deadline=None):
        timeout = min(authority_deadline, deadline if deadline is not None else authority_deadline) - time.monotonic()
        assert timeout > 0, 'fixture/held phase deadline'
        return timeout

    def accepted_identity(channel, identity, current_credentials=False):
        actor = Path('/proc', str(identity['pid']), 'stat').read_text().rsplit(') ', 1)[1].split()
        wrapper = Path('/proc', str(channel.process.pid), 'stat').read_text().rsplit(') ', 1)[1].split()
        assert int(actor[2]) == int(wrapper[2]) == channel.process.pid, 'actor escaped owned group'
        if current_credentials:
            status = Path('/proc', str(identity['pid']), 'status').read_text()
            uid = next(line for line in status.splitlines() if line.startswith('Uid:'))
            gid = next(line for line in status.splitlines() if line.startswith('Gid:'))
            current = dict(identity, uid=int(uid.split()[1]), gid=int(gid.split()[1]), proc_status=status)
            validate_identity(current, identity['uid'])
            identity = current
        return dict(identity, starttime_ticks=int(actor[19]), wrapper_pid=channel.process.pid,
                    wrapper_starttime_ticks=int(wrapper[19]), pgid=int(wrapper[2]))

    def stop(channel):
        result = stop_channel(channel, shutdown_identities.get(channel))
        result['process_group_retired'] = result['group_absent']
        return result

    def request(actor, **values):
        deadline = values.get('deadline', min(authority_deadline, time.monotonic() + 1))
        actor['channel'].begin(**values)
        response = actor['channel'].read(timeout=remaining(deadline))
        report['receipts'].append(dict(identity=actor['identity'], request=values, response=response))
        persist()
        assert response['ok'], response
        return response['result']

    def call(actor, member, signature='', body=(), deadline=None):
        values = dict(op='call', member=member, signature=signature, body=body)
        if deadline is not None:
            # Ordinary Client commands do not accept a transport deadline keyword.
            actor['channel'].begin(**values)
            response = actor['channel'].read(timeout=remaining(deadline))
            report['receipts'].append(dict(identity=actor['identity'], request=values, response=response))
            persist()
            assert response['ok'], response
            return response['result']
        return request(actor, **values)

    def spawn(uid):
        user = {1100: 'foundationA', 1101: 'foundationB'}[uid]
        launch = ['runuser', '-u', user, '--', 'python3', str(HERE / 'actor.py'), WORKLOAD['socket'], str(original)]
        channel = legacy.Actor(launch, evidence / f'actor-{len(actors)}.log')
        actors.append(channel)
        report['commands'].append(launch)
        identity = channel.read(timeout=remaining())
        identity['proc_status'] = Path(f"/proc/{identity['pid']}/status").read_text()
        validate_identity(identity, uid)
        shutdown_identities[channel] = accepted_identity(channel, identity)
        actor = dict(channel=channel, identity=identity, unique=None)
        report['actors'].append(identity)
        persist()
        return actor

    def public_active():
        return [dict(identity=dict(row['identity'], **{key: shutdown_identities[row['channel']][key]
                     for key in ('starttime_ticks', 'wrapper_pid', 'wrapper_starttime_ticks', 'pgid')}),
                     unique=row['unique']) for row in active]

    def settle(deadline=None):
        deadline = min(deadline or authority_deadline, time.monotonic() + 1, authority_deadline)
        prior = None
        for _ in range(128):
            daemon.process.stdin.write(b'snapshot\n')
            daemon.process.stdin.flush()
            state = daemon.read(timeout=remaining(deadline))
            report['snapshots'].append(state)
            persist()
            try:
                joins = validate_state(state, public_active(), report.get('authorities'))
            except (AssertionError, KeyError, TypeError) as error:
                report.setdefault('unsettled', []).append(repr(error))
                prior = None
                continue
            if prior is not None and state_key(prior) == state_key(state):
                return dict(state=state, active=public_active(), joins=joins)
            prior = state
        raise AssertionError('bounded settled readbacks exhausted')

    def capture(trial, phase, deadline=None):
        observation = settle(deadline)
        trial['phases'][phase] = observation
        if phase == 'reused':
            pid = trial['reuse_actor_pid']
            trial['reused_peer'] = next(row['peer'] for row in observation['joins'] if row['identity']['pid'] == pid)
        persist()
        return observation['state']

    def probe(trial, deadline=None):
        probe_start = time.monotonic()
        deadline = min(deadline or authority_deadline, probe_start + 1)
        owner = reply(call(observer, 'GetNameOwner', 's', ['org.foundation.Observer'], deadline), [observer['unique']])
        bus_id = reply(call(observer, 'GetId', deadline=deadline))
        assert bus_id['body'] == report['bus_id']
        trial['probes'].append(dict(elapsed_ms=(time.monotonic() - probe_start) * 1000, owner=owner, bus_id=bus_id))
        assert time.monotonic() < deadline

    def hold(actor, deadline):
        result = request(actor, op='hold', deadline=deadline)
        if result['admitted']:
            actor['unique'] = None
            active.append(actor)
        return result

    def finish(actor, deadline):
        result = request(actor, op='complete', deadline=deadline)
        actor['unique'] = reply(result)['body'][0]
        return result

    def connect(actor):
        nonlocal checkpoint_deferred
        previous_checkpoint_deferred = checkpoint_deferred
        checkpoint_deferred = True
        try:
            deadline = min(time.monotonic() + 0.4, authority_deadline)
            result = hold(actor, deadline)
            assert result['admitted'], result
            finish(actor, deadline)
            return result
        finally:
            checkpoint_deferred = previous_checkpoint_deferred
            persist()

    def close(actor, trial):
        result = request(actor, op='close')
        trial['socket_closes'].append(result)
        if actor in active:
            active.remove(actor)
        actor['unique'] = None

    def new_trial(dimension, name):
        trial = dict(phases={}, probes=[], allocations=[], socket_closes=[])
        report['outcomes'][dimension]['trials'][name] = trial
        before = capture(trial, 'before')
        assert state_key(before) == state_key(baseline), 'case did not start at observer baseline'
        probe(trial)
        return trial

    def boundary(trial, dimension, target, operation, deadline=None):
        probe(trial, deadline)
        n = capture(trial, 'N', deadline)
        peer = next((row['peer'] for row in n['res01']['children']
                     if row['credentials']['pid'] == target['identity']['pid']), None)
        trial.update(target_peer=peer, target_uid=target['identity']['uid'], reuse_actor_pid=target['identity']['pid'],
                     headroom=headroom(n, peer, target['identity']['uid'], dimension))
        trial['rejection'] = operation()
        probe(trial, deadline)
        rejected = capture(trial, 'rejected', deadline)
        assert state_key(n) == state_key(rejected), 'rejection mutated durable authority state'

    def retired(trial):
        capture(trial, 'baseline')
        probe(trial)
        capture(trial, 'baseline_repeated')
        assert all(state_key(trial['phases'][phase]['state']) == state_key(baseline) for phase in ('baseline', 'baseline_repeated'))

    persist()
    try:
        daemon = legacy.Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        report['provenance'] = daemon.read(timeout=remaining())
        provenance = report['provenance']
        assert provenance['event'] == 'res01_provenance' and provenance['original_sha256'] == WORKLOAD['original_pins']['daemon.exs']
        assert provenance['defaults_replaced'] == 2 and provenance['snapshot_insertions'] == 1
        report['ready'] = daemon.read(timeout=remaining())
        ready = report['ready']
        validate_provenance(provenance, ready)
        assert ready['event'] == 'ready' and int(ready['pid']) == daemon.process.pid
        shutdown_identities[daemon] = accepted_identity(daemon, dict(pid=daemon.process.pid, uid=0, gid=0))
        assert ready['identity']['uid'] == 0 and ready['configuration']['resource_limits'] == provenance['profile']
        assert ready['configuration']['auth_limits'] == {'timeout_ms': 1500, 'idle_timeout_ms': 500}
        assert ready['configuration']['socket_path'] == WORKLOAD['socket'] and ready['configuration']['profile'] == 'system'
        assert ready['configuration']['cluster'] is False and ready['configuration']['capability_restrictions'] is False
        listener = Path(WORKLOAD['socket']).lstat()
        assert stat.S_ISSOCK(listener.st_mode) and listener.st_uid == 0 and stat.S_IMODE(listener.st_mode) == 0o666
        report['listener'] = dict(inode=listener.st_ino, device=listener.st_dev, uid=listener.st_uid, mode=stat.S_IMODE(listener.st_mode))
        report['policy']['evaluated'] = ready['policy']
        observer = spawn(1100)
        connect(observer)
        reply(call(observer, 'RequestName', 'su', ['org.foundation.Observer', 0]), [1])
        report['bus_id'] = reply(call(observer, 'GetId'))['body']
        baseline = settle()['state']
        assert baseline['res01']['limits']['limits'] == provenance['profile'], 'initialized full profile drift'
        report['authorities'] = baseline['res01']['authorities']
        report['baseline'] = baseline

        def connections(dimension):
            for label in TRIALS[dimension]:
                trial = new_trial(dimension, label)
                if dimension == 'uid_connections':
                    uid = int(label)
                    additions = [spawn(uid) for _ in range(3 if uid == 1100 else 4)]
                    target, independent = spawn(uid), spawn(1101 if uid == 1100 else 1100)
                else:
                    additions = [spawn(uid) for uid in (1100, 1100, 1100, 1101, 1101)]
                    target, independent = spawn(1101), None
                for actor in additions:
                    trial['allocations'].append(dict(success=connect(actor)['admitted'], uid=actor['identity']['uid']))
                boundary(trial, dimension, target, lambda: hold(target, min(time.monotonic() + 0.4, authority_deadline)))
                assert trial['rejection']['closed'] and not trial['rejection']['admitted']
                if independent:
                    connect(independent)
                    trial['independent'] = settle()
                    close(independent, trial)
                close(additions.pop(), trial)
                capture(trial, 'released')
                reallocate_start = time.monotonic()
                connect(target)
                trial['reallocation_ms'] = (time.monotonic() - reallocate_start) * 1000
                capture(trial, 'reused')
                for actor in additions + [target]:
                    close(actor, trial)
                retired(trial)

        def authenticating(dimension):
            nonlocal checkpoint_deferred
            for label in TRIALS[dimension]:
                trial = new_trial(dimension, label)
                uids = [int(label)] * 2 if dimension == 'uid_authenticating' else [1100, 1100, 1101]
                holders = [spawn(uid) for uid in uids]
                target = spawn(int(label) if dimension == 'uid_authenticating' else 1101)
                independent = spawn(1101 if label == '1100' else 1100) if dimension == 'uid_authenticating' else None
                # Preserve observations in memory and respect the enclosing checkpoint scope.
                previous_checkpoint_deferred = checkpoint_deferred
                checkpoint_deferred = True
                try:
                    held_start = time.monotonic()
                    deadline = min(held_start + 0.4, authority_deadline)
                    for actor in holders:
                        trial['allocations'].append(dict(success=hold(actor, deadline)['admitted'], uid=actor['identity']['uid']))
                        assert trial['allocations'][-1]['success']
                    boundary(trial, dimension, target, lambda: hold(target, deadline), deadline)
                    assert not trial['rejection']['admitted'] and trial['rejection']['closed']
                    if independent:
                        assert hold(independent, deadline)['admitted']
                        trial['independent'] = settle(deadline)
                        finish(independent, deadline)
                    before_complete = settle(deadline)['state']['res01']['limits']['global']
                    finish(holders[0], deadline)
                    released = capture(trial, 'released', deadline)['res01']['limits']['global']
                    trial['auth_completed'] = dict(connections_unchanged=before_complete['connections'] == released['connections'],
                                                   auth_delta=released['authenticating'] - before_complete['authenticating'])
                    if independent:
                        close(independent, trial)
                    reallocate_start = time.monotonic()
                    assert hold(target, deadline)['admitted']
                    trial['reallocation_ms'] = (time.monotonic() - reallocate_start) * 1000
                    capture(trial, 'reused', deadline)
                    probe(trial, deadline)
                    for actor in holders[1:] + [target]:
                        finish(actor, deadline)
                    completed = settle(deadline)
                    assert completed['state']['res01']['limits']['global']['authenticating'] == 0
                    trial['all_completed'] = completed
                    trial['held_elapsed_ms'] = (time.monotonic() - held_start) * 1000
                    assert trial['held_elapsed_ms'] <= 400
                finally:
                    checkpoint_deferred = previous_checkpoint_deferred
                    persist()
                for actor in holders + [target]:
                    close(actor, trial)
                retired(trial)

        def names(dimension):
            for label in TRIALS[dimension]:
                trial = new_trial(dimension, label)
                if dimension == 'peer_names':
                    target = observer if label == '1100' else spawn(1101)
                    if target is not observer:
                        connect(target)
                    prefix = 'org.foundation.Res01A.Peer' if label == '1100' else 'org.foundation.Service.Res01.Peer'
                    acquired = [prefix + str(index) for index in range(1 if target is observer else 2)]
                    for name in acquired:
                        reply(call(target, 'RequestName', 'su', [name, 0]), [1])
                        trial['allocations'].append(dict(success=True, name=name))
                    rejected_name = prefix + 'Rejected'
                    boundary(trial, dimension, target, lambda: call(target, 'RequestName', 'su', [rejected_name, 0]))
                    reply(trial['rejection'], error=LIMIT)
                    reply(call(target, 'ReleaseName', 's', [acquired.pop()]), [1])
                    capture(trial, 'released')
                    reallocate_start = time.monotonic()
                    reply(call(target, 'RequestName', 'su', [rejected_name, 0]), [1])
                    trial['reallocation_ms'] = (time.monotonic() - reallocate_start) * 1000
                    capture(trial, 'reused')
                    for name in acquired + [rejected_name]:
                        reply(call(target, 'ReleaseName', 's', [name]), [1])
                    if target is not observer:
                        close(target, trial)
                    else:
                        witness = spawn(1100)
                        connect(witness)
                        close(witness, trial)
                else:
                    owner, target = spawn(1101), spawn(1101)
                    connect(owner)
                    connect(target)
                    added, queued, rejected_name = 'org.foundation.Res01A.Global', 'org.foundation.Service.Res01.Queue', 'org.foundation.Service.Res01.Fresh'
                    for actor, name, result in [(observer, added, 1), (owner, queued, 1), (target, queued, 2)]:
                        reply(call(actor, 'RequestName', 'su', [name, 0]), [result])
                        trial['allocations'].append(dict(success=True, name=name, result=result))
                    boundary(trial, dimension, target, lambda: call(target, 'RequestName', 'su', [rejected_name, 0]))
                    reply(trial['rejection'], error=LIMIT)
                    reply(call(target, 'ReleaseName', 's', [queued]), [1])
                    capture(trial, 'released')
                    reallocate_start = time.monotonic()
                    reply(call(target, 'RequestName', 'su', [rejected_name, 0]), [1])
                    trial['reallocation_ms'] = (time.monotonic() - reallocate_start) * 1000
                    capture(trial, 'reused')
                    # Real actor death owns both an association and a queue plus a match.
                    reply(call(observer, 'ReleaseName', 's', [added]), [1])
                    reply(call(target, 'RequestName', 'su', [queued, 0]), [2])
                    rule = "type='signal',member='Res01Death'"
                    reply(call(target, 'AddMatch', 's', [rule]), [])
                    death_before = settle()
                    actor_pid = target['identity']['pid']
                    operation = dict(identity=shutdown_identities[target['channel']], wrapper_pid=target['channel'].process.pid,
                                     signal=signal.SIGKILL, method='pidfd_send_signal', identity_checked=False,
                                     signal_sent=False, actor_dead_pidfd=False, actor_proc_absent=False, wrapper_exit=None)
                    report['deliberate_deaths'].append(operation)
                    pidfd = os.pidfd_open(actor_pid)
                    try:
                        current = accepted_identity(target['channel'], target['identity'], current_credentials=True)
                        operation['current_identity'] = current
                        victims = [row['identity'] for row in death_before['active'] if row['identity']['pid'] == actor_pid]
                        fields = ('pid', 'uid', 'gid', 'starttime_ticks', 'wrapper_pid', 'wrapper_starttime_ticks', 'pgid')
                        assert len(victims) == 1 and all(current[key] == operation['identity'][key] == victims[0][key]
                                                       for key in fields), 'death victim credential/incarnation drift'
                        operation['identity_checked'] = True
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        operation['signal_sent'] = True
                        assert select.select([pidfd], [], [], remaining(time.monotonic() + 1))[0], 'actor death deadline'
                        operation['actor_dead_pidfd'] = True
                    finally:
                        os.close(pidfd)
                    active.remove(target)
                    target['channel'].process.wait(timeout=remaining(time.monotonic() + 1))
                    assert not Path(f'/proc/{actor_pid}').exists(), 'actual actor process retained'
                    operation.update(actor_proc_absent=True, wrapper_exit=target['channel'].process.returncode)
                    death_after = settle()
                    death_repeated = settle()
                    probe(trial)
                    assert len(death_after['state']['res01']['matches']['entries']) == 0
                    assert rejected_name not in death_after['state']['names']
                    death_reallocate_start = time.monotonic()
                    replacement = spawn(1101)
                    connect(replacement)
                    reply(call(replacement, 'RequestName', 'su', [rejected_name, 0]), [1])
                    reply(call(replacement, 'AddMatch', 's', [rule]), [])
                    death_reused = settle()
                    probe(trial)
                    report['outcomes'][dimension]['death'] = dict(before=death_before, after=death_after,
                        repeated=death_repeated, reuse=death_reused, reused=True, actor_dead_pidfd=True, actor_proc_absent=True,
                        wrapper_exit=target['channel'].process.returncode, actual_actor_pid=actor_pid, signal=signal.SIGKILL, operation=operation,
                        reallocation_ms=(time.monotonic() - death_reallocate_start) * 1000)
                    for actor in [owner, replacement]:
                        close(actor, trial)
                retired(trial)

        def matches(dimension):
            for label in TRIALS[dimension]:
                trial = new_trial(dimension, label)
                target = spawn(1101 if label in ('1101', 'mixed') else 1100)
                connect(target)
                other = spawn(1100) if dimension == 'global_matches' else None
                if other:
                    connect(other)
                rules = ["type='signal',member='Res01One'", "type='signal',member='Res01Two'", "type='signal',member='Res01Three'"]
                if label == 'duplicate':
                    rules[1] = "member='Res01One',type='signal'"
                    rules[2] = rules[0]
                allocation = [(other, rules[0]), (other, rules[1]), (target, rules[0])] if other else [(target, rules[0]), (target, rules[1])]
                for actor, rule in allocation:
                    reply(call(actor, 'AddMatch', 's', [rule]), [])
                    trial['allocations'].append(dict(success=True, rule=rule, uid=actor['identity']['uid']))
                rejected_rule = rules[1] if other else rules[2]
                boundary(trial, dimension, target, lambda: call(target, 'AddMatch', 's', [rejected_rule]))
                reply(trial['rejection'], error=LIMIT)
                remove_actor, remove_rule = allocation.pop(0)
                before_entries = trial['phases']['rejected']['state']['res01']['matches']['entries']
                reply(call(remove_actor, 'RemoveMatch', 's', [remove_rule]), [])
                released = capture(trial, 'released')['res01']['matches']['entries']
                assert len(released) == len(before_entries) - 1
                assert all(entry in before_entries for entry in released), 'RemoveMatch changed surviving references'
                if label == 'duplicate':
                    assert len(released) == 1 and released[0][2] == before_entries[0][2]
                reallocate_start = time.monotonic()
                reply(call(target, 'AddMatch', 's', [rejected_rule]), [])
                trial['reallocation_ms'] = (time.monotonic() - reallocate_start) * 1000
                capture(trial, 'reused')
                for actor, rule in allocation + [(target, rejected_rule)]:
                    reply(call(actor, 'RemoveMatch', 's', [rule]), [])
                for actor in [target] + ([other] if other else []):
                    close(actor, trial)
                retired(trial)

        actions = dict(uid_connections=connections, global_connections=connections,
                       uid_authenticating=authenticating, global_authenticating=authenticating,
                       peer_names=names, global_names=names, peer_matches=matches, global_matches=matches)
        for dimension in SELECTED:
            report['outcomes'][dimension]['status'] = 'running'
            persist()
            try:
                # Keep full observations; write once at the existing status checkpoint.
                previous_checkpoint_deferred = checkpoint_deferred
                checkpoint_deferred = True
                try:
                    actions[dimension](dimension)
                finally:
                    checkpoint_deferred = previous_checkpoint_deferred
            except Exception as error:
                report['outcomes'][dimension].update(status='failed', reason=repr(error))
                persist()
                raise
            report['outcomes'][dimension]['status'] = 'passed'
            persist()
        report['final_baseline'] = settle()
        assert state_key(report['final_baseline']['state']) == state_key(baseline)
    except Exception as error:
        report['failure'] = repr(error)
        raise
    finally:
        for channel in actors:
            try:
                report['actors_shutdown'].append(stop(channel))
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
                report['daemon_shutdown'] = stop(daemon)
                report['socket_removed'] = not Path(WORKLOAD['socket']).exists()
            except Exception as error:
                report['shutdown_errors'].append(repr(error))
        report['authority_elapsed_ms'] = (time.monotonic() - started) * 1000
        persist()
    try:
        complete(report)
        assert report['authority_elapsed_ms'] <= 60_000
    except Exception as error:
        report['acceptance_failure'] = repr(error)
        persist()
        raise
    report['result'] = 'passed_selected_scope'
    persist()
    print(json.dumps(dict(result=report['result'], counts=report['counts'], limitations=report['limitations'])))


if __name__ == '__main__':
    main(*(Path(argument) for argument in sys.argv[1:]))
