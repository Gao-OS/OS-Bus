"""Additional kill witnesses; inherited UID validator remains the state oracle."""
import copy


def validate_candidate_binding(manifest, actual_manifest, expected_manifest, expected_source):
    for value in (actual_manifest, expected_manifest, expected_source):
        assert isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    assert actual_manifest == expected_manifest and manifest['source_sha256'] == expected_source
    assert actual_manifest != 'a27888106012b209b8941a4c7e5b9611764c7ceaa3ff2e27ebe9c753783a6c77'
    assert expected_source != 'f5dfe03ced34c9b24e69b780588156330a74d2ee025a07dcf2dd0e5d395eab92'


def validate_kill_selection(report):
    required = {'uid_names': ['owner_down_promotes', 'queued_down_reclaims'],
                'uid_matches': ['match_down_reclaims']}
    selected = report['selected']
    assert selected in (['uid_names'], ['uid_matches'], ['uid_names', 'uid_matches'])
    assert set(report['outcomes']) == set(selected)
    labels = []
    for key in selected:
        row = report['outcomes'][key]
        assert row['status'] == 'passed' and row['abrupt_kill_labels'] == required[key]
        labels.extend(required[key])
    assert [record['label'] for record in report['abrupt_kills']] == labels
    observed = set()
    for record in report['abrupt_kills']:
        event = record['event']
        identity = (event['peer'], event['down']['monitor'])
        assert identity not in observed, 'duplicate kill witness'
        observed.add(identity)
        validate_abrupt(event, record['before'], record['after'], record['join'], record['elapsed_ms'])


def canonical_ledger(ledger):
    value = copy.deepcopy(ledger)
    for key in ('names', 'uniques', 'pid_names', 'entries'):
        if key in value:
            value[key] = sorted(value[key], key=lambda row: (row[0], str(row[1])))
    return value


def validate_abrupt(event, before, after, join, elapsed_ms):
    peer, unique, identity = join['peer'], join['unique'], join['identity']
    assert identity['uid'] == identity['gid'] == 1100
    assert event['event'] == 'uid_abrupt_peer_down'
    assert event['operation'] == 'Process.exit(peer, :kill)'
    assert event['peer'] == event['down']['peer'] == peer and event['unique'] == unique
    assert event['down']['reason'] == 'killed'
    assert event['down']['monitor'].startswith('#Reference<')
    assert event['explicit_cleanup_calls'] == []
    assert all(event['credentials'][key] == identity[key] for key in ('pid', 'uid', 'gid'))
    for elapsed in (event['daemon_elapsed_ms'], elapsed_ms):
        assert type(elapsed) in (int, float) and 0 <= elapsed <= 1000
    old, new = before['uid_authorities'], after['uid_authorities']
    assert new['authorities'] == old['authorities']
    assert any(row['peer'] == peer and row['name'] == unique for row in before['peers'])
    assert not any(row['peer'] == peer for row in after['peers'])
    assert new['children'] == [row for row in old['children'] if row['peer'] != peer]
    supervised = dict(old['supervised'])
    for key in ('active', 'specs', 'workers'):
        supervised[key] -= 1
    assert new['supervised'] == supervised
    account = copy.deepcopy(old['accounting'])
    admitted = account['peers'].pop(peer)
    assert admitted['uid'] == identity['uid'] and admitted['monitor'] == join['admission']
    assert new['accounting'] == account, 'automatic admission cleanup or survivor drift'
    limits = copy.deepcopy(old['limits'])
    counts = limits['peers'].pop(peer)
    assert counts['connections'] == 1 and all(n == 0 for k, n in counts.items() if k != 'connections')
    uid = str(identity['uid'])
    for key, count in counts.items():
        limits['global'][key] -= count
        limits['uids'][uid][key] -= count
    if not any(limits['uids'][uid].values()):
        del limits['uids'][uid]
    assert new['limits'] == limits, 'automatic credit cleanup must be exact'
    for kind in ('names', 'matches'):
        ledger = copy.deepcopy(old[kind])
        cached = ledger['peers'].pop(peer, None)
        if cached is not None:
            assert cached['uid'] == identity['uid'] and cached['admission'] == join['admission']
            removed = (sum(int(row[1] == peer) + sum(q[0] == peer for q in row[4])
                           for row in ledger['names']) if kind == 'names'
                       else sum(row[0] == peer for row in ledger['entries']))
            assert cached['count'] == removed > 0
            remaining = ledger['uid_counts'][uid] - removed
            assert remaining >= 0
            if remaining:
                ledger['uid_counts'][uid] = remaining
            else:
                del ledger['uid_counts'][uid]
        if kind == 'matches':
            ledger['entries'] = [row for row in ledger['entries'] if row[0] != peer]
        else:
            names = []
            for name, owner, owner_unique, flags, queue in ledger['names']:
                if owner == peer:
                    if queue:
                        promoted, rest = queue[0], queue[1:]
                        names.append([name, promoted[0], promoted[1], promoted[2], rest])
                else:
                    names.append([name, owner, owner_unique, flags, [q for q in queue if q[0] != peer]])
            ledger['names'] = names
            ledger['uniques'] = [row for row in ledger['uniques'] if row != [unique, peer]]
            ledger['pid_names'] = [row for row in ledger['pid_names'] if row[0] != peer]
        assert canonical_ledger(new[kind]) == canonical_ledger(ledger), (kind, 'automatic ledger cleanup or survivor drift')
