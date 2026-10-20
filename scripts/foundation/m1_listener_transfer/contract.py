"""Pure acceptance predicates for one listener transfer-failure subcase."""
import json

BUS = 'org.freedesktop.DBus'
SELECTED = ['FAIL-02/transfer-failure']


def state_key(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':'))


def validate_transfer(event, client, observer):
    assert event['event'] == 'listener_transfer_failure'
    assert event['operation'] == 'GaoBus.Listener.transfer_ownership/2'
    assert event['error'] == ['error', ['invalid', 'not_owner']]
    assert event['marker_hex'] == '2a' and event['explicit_peer_cleanup'] == []
    assert event['owner_before'] == event['holder'] != event['caller']
    assert len({event[key] for key in ('peer', 'holder', 'caller')}) == 3
    assert all(event[key].startswith('#PID<') for key in ('peer', 'holder', 'caller'))
    assert event['incomplete'] == dict(phase='waiting_socket', native_socket=None,
        unique=None, credentials=None, registry=[], router_member=False, accounting_member=False)
    for key, peer, reason in [('down', event['peer'], 'shutdown'), ('holder_down', event['holder'], 'normal')]:
        assert event[key]['peer'] == peer and event[key]['reason'] == reason
        assert event[key]['monitor'].startswith('#Reference<')
    assert event['down']['monitor'] != event['holder_down']['monitor']
    assert isinstance(event['fd'], int) and event['fd'] >= 0
    assert event['fd_before'].startswith('socket:[') and event['fd_before'].endswith(']')
    assert event['fd_after'] == ['error', 'enoent']
    assert event['socket_after'] == ['error', 'closed'] and event['fault_path_removed'] is True
    assert 0 <= event['daemon_elapsed_ms'] <= 1000
    assert client['pid'] > 1 and client['uid'] == client['gid'] == 1101
    assert observer['identity']['pid'] > 1 and observer['identity']['uid'] == observer['identity']['gid'] == 1100
    assert client['pid'] != observer['identity']['pid']
    assert {key:event['accepted_credentials'][key] for key in ('pid','uid','gid')} == client
    before, after = event['before'], event['after']
    assert state_key(before) == state_key(after), 'authority/resource/incumbent baseline drift'
    assert before['event'] == 'snapshot' and before['router'].startswith('#PID<')
    authority = before['authority']
    assert set(authority) == {'authorities','children','core_children','accounting','name_state',
                              'name_tables','match_state','match_entries','capabilities'}
    assert set(authority['authorities']) == {'GaoBus.Supervisor','GaoBus.Listener','GaoBus.Router',
        'GaoBus.Limits','GaoBus.NameRegistry','GaoBus.MatchRules','GaoBus.Policy','GaoBus.PeerSupervisor'}
    assert all(pid.startswith('#PID<') for pid in authority['authorities'].values())
    assert before['router'] == authority['authorities']['GaoBus.Router']
    children = [child for child in authority['children'] if child['peer'] == observer['peer']]
    assert len(children) == len(authority['children']) == 1
    assert children[0]['phase'] == 'connected' and children[0]['unique'] == observer['unique']
    assert {key:children[0]['credentials'][key] for key in ('pid','uid','gid')} == observer['identity']
    admission = authority['accounting']['peers'][observer['peer']]
    assert admission['uid'] == 1100 and admission['monitor'].startswith('#Reference<')
    assert before['usage']['reservations'] == 0 and before['usage']['global']['authenticating'] == 0
    assert before['incumbent']['inode'] > 0
    assert str(event['fd']) not in before['native_fds']
    assert event['fd_before'] not in before['native_fds'].values()
    peers = [peer for peer in before['peers'] if peer['peer'] == observer['peer']]
    assert len(peers) == 1
    assert peers[0]['name'] == observer['unique'] and observer['unique'].startswith(':')
    assert {key:peers[0]['credentials'][key] for key in ('pid','uid','gid')} == observer['identity']
    assert 'org.foundation.Observer' in before['names']
    assert all(peer['peer'] != event['peer'] for peer in before['peers'])


def validate_eof(result):
    assert result['closed'] is True and result['method'] == 'eof'
    assert result['sent_hex'] == '2a' and result['response_hex'] == ''
    assert 0 <= result['elapsed_ms'] <= 1000


def validate_probe(probe, observer, bus_id):
    assert probe['identity'] == observer['identity'] and probe['unique'] == observer['unique']
    assert 0 <= probe['elapsed_ms'] <= 1000
    for key, body in [('owner',[observer['unique']]), ('bus',bus_id)]:
        reply = probe[key]
        assert reply['type'] == 2 and reply['error'] is None
        assert reply['sender'] == BUS and isinstance(reply['reply_serial'], int)
        assert reply['reply_serial'] > 1 and reply['body'] == body and body
    assert probe['bus']['reply_serial'] == probe['owner']['reply_serial'] + 1


def validate_selection(report):
    assert report['selected'] == SELECTED and set(report['outcomes']) == set(SELECTED)
    assert report['outcomes'][SELECTED[0]]['status'] == 'passed'
    assert report['counts'] == dict(selected=1,executed=1,passed=1,failed=0,blocked=0,skipped=0)


def validate_shutdown(shutdown):
    assert shutdown['method'] == 'eof' and shutdown['returncode'] == 0
    assert shutdown['pid_absent'] is shutdown['actor_pid_absent'] is shutdown['group_absent'] is True
    before = shutdown['before_containment']
    assert before['stdin_closed'] is before['wrapper_waited'] is True
    assert before['wrapper_returncode'] == 0 and before['timed_out'] is False
    assert before['pid_absent'] is before['actor_pid_absent'] is before['group_absent'] is True
    assert before['errors'] == []
