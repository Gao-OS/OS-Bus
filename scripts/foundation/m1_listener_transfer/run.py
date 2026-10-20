"""One bounded guest transfer-failure subcase; parent owns all execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
from cleanup import stop_channel
from contract import SELECTED, state_key, validate_eof, validate_probe, validate_selection, validate_shutdown, validate_transfer

HERE = Path(__file__).resolve().parent
SOCKET = '/run/osbus-security/listener-transfer/bus'
MANIFEST_SHA = '372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'
SOURCE_SHA = 'efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'
BUS = 'org.freedesktop.DBus'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(pid, uid):
    text = Path('/proc', str(pid), 'status').read_text()
    for key in ('Uid:', 'Gid:'):
        assert [int(x) for x in next(line for line in text.splitlines() if line.startswith(key)).split()[1:]] == [uid] * 4
    return text


def main(candidate, original, evidence, selection):
    assert selection == 'transfer_failure'
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security/listener-transfer'
    assert evidence.stat().st_uid == 0 and stat.S_IMODE(evidence.stat().st_mode) == 0o755
    assert not Path(SOCKET).exists() and not (evidence / 'qualification.json').exists()
    started = time.monotonic()
    deadline = started + 60
    report = dict(version=1,fixture='standalone-listener-transfer',selected=SELECTED,
        workload=json.loads((HERE/'workload.json').read_text()),
        outcomes={SELECTED[0]:dict(status='blocked',reason='not_executed')},
        bounds=dict(authority_seconds=60,guest_seconds=120,host_seconds=900,cleanup_seconds=5,
                    healthy_probe_ms=1000,transfer_ms=1000),commands=[],actors=[],receipts=[],
        snapshots=[],probes=[],actors_shutdown=[],shutdown_errors=[],result='failed',
        product_qualified=False,readiness='L0',limitations='FAIL-02 transfer branch only; whole FAIL-02 and SYS-02 remain unqualified')
    daemon = None
    actors = []

    def persist():
        statuses = [row['status'] for row in report['outcomes'].values()]
        report['counts'] = dict(selected=1,executed=sum(s in ('passed','failed') for s in statuses),
            passed=statuses.count('passed'),failed=statuses.count('failed'),
            blocked=sum(s in ('blocked','running') for s in statuses),skipped=0)
        temporary = evidence / 'qualification.json.tmp'
        temporary.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        temporary.replace(evidence / 'qualification.json')

    def remaining(bound=None):
        seconds = min(deadline,bound if bound is not None else deadline) - time.monotonic()
        assert seconds > 0, 'listener transfer authority deadline'
        return seconds

    def request(worker, **command):
        worker['channel'].begin(**command)
        response = worker['channel'].read(timeout=remaining(time.monotonic()+1))
        report['receipts'].append(dict(identity=worker['identity'],request=command,response=response))
        assert response['ok'],response
        return response['result']

    def call(worker, member, signature='', body=()):
        worker['serial'] += 1
        result = request(worker,op='call',member=member,signature=signature,body=body)
        assert result['type'] == 2 and result['error'] is None and result['sender'] == BUS
        assert result['reply_serial'] == worker['serial']
        return result

    def snapshot():
        daemon.process.stdin.write(b'snapshot\n');daemon.process.stdin.flush()
        state = daemon.read(timeout=remaining(time.monotonic()+1))
        assert state['event'] == 'snapshot'
        report['snapshots'].append(state)
        return state

    def settle(expected=None):
        bound = time.monotonic()+1
        previous = None
        for _ in range(128):
            remaining(bound)
            state = snapshot()
            key = state_key(state)
            if key == previous and (expected is None or key == state_key(expected)):
                assert time.monotonic() <= bound
                return state
            previous = key
        raise AssertionError('listener transfer exact baseline not reached')

    persist()
    try:
        missing = [tool for tool in ('elixir','python3','runuser') if shutil.which(tool) is None]
        assert not missing, ('BLOCKED_ENV missing required tools',missing)
        pins = json.loads((HERE/'INHERITED_INPUTS.json').read_text())['inputs']
        security = {Path(pin['frozen']).name:pin['sha256'] for pin in pins.values()
                    if '/inherited/security/' in pin['frozen']}
        assert set(security) == {'run.py','actor.py','workload.json','daemon.exs','state.ex','policy.exs','capture.py'}
        assert {p.name for p in original.iterdir() if p.is_file()} == set(security)
        for name,pin in security.items():
            assert not (original/name).is_symlink() and digest(original/name) == pin
        sys.path.insert(0,str(original))
        spec = importlib.util.spec_from_file_location('listener_original_transport',original/'run.py')
        legacy = importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        manifest = json.loads((candidate/'candidate.json').read_text())
        assert digest(candidate/'candidate.json') == MANIFEST_SHA
        assert manifest['source_sha256'] == SOURCE_SHA
        assert os.environ['LISTENER_TRANSFER_CANDIDATE_MANIFEST_SHA256'] == MANIFEST_SHA
        assert os.environ['LISTENER_TRANSFER_CANDIDATE_SOURCE_SHA256'] == SOURCE_SHA
        assert manifest['baseline'] == '7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4' and manifest['not_a_release'] is True
        assert (len(manifest['sources']),len(manifest['source_beams']),len(manifest['files'])) == (71,57,80)
        assert hashlib.sha256(json.dumps(manifest['sources'],sort_keys=True).encode()).hexdigest() == SOURCE_SHA
        for name,pin in manifest['files'].items():
            path=candidate/name;mode=manifest['file_modes'][name]
            assert not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
            assert digest(path) == pin and stat.S_IMODE(path.stat().st_mode) == (0o555 if mode & 0o111 else 0o444)
        report.update(candidate=manifest,candidate_manifest_sha256=MANIFEST_SHA,original_pins=security,
            fixture_pins={str(p.relative_to(HERE)):digest(p) for p in HERE.rglob('*') if p.is_file()})
        policy = evidence/'policy.exs';shutil.copyfile(original/'policy.exs',policy);policy.chmod(0o600)
        report['policy']=dict(bytes=policy.read_text(),sha256=digest(policy),overlay=False)
        command=['elixir','--erl','+S 2:2']
        for path in sorted((candidate/'lib').glob('*/ebin')):command += ['-pa',str(path)]
        command += [str(HERE/'launcher.exs'),SOCKET,str(policy)]
        os.environ['LISTENER_TRANSFER_ORIGINAL']=str(original)
        report['commands'].append(command)
        daemon=legacy.Channel(command,evidence/'daemon.log','FIXTURE ')
        report['provenance']=daemon.read(timeout=remaining(time.monotonic()+10))
        assert report['provenance']['event'] == 'listener_transfer_provenance'
        report['daemon']=daemon.read(timeout=remaining(time.monotonic()+10))
        assert report['daemon']['event'] == 'ready' and int(report['daemon']['pid']) == daemon.process.pid
        assert report['daemon']['identity']['uid'] == report['daemon']['identity']['gid'] == 0
        assert stat.S_ISSOCK(Path(SOCKET).stat().st_mode) and stat.S_IMODE(Path(SOCKET).stat().st_mode) == 0o666

        def spawn(uid,program,path):
            user={1100:'foundationA',1101:'foundationB'}[uid]
            command=['runuser','-u',user,'--','python3',str(program),path]
            worker=dict(channel=legacy.Actor(command,evidence/f'actor-{len(actors)}.log'),identity=None,serial=1)
            actors.append(worker);report['commands'].append(command)
            worker['identity']=worker['channel'].read(timeout=remaining(time.monotonic()+1))
            assert worker['identity']['uid'] == worker['identity']['gid'] == uid
            report['actors'].append(dict(identity=worker['identity'],proc_status=identity(worker['identity']['pid'],uid)))
            return worker

        observer=spawn(1100,original/'actor.py',SOCKET)
        reply=request(observer,op='register')
        assert reply['type'] == 2 and reply['reply_serial'] == 1 and reply['body'][0].startswith(':')
        observer['unique']=reply['body'][0]
        assert call(observer,'RequestName','su',['org.foundation.Observer',0])['body'] == [1]
        assert call(observer,'AddMatch','s',["type='signal'"])['body'] == []
        bus_id=call(observer,'GetId')['body'];report['bus_id']=bus_id
        baseline=settle()
        peers=[peer for peer in baseline['peers'] if peer['name'] == observer['unique']]
        assert len(peers) == 1
        observer['peer']=peers[0]['peer']
        observed={key:peers[0]['credentials'][key] for key in ('pid','uid','gid')}
        assert observed == observer['identity']
        observer_public={key:observer[key] for key in ('identity','unique','peer')}
        report['observer']=observer_public

        def healthy(phase):
            began=time.monotonic()
            owner=call(observer,'GetNameOwner','s',['org.foundation.Observer'])
            bus=call(observer,'GetId')
            probe=dict(identity=observer['identity'],unique=observer['unique'],owner=owner,bus=bus,
                       elapsed_ms=(time.monotonic()-began)*1000,phase=phase)
            validate_probe(probe,observer_public,bus_id);report['probes'].append(probe)

        healthy('before')
        baseline=settle(expected=baseline);report['baseline']=baseline
        daemon.process.stdin.write(b'prepare_listener_transfer\n');daemon.process.stdin.flush()
        prepared=daemon.read(timeout=remaining(time.monotonic()+1))
        assert prepared['event'] == 'listener_transfer_prepared' and state_key(prepared['before']) == state_key(baseline)
        assert prepared['path'] == str(evidence/'transfer');report['prepared']=prepared
        client=spawn(1101,HERE/'client.py',prepared['path'])
        outcome=report['outcomes'][SELECTED[0]];outcome.update(status='running');persist()
        bound=time.monotonic()+1
        client['channel'].begin(op='transfer')
        daemon.process.stdin.write(b'listener_transfer_failure\n');daemon.process.stdin.flush()
        # Real wire calls while the root fault response is still outstanding.
        healthy('command_outstanding')
        event=daemon.read(timeout=remaining(bound))
        report['transfer']=event
        response=client['channel'].read(timeout=remaining(bound))
        report['receipts'].append(dict(identity=client['identity'],request={'op':'transfer'},response=response))
        assert response['ok'],response
        report['client_eof']=response['result'];validate_eof(response['result'])
        identity(client['identity']['pid'],1101)
        validate_transfer(event,client['identity'],observer_public)
        assert state_key(event['before']) == state_key(baseline)
        healthy('after');report['final_baseline']=settle(expected=baseline)
        outcome.update(status='passed',reason='passed_transfer_branch_only')
    except Exception as error:
        report['failure']=repr(error)
        outcome=report['outcomes'][SELECTED[0]]
        if outcome['status'] == 'running':outcome.update(status='failed',reason=repr(error))
        else:outcome.update(status='blocked',reason=repr(error))
    finally:
        for worker in actors:
            try:
                shutdown=stop_channel(worker['channel'],worker['identity'])
                report['actors_shutdown'].append(shutdown)
            except Exception as error:report['shutdown_errors'].append(repr(error))
        if daemon is not None:
            try:
                daemon.process.stdin.write(b'quit\n');daemon.process.stdin.flush();report['quit_flushed']=True
                report['daemon_shutdown']=stop_channel(daemon,dict(pid=daemon.process.pid,uid=0,gid=0))
            except Exception as error:report['shutdown_errors'].append(repr(error))
        report['socket_removed']=not Path(SOCKET).exists()
        report['fault_path_removed']=not (evidence/'transfer').exists()
        report['authority_elapsed_ms']=(time.monotonic()-started)*1000
        persist()
    try:
        validate_selection(report)
        assert len(report['actors_shutdown']) == len(report['actors']) == 2
        assert not report['shutdown_errors'] and report['quit_flushed'] is True
        for shutdown in report['actors_shutdown']+[report['daemon_shutdown']]:validate_shutdown(shutdown)
        assert report['socket_removed'] is report['fault_path_removed'] is True
        assert report['authority_elapsed_ms'] <= 60_000
    except Exception as error:
        report['acceptance_failure']=repr(error)
        if report['outcomes'][SELECTED[0]]['status'] == 'passed':
            report['outcomes'][SELECTED[0]].update(status='failed',reason=repr(error))
        persist();raise
    report['result']='passed_transfer_branch_only';persist()
    print(json.dumps(dict(result=report['result'],counts=report['counts'],readiness='L0',product_qualified=False)))


if __name__ == '__main__':
    assert len(sys.argv) == 5
    main(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4])
