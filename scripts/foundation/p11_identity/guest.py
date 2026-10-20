"""Three private packaged identity rows; UID/GID transitions are guest-only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import runpy
import select
import signal
import socket
import subprocess
import struct
import sys
import time

BASE = Path('/run/osbus-p11-identity')
CASES = ['matching', 'uid-mismatch', 'gid-mismatch']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait(pid, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed:
            return os.waitstatus_to_exitcode(status)
        select.select([], [], [], min(0.02, max(0, deadline-time.monotonic())))
    raise AssertionError('child exit deadline exceeded')


def run_case(case, release, helpers, report):
    account = pwd.getpwnam('messagebus')
    directory = BASE/case
    directory.mkdir(mode=0o755)
    temporary = directory/'tmp'
    temporary.mkdir(mode=0o700)
    uid = 0 if case == 'gid-mismatch' else account.pw_uid
    gid = account.pw_gid
    expected_uids = [uid, uid, uid, uid]
    expected_gids = [gid, gid, gid, gid]
    if case == 'uid-mismatch':
        expected_uids[0] = 0
    if case == 'gid-mismatch':
        expected_gids[0] = 0
    os.chown(temporary, uid, gid)
    config = directory/'bus.conf'
    address = str(directory/'bus')
    config.write_text('<busconfig><type>system</type><user>'+str(uid)+'</user>'
                      '<listen>unix:path='+address+'</listen><policy context="default">'
                      '<allow user="root"/><allow user="messagebus"/><allow own="*"/>'
                      '<allow send_destination="*"/><allow receive_sender="*"/>'
                      '</policy></busconfig>')
    config.chmod(0o644)
    row = {'id': case, 'config_sha256': digest(config), 'expected': 'ready' if case == 'matching' else 'denied'}
    row['launch_boundary'] = 'reconstructed packaged final native startup; IDs injected before erlexec, not unchanged foreground chain acceptance'
    child, reaped = None, False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as manager, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
        manager.bind(address)
        manager.listen()
        manager.settimeout(2)
        os.chmod(address, 0o666)
        before = os.stat(address)
        notify.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        notification = str(directory/'notify')
        notify.bind(notification)
        os.chmod(notification, 0o666)
        env = {key: value for key, value in os.environ.items() if not key.startswith(
            ('LISTEN_', 'OS_BUS_', 'DBUS_', 'GAO_', 'PHX_', 'RELEASE_'))}
        env.update(OS_BUS_CONFIG=str(config), OS_BUS_INHERITED_LISTENER='true',
                   NOTIFY_SOCKET=notification, RELEASE_TMP=str(temporary), ERL_FLAGS='+S 2:2',
                   ERL_CRASH_DUMP_SECONDS='0', PATH='/run/current-system/sw/bin')
        prepared = subprocess.run([str(release/'bin/os_bus'), 'start'],
                                  env={**env, 'ELIXIR_CLI_DRY_RUN': '1'},
                                  capture_output=True, text=True, timeout=10)
        assert prepared.returncode == 0, 'packaged dry-run preparation failed'
        line = prepared.stdout.strip()
        assert '\n' not in line and line and not any(char in line for char in "\"'\\\t"), 'ambiguous dry-run arguments'
        argv = line.split(' ')
        assert all(argv) and ' '.join(argv) == line, 'non-roundtrippable dry-run arguments'
        bindir = release/('erts-'+manifest_erts(release))/'bin'
        assert Path(argv[0]).resolve() == (bindir/'erl').resolve() and '-name' not in argv and '-sname' not in argv, 'unexpected packaged final command'
        assert '-setcookie' in argv and '-config' in argv and '-boot' in argv and '-args_file' in argv
        row['packaged_dry_run_argv'] = helpers['redact_argv'](argv)
        row['packaged_erl_sha256'] = digest(bindir/'erl')
        row['erlexec_sha256'] = digest(bindir/'erlexec')
        env.update(ROOTDIR=str(release), BINDIR=str(bindir), EMU='beam', PROGNAME='erl',
                   RELEASE_ROOT=str(release), RELEASE_SYS_CONFIG=argv[argv.index('-config')+1],
                   RELEASE_NAME='os_bus', RELEASE_VSN=(release/'releases/start_erl.data').read_text().split()[1],
                   RELEASE_DISTRIBUTION='none', RELEASE_COMMAND='start')
        row['prepared_release_environment'] = {key: env[key] for key in ['ROOTDIR', 'BINDIR', 'EMU', 'PROGNAME', 'RELEASE_ROOT', 'RELEASE_SYS_CONFIG', 'RELEASE_DISTRIBUTION']}
        try:
            with (BASE/'evidence'/(case+'.log')).open('wb') as log:
                child = os.fork()
                if child == 0:
                    try:
                        # Only the disposable root test wrapper changes IDs, before exec.
                        assert Path('/etc/osbus-p11-identity-guest').read_text().strip() == 'isolated-vm'
                        os.dup2(log.fileno(), 1)
                        os.dup2(log.fileno(), 2)
                        os.dup2(manager.fileno(), 3, inheritable=True)
                        os.set_inheritable(3, True)
                        os.setgroups([])
                        os.setresgid(0 if case == 'gid-mismatch' else gid, gid, gid)
                        os.setresuid(0 if case == 'uid-mismatch' else uid, uid, uid)
                        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
                        sample = {'pid': os.getpid(), 'starttime': helpers['stat_starttime'](Path('/proc/self/stat').read_text()),
                                  'uid': [int(value) for value in status['Uid'].split()],
                                  'gid': [int(value) for value in status['Gid'].split()]}
                        sample['config_readable'] = config.read_text().startswith('<busconfig>')
                        (temporary/'wrapper.json').write_text(json.dumps(sample)+'\n')
                        env.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='1', LISTEN_FDNAMES='dbus')
                        os.chdir(temporary)
                        os.execve(str(bindir/'erlexec'), [str(bindir/'erlexec'), *argv[1:]], env)
                    except BaseException as error:
                        print(repr(error), file=sys.stderr, flush=True)
                        os._exit(125)
                row['pid'] = child
                deadline = time.monotonic()+20
                notification_data = None
                code = None
                while time.monotonic() < deadline:
                    if not row.get('native_identity_witness'):
                        try:
                            if Path(os.readlink(Path('/proc', str(child), 'exe'))).name == 'beam.smp':
                                row['native_identity_witness'] = helpers['identity'](child)
                                witness = row['native_identity_witness']
                                assert witness['uid'] == expected_uids and witness['gid'] == expected_gids, 'native erlexec changed injected identities'
                        except FileNotFoundError:
                            pass
                    if select.select([notify], [], [], 0.05)[0]:
                        data, controls, flags, _ = notify.recvmsg(128, socket.CMSG_SPACE(12))
                        assert data == b'READY=1' and flags == 0, (data, flags)
                        credentials = [struct.unpack('3i', value) for level, kind, value in controls
                                       if (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)]
                        assert len(credentials) == 1 and credentials[0][0] == child, credentials
                        row['readiness_credentials'] = credentials
                        notification_data = data.decode()
                        row['beam'] = helpers['identity'](child)
                        assert Path(row['beam']['exe']).name == 'beam.smp'
                        row['health'] = helpers['health'](address, 1000)
                        os.kill(child, signal.SIGTERM)
                        code = wait(child, 8)
                        reaped = True
                        assert code == 0, code
                        break
                    observed, status = os.waitpid(child, os.WNOHANG)
                    if observed:
                        code = os.waitstatus_to_exitcode(status)
                        reaped = True
                        break
                assert reaped, 'startup observation deadline exceeded'
                row['wrapper'] = json.loads((temporary/'wrapper.json').read_text())
                assert row['wrapper']['uid'] == expected_uids and row['wrapper']['gid'] == expected_gids, row['wrapper']
                assert row['wrapper']['config_readable']
                if 'beam' in row:
                    assert row['beam']['uid'] == expected_uids and row['beam']['gid'] == expected_gids, row['beam']
                if row.get('native_identity_witness'):
                    witness = row['native_identity_witness']
                    assert witness['uid'] == expected_uids and witness['gid'] == expected_gids, 'native erlexec changed injected identities'
                notify.setblocking(False)
                if notification_data is None:
                    try:
                        notification_data = notify.recv(128).decode()
                    except BlockingIOError:
                        pass
                row.update(notification=notification_data, exit_status=code, child_reaped=True)
                after = os.stat(address)
                assert (before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    client.connect(address)
                    accepted, _ = manager.accept()
                    accepted.close()
                row['manager_survived'] = True
                if case == 'matching':
                    assert notification_data == 'READY=1' and 'health' in row
                    row['result'] = 'passed'
                else:
                    denied = notification_data is None and code != 0 and 'health' not in row
                    denied = denied and code != 125 and row.get('native_identity_witness') is not None
                    row['expected_refusal_observed'] = 'daemon_identity_mismatch' in (BASE/'evidence'/(case+'.log')).read_text()
                    denied = denied and row['expected_refusal_observed']
                    row['result'] = 'passed' if denied else 'failed'
                    row['meaningful_red'] = notification_data == 'READY=1' and 'health' in row
                    row['reason'] = ('identity mismatch denied before readiness/authority' if denied else
                                     'identity mismatch accepted with READY and independent usable authority' if row['meaningful_red'] else
                                     'startup did not reach authority or the expected identity refusal')
            return row
        finally:
            if child is not None and not reaped:
                os.kill(child, signal.SIGKILL)
                wait(child, 8)
            report['cleanup'].append({'id': case, 'pid': child, 'reaped': child is None or not Path('/proc', str(child)).exists()})


def manifest_erts(release):
    return (release/'releases/start_erl.data').read_text().split()[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frozen', type=Path)
    parser.add_argument('--lifecycle', type=Path, required=True)
    parser.add_argument('--transport', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path('/etc/osbus-p11-identity-guest').read_text().strip() == 'isolated-vm', 'guest-only identity effects refused'
    assert not BASE.exists(), 'preserve previous guest evidence'
    BASE.mkdir(mode=0o755)
    (BASE/'evidence').mkdir(mode=0o755)
    sys.path.insert(0, str(args.transport))
    helpers = runpy.run_path(str(args.lifecycle/'guest.py'))
    manifest = json.loads((args.frozen/'release.json').read_text())
    report = {'selected': CASES, 'rows': [], 'cleanup': [], 'manifest_sha256': digest(args.frozen/'release.json'),
              'source_sha256': manifest['source_sha256'], 'guest_sha256': digest(Path(__file__)),
              'lifecycle_guest_sha256': digest(args.lifecycle/'guest.py'), 'transport_sha256': digest(args.transport/'transport.py'),
              'scope': 'private inherited listener; no activation/canonical/P12 acceptance'}
    report['launch_boundary'] = 'reconstructed packaged final native startup with guest-only identity injection; no unchanged-chain claim'
    report['utilities'] = {name: {'path': str(Path('/run/current-system/sw/bin', name).resolve()),
                                'sha256': digest(Path('/run/current-system/sw/bin', name))}
                           for name in ['readlink', 'dirname', 'cut', 'cat', 'sed', 'grep', 'date', 'dd', 'od', 'awk']}
    try:
        helpers['verify_inventory'](args.frozen/'release', manifest['inventory'])
        report['package_before_verified'] = True
        for case in CASES:
            try:
                row = run_case(case, args.frozen/'release', helpers, report)
                report['rows'].append(row)
                if row.get('reason') == 'startup did not reach authority or the expected identity refusal':
                    break
            except BaseException as error:
                report['rows'].append({'id': case, 'result': 'failed', 'error': repr(error)})
                if str(error) == 'native erlexec changed injected identities':
                    break
        helpers['verify_inventory'](args.frozen/'release', manifest['inventory'])
        report['package_after_verified'] = True
    finally:
        report['counts'] = {'selected': 3, 'executed': len(report['rows']),
                            'passed': sum(row['result'] == 'passed' for row in report['rows']),
                            'failed': sum(row['result'] == 'failed' for row in report['rows']),
                            'blocked': 3-len(report['rows']), 'skipped': 0}
        report['result'] = 'passed' if report['counts']['passed'] == 3 else 'failed'
        (BASE/'evidence/report.json').write_text(json.dumps(report, indent=2)+'\n')
        for path in (BASE/'evidence').iterdir():
            path.chmod(0o644)
        print(json.dumps(report['counts']), flush=True)
    assert report['result'] == 'passed', 'release identity rejection regression failed'


if __name__ == '__main__':
    main()
