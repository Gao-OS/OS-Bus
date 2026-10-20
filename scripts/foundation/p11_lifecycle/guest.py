"""Five bounded packaged-release lifecycle rows; effects require a disposable VM marker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'scripts/foundation/p08_sustained'))
SELECTED = ['P11-PKG-%02d' % row for row in range(1, 6)]
BASE = Path('/run/osbus-p11')
WORK = BASE/'work'
SERVICE = 'osbus-p11.service'
SOCKET = 'osbus-p11.socket'
NEG_SERVICE = 'osbus-p11-negative.service'
NEG_SOCKET = 'osbus-p11-negative.socket'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def complete(rows):
    return [row['id'] for row in rows] == SELECTED and all(row['result'] == 'passed' for row in rows)


def assert_bootstrap_refusal(properties, journal):
    assert properties['ActiveState'] == 'failed' and properties['MainPID'] == '0' and properties['ActiveEnterTimestampMonotonic'] == '0', properties
    assert properties['ExecMainStatus'] == '1' and 'invalid_inherited_environment' in journal, 'negative row did not reach the intended named-listener refusal'


def stat_starttime(text):
    return int(text[text.rfind(')')+2:].split()[19])


def redact_argv(argv):
    result, cookie = [], False
    for value in argv:
        result.append('<redacted>' if cookie else value)
        cookie = value == '-setcookie'
    return result


def identity(pid):
    root = Path('/proc')/str(pid)
    status = dict(line.split(':', 1) for line in (root/'status').read_text().splitlines() if ':' in line)
    environ = dict(item.split(b'=', 1) for item in (root/'environ').read_bytes().split(b'\0') if b'=' in item)
    keys = ['LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES', 'OS_BUS_CONFIG', 'OS_BUS_INHERITED_LISTENER', 'NOTIFY_SOCKET', 'RELEASE_DISTRIBUTION', 'RELEASE_TMP', 'PATH']
    return {'pid': pid, 'starttime': stat_starttime((root/'stat').read_text()),
            'exe': os.readlink(root/'exe'), 'argv': redact_argv([value.decode() for value in (root/'cmdline').read_bytes().split(b'\0') if value]),
            'uid': [int(value) for value in status['Uid'].split()], 'gid': [int(value) for value in status['Gid'].split()],
            'cgroup': (root/'cgroup').read_text(),
            'initial_environment': {key: environ[key.encode()].decode() for key in keys if key.encode() in environ}}


def gone(old):
    try:
        return stat_starttime(Path('/proc', str(old['pid']), 'stat').read_text()) != old['starttime']
    except FileNotFoundError:
        return True


def group_path(text):
    return Path('/sys/fs/cgroup')/next(line[3:] for line in text.splitlines() if line.startswith('0::')).lstrip('/')


def group_snapshot(path):
    if not path.exists():
        return {'path': str(path), 'pids': [], 'events': 'removed', 'monotonic': time.monotonic()}
    try:
        return {'path': str(path), 'pids': [int(pid) for pid in (path/'cgroup.procs').read_text().split()],
                'events': (path/'cgroup.events').read_text(), 'monotonic': time.monotonic()}
    except FileNotFoundError:
        assert not path.exists(), 'partially missing cgroup observation'
        return {'path': str(path), 'pids': [], 'events': 'removed', 'monotonic': time.monotonic()}


def vm_guard():
    assert os.geteuid() == 0 and Path('/etc/osbus-p11-guest').read_text().strip() == 'isolated-vm', 'guest-only runtime effects refused'


def control_guard():
    assert Path('/etc/osbus-p11-guest').read_text().strip() == 'isolated-vm'
    assert group_path(Path('/proc/self/cgroup').read_text()).name == SERVICE, 'control fixture outside private service cgroup'


def prestart():
    control_guard()
    sample = group_snapshot(group_path(Path('/proc/self/cgroup').read_text()))
    sample.update(control_pid=os.getpid(), starttime=stat_starttime(Path('/proc/self/stat').read_text()))
    assert sample['pids'] == [os.getpid()], ('old generation present before start', sample)
    with (WORK/'prestart.jsonl').open('a') as file:
        file.write(json.dumps(sample)+'\n')
        file.flush()
        os.fsync(file.fileno())


def sentinel():
    control_guard()
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        for fd in [int(path.name) for path in Path('/proc/self/fd').iterdir()]:
            if fd >= 3 and fd != writer:
                try:
                    os.close(fd)
                except OSError:
                    pass
        null = os.open('/dev/null', os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        if null != writer and null >= 3:
            os.close(null)
        sample = {'pid': os.getpid(), 'starttime': stat_starttime(Path('/proc/self/stat').read_text()),
                  'cgroup': Path('/proc/self/cgroup').read_text(), 'monotonic': time.monotonic(),
                  'kind': 'benign nonactivation manager control-process descendant'}
        (WORK/('sentinel-%d.json' % os.getpid())).write_text(json.dumps(sample)+'\n')
        os.write(writer, b'ready')
        os.close(writer)
        while True:
            signal.pause()
    os.close(writer)
    # The pipe is a completion barrier, not a timer-based synchronization.
    import select
    assert select.select([reader], [], [], 3)[0], 'sentinel record deadline'
    assert os.read(reader, 5) == b'ready', 'sentinel creation failed'
    assert select.select([reader], [], [], 3)[0] and os.read(reader, 1) == b'', 'sentinel retained its status pipe'
    os.close(reader)


def verify_inventory(root, expected):
    actual = {}
    for path in sorted(root.rglob('*')):
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            row = {'type': 'symlink', 'target': os.readlink(path)}
        elif path.is_file():
            row = {'type': 'file', 'sha256': digest(path), 'size': path.stat().st_size}
        elif path.is_dir():
            row = {'type': 'directory'}
        else:
            raise AssertionError(('special imported file', str(path)))
        name = str(path.relative_to(root))
        original = expected.get(name)
        assert original is not None, ('unrecorded imported path', name)
        # builtins.path records executable bits and normalizes immutable modes.
        normalized = 0o555 if original['type'] == 'directory' or original['mode'] & 0o111 else 0o444
        if original['type'] != 'symlink':
            assert mode == normalized, ('imported mode mismatch', name, mode, normalized)
        assert row == {key: value for key, value in original.items() if key != 'mode'}, ('imported bytes/link mismatch', name)
        actual[name] = row
    assert set(actual) == set(expected), 'imported paths missing'


class Health:
    def __init__(self, path, milliseconds):
        from transport import Client, call, read_string
        self.deadline = time.monotonic() + milliseconds/1000
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.arm()
        self.sock.connect(path)
        self.arm()
        self.sock.sendall(b'\0AUTH EXTERNAL '+str(os.getuid()).encode().hex().encode()+b'\r\n')
        line = self.line()
        assert re.fullmatch(rb'OK [0-9a-fA-F]{32}\r\n', line), line
        self.guid = line[3:-2].decode()
        self.arm()
        self.sock.sendall(b'BEGIN\r\n'+call('Hello', 1))
        self.reply = lambda serial: Client.reply(self, serial)
        self.receive = lambda: Client.receive(self)
        reply = self.reply(1)
        assert reply['type'] == 2 and not reply['fds'], reply
        self.name = read_string(reply['body'])
        assert self.name.startswith(':'), self.name
        self.arm()
        self.sock.sendall(call('GetId', 2))
        reply = self.reply(2)
        assert reply['type'] == 2 and not reply['fds'], reply
        self.bus_id = read_string(reply['body'])
        assert re.fullmatch('[0-9a-fA-F]{32}', self.bus_id), self.bus_id

    def arm(self):
        remaining = self.deadline-time.monotonic()
        assert remaining > 0, 'absolute health deadline exceeded'
        self.sock.settimeout(remaining)

    def line(self):
        result = b''
        while not result.endswith(b'\r\n'):
            self.arm()
            byte = self.sock.recv(1)
            assert byte and len(result) < 512, 'auth line EOF/limit'
            result += byte
        return result

    def read(self, length, fds):
        result = b''
        while len(result) < length:
            self.arm()
            data, controls, flags, _ = self.sock.recvmsg(length-len(result), 0)
            assert data and not controls and flags == 0, 'health frame EOF/unexpected rights'
            result += data
        return result


def health(path, milliseconds):
    started = time.monotonic()
    actor = Health.__new__(Health)
    try:
        actor.__init__(path, milliseconds)
        elapsed = (time.monotonic()-started)*1000
        assert elapsed <= milliseconds, 'health exceeded absolute deadline'
        return {'address': 'unix:path='+path, 'guid': actor.guid, 'unique_name': actor.name,
                'bus_id': actor.bus_id, 'elapsed_ms': elapsed, 'deadline_ms': milliseconds,
                'actor': 'independent raw EXTERNAL/Hello/GetId'}
    finally:
        if hasattr(actor, 'sock'):
            actor.sock.close()


def endpoint(path):
    info = os.stat(path)
    rows = [line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
    matches = [row for row in rows if len(row) >= 8 and row[7] == path and row[3] == '00010000']
    assert len(matches) == 1, ('manager listener missing/ambiguous', path, matches)
    inode = matches[0][6]
    manager_links = []
    for entry in Path('/proc/1/fd').iterdir():
        try:
            manager_links.append(os.readlink(entry))
        except FileNotFoundError:
            pass
    assert 'socket:['+inode+']' in manager_links, 'PID1 does not retain listener'
    return {'path': path, 'dev': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'kernel_inode': inode}


def listener_fds(pid, inode):
    result = []
    for entry in Path('/proc', str(pid), 'fd').iterdir():
        try:
            if os.readlink(entry) == 'socket:['+inode+']':
                flags = int(next(line.split()[1] for line in Path('/proc', str(pid), 'fdinfo', entry.name).read_text().splitlines() if line.startswith('flags:')), 8)
                result.append({'fd': int(entry.name), 'flags': flags})
        except FileNotFoundError:
            pass
    assert len(result) == 1 and result[0]['fd'] != 3 and result[0]['flags'] & 0o2000000, ('owned duplicate/CLOEXEC mismatch', result)
    return result


class Gate:
    def __init__(self, frozen, transport):
        self.frozen = frozen
        self.release = frozen/'release'
        self.manifest = json.loads((frozen/'release.json').read_text())
        self.workload = json.loads(Path(__file__).with_name('workload.json').read_text())
        assert self.workload['selected'] == SELECTED
        self.report = {'selected': SELECTED, 'rows': [], 'commands': [], 'cgroup_samples': [], 'limits': self.manifest['limits'],
                       'manifest_sha256': digest(frozen/'release.json'), 'workload_sha256': digest(Path(__file__).with_name('workload.json')),
                       'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        self.transport = transport
        sys.path.insert(0, str(transport))
        self.group = None
        self.generations = []

    def command(self, argv, check=True):
        started = time.monotonic()
        result = subprocess.run(argv, text=True, capture_output=True, timeout=30)
        self.report['commands'].append({'argv': argv, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                                        'monotonic_started': started, 'elapsed': time.monotonic()-started})
        if check:
            assert result.returncode == 0, (argv, result.returncode, result.stderr)
        return result

    def properties(self, unit):
        names = ['Type', 'NotifyAccess', 'MainPID', 'ControlGroup', 'ActiveState', 'SubState', 'Result', 'KillMode', 'NRestarts',
                 'TimeoutStartUSec', 'TimeoutStopUSec', 'Restart', 'ExecMainCode', 'ExecMainStatus', 'ActiveEnterTimestampMonotonic']
        result = self.command(['systemctl', 'show', unit, '--property='+','.join(names)])
        return dict(line.split('=', 1) for line in result.stdout.splitlines())

    def poll(self, predicate, seconds):
        deadline = time.monotonic()+seconds
        while True:
            value = predicate()
            if value:
                return value
            assert time.monotonic() < deadline, 'manager/process observation deadline exceeded'
            time.sleep(min(0.05, max(0, deadline-time.monotonic())))

    def snapshot(self):
        assert self.group is not None
        sample = group_snapshot(self.group)
        self.report['cgroup_samples'].append(sample)
        return sample

    def stopped(self, old):
        return gone(old) and not self.snapshot()['pids']

    def generation(self):
        properties = self.properties(SERVICE)
        assert properties['ActiveState'] == 'active' and properties['Type'] == 'notify' and properties['NotifyAccess'] == 'main', properties
        main = identity(int(properties['MainPID']))
        account = pwd.getpwnam('messagebus')
        assert Path(main['exe']).name == 'beam.smp', main
        assert main['uid'] == [account.pw_uid]*4 and main['gid'] == [account.pw_gid]*4, main
        assert properties['ControlGroup'] == '/'+str(group_path(main['cgroup']).relative_to('/sys/fs/cgroup')), main
        initial = main['initial_environment']
        # The packaged ERTS launcher prepends its bin and release bin to the unit PATH.
        expected_path = ':'.join([str(self.release/('erts-'+self.manifest['metadata']['erts'])/'bin'),
                                  str(self.release/'bin'), '/run/current-system/sw/bin'])
        assert initial.get('PATH') == expected_path, ('unpinned launcher PATH', initial)
        assert initial.get('LISTEN_PID') == str(main['pid']) and initial.get('LISTEN_FDS') == '1' and initial.get('LISTEN_FDNAMES') == 'dbus', initial
        self.group = group_path(main['cgroup'])
        retained = listener_fds(main['pid'], self.manager['kernel_inode'])
        result = {'main': main, 'unit': properties, 'listener_fds': retained,
                  'health': health(str(BASE/'bus'), self.workload['health_deadline_ms']), 'cgroup': self.snapshot()}
        self.generations.append(result)
        return result

    def install(self):
        account = pwd.getpwnam('messagebus')
        WORK.mkdir(mode=0o700)
        os.chown(WORK, account.pw_uid, account.pw_gid)
        python, runner = sys.executable, str(Path(__file__).resolve())
        tools = {}
        for name in ['readlink', 'dirname', 'cut', 'sed', 'grep', 'awk', 'dd', 'od', 'mktemp']:
            executable = Path('/run/current-system/sw/bin')/name
            assert executable.is_file() and os.access(executable, os.X_OK), ('required release utility missing', name)
            tools[name] = {'path': str(executable.resolve()), 'sha256': digest(executable)}
        self.report['launcher_utilities'] = tools
        for negative in [False, True]:
            stem = 'osbus-p11-negative' if negative else 'osbus-p11'
            path = str(BASE/('negative-bus' if negative else 'bus'))
            config_path = BASE/(stem+'.conf')
            config = '<busconfig><type>system</type><listen>unix:path='+path+'</listen><policy context="default"><allow user="root"/><allow user="messagebus"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>'
            config_path.write_text(config)
            config_path.chmod(0o644)
            socket_unit = '[Unit]\nDescription=Private OS-Bus P11 listener\n[Socket]\nListenStream='+path+'\nFileDescriptorName='+('wrong' if negative else 'dbus')+'\nAccept=no\nSocketMode=0666\n'
            controls = '' if negative else 'ExecStartPre='+python+' '+runner+' --prestart\nExecStartPost='+python+' '+runner+' --sentinel\n'
            service_unit = ('[Unit]\nDescription=Private packaged OS-Bus P11\nRequires='+stem+'.socket\nAfter='+stem+'.socket\n'
                            '[Service]\nType=notify\nNotifyAccess=main\nUser=messagebus\nGroup=messagebus\nWorkingDirectory='+str(WORK)+'\n'
                            'Environment=OS_BUS_CONFIG='+str(config_path)+'\nEnvironment=OS_BUS_INHERITED_LISTENER=true\nEnvironment="ERL_FLAGS=+S 2:2"\n'
                            'Environment=RELEASE_TMP='+str(WORK)+'\nEnvironment=ERL_CRASH_DUMP_SECONDS=0\nEnvironment=PATH=/run/current-system/sw/bin\n'
                            'UnsetEnvironment=PHX_SERVER SECRET_KEY_BASE DBUS_SOCKET_PATH DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS RELEASE_COOKIE\n'
                            +controls+'ExecStart='+str(self.release/'bin/os_bus')+' start\nKillMode=control-group\nTimeoutStartSec=15\nTimeoutStopSec=3\n'
                            'Restart='+('no' if negative else 'on-failure')+'\nRestartSec=1\nTasksMax=128\nMemoryMax=256M\n')
            for suffix, contents in [('socket', socket_unit), ('service', service_unit)]:
                target = Path('/run/systemd/system')/(stem+'.'+suffix)
                assert not target.exists(), 'preserve existing unit'
                target.write_text(contents)
                target.chmod(0o644)
                self.report.setdefault('units', {})[target.name] = {'sha256': digest(target), 'contents': contents}
            self.report.setdefault('configs', {})[config_path.name] = {'sha256': digest(config_path), 'contents': config}
        self.command(['systemctl', 'daemon-reload'])

    def row01(self):
        self.command(['systemctl', 'start', NEG_SOCKET])
        before = endpoint(str(BASE/'negative-bus'))
        refused = self.command(['systemctl', 'start', NEG_SERVICE], check=False)
        assert refused.returncode != 0, 'invalid named handoff became ready'
        props = self.properties(NEG_SERVICE)
        group = Path('/sys/fs/cgroup')/props['ControlGroup'].lstrip('/') if props['ControlGroup'] else Path('/sys/fs/cgroup/system.slice')/NEG_SERVICE
        journal = self.command(['journalctl', '-b', '--no-pager', '-u', NEG_SERVICE])
        assert_bootstrap_refusal(props, journal.stdout)
        sample = group_snapshot(group)
        assert not sample['pids'], sample
        assert endpoint(str(BASE/'negative-bus')) == before, 'negative manager endpoint changed'
        return {'refusal': props, 'empty_cgroup': sample, 'manager': before, 'bootstrap_refusal': 'invalid_inherited_environment', 'journal_sha256': hashlib.sha256(journal.stdout.encode()).hexdigest()}

    def row02(self):
        self.command(['systemctl', 'start', SOCKET])
        self.manager = endpoint(str(BASE/'bus'))
        self.command(['systemctl', 'start', SERVICE])
        first = self.generation()
        assert self.manager == endpoint(str(BASE/'bus'))
        return first

    def row03(self):
        assert self.manifest['schema'] == 1 and self.manifest['fixture'] == 'p11-packaged-lifecycle' and self.manifest['not_a_release'] is False
        verify_inventory(self.release, self.manifest['inventory'])
        assert digest(self.frozen/'build-record.json') == self.manifest['build_record_sha256']
        for path, name in [(Path(__file__), 'guest.py'), (Path(__file__).with_name('workload.json'), 'workload.json'), (self.transport/'transport.py', None)]:
            source = 'scripts/foundation/p11_lifecycle/'+name if name else 'scripts/foundation/p08_sustained/transport.py'
            assert digest(path) == self.manifest['sources'][source], ('fixture differs from capture', source)
        apps = [row['name'] for row in self.manifest['metadata']['apps']]
        assert not {'gao_bus_web', 'gao_config', 'gao_bus_test', 'phoenix', 'bandit', 'dns_cluster'}.intersection(apps)
        main = self.generations[-1]['main']
        assert not {'-name', '-sname'}.intersection(main['argv']), main
        pids = self.snapshot()['pids']
        for pid in pids:
            assert Path(identity(pid)['exe']).name != 'epmd', 'epmd actually running in service cgroup'
            sockets = set()
            for entry in Path('/proc', str(pid), 'fd').iterdir():
                try:
                    target = os.readlink(entry)
                    if target.startswith('socket:['):
                        sockets.add(target[8:-1])
                except FileNotFoundError:
                    pass
            for table in ['tcp', 'tcp6']:
                for line in Path('/proc', str(pid), 'net', table).read_text().splitlines()[1:]:
                    fields = line.split()
                    assert not (fields[3] == '0A' and fields[9] in sockets), ('actual service TCP listener', pid, line)
        return {'apps': apps, 'complete_inventory_verified': True, 'nix_mode_normalization_verified': True,
                'no_distribution_listener': True, 'cgroup_pids': pids, 'helper_binding': self.manifest['helper_binding']}

    def row04(self):
        old = self.generations[-1]
        self.command(['systemctl', 'stop', SERVICE])
        self.poll(lambda: self.stopped(old['main']), self.workload['stop_deadline_seconds'])
        stopped = self.properties(SERVICE)
        assert stopped['ActiveState'] == 'inactive'
        assert self.properties(SOCKET)['ActiveState'] == 'active'
        assert endpoint(str(BASE/'bus')) == self.manager
        # No connect while stopped: inspection cannot autoactivate this service.
        self.command(['systemctl', 'start', SERVICE])
        new = self.generation()
        assert new['main']['pid'] != old['main']['pid'] and gone(old['main'])
        assert new['health']['bus_id'] != old['health']['bus_id'] and new['health']['guid'] != old['health']['guid']
        assert endpoint(str(BASE/'bus')) == self.manager
        return {'stopped': stopped, 'new': new, 'manager_survived': True}

    def row05(self):
        old = self.generations[-1]
        assert old['unit']['KillMode'] == 'control-group' and old['unit']['Restart'] == 'on-failure'
        candidates = [json.loads(path.read_text()) for path in WORK.glob('sentinel-*.json')]
        sentinel_old = [row for row in candidates if not gone(row)]
        assert len(sentinel_old) == 1 and sentinel_old[0]['pid'] in self.snapshot()['pids'], sentinel_old
        sentinel_old = sentinel_old[0]
        sentinel_fds = {entry.name: os.readlink(entry) for entry in Path('/proc', str(sentinel_old['pid']), 'fd').iterdir()}
        assert set(sentinel_fds) == {'0', '1', '2'} and set(sentinel_fds.values()) == {'/dev/null'}, ('sentinel retained bus/control/status descriptor', sentinel_fds)
        sentinel_old['observed_fds'] = sentinel_fds
        pre_before = len((WORK/'prestart.jsonl').read_text().splitlines())
        self.command(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', SERVICE])
        def restarted():
            self.snapshot()
            props = self.properties(SERVICE)
            return props['ActiveState'] == 'active' and int(props['MainPID']) not in (0, old['main']['pid']) and gone(old['main']) and gone(sentinel_old)
        self.poll(restarted, self.workload['restart_deadline_seconds'])
        new = self.generation()
        pre = [json.loads(line) for line in (WORK/'prestart.jsonl').read_text().splitlines()]
        assert len(pre) == pre_before+1 and pre[-1]['pids'] == [pre[-1]['control_pid']], pre
        assert pre[-1]['monotonic'] > sentinel_old['monotonic'], pre[-1]
        assert int(new['unit']['NRestarts']) == int(old['unit']['NRestarts'])+1
        assert new['health']['bus_id'] != old['health']['bus_id'] and new['health']['guid'] != old['health']['guid']
        assert endpoint(str(BASE/'bus')) == self.manager
        self.command(['systemctl', 'stop', SERVICE])
        self.poll(lambda: self.stopped(new['main']), self.workload['stop_deadline_seconds'])
        assert all(gone(json.loads(path.read_text())) for path in WORK.glob('sentinel-*.json'))
        assert endpoint(str(BASE/'bus')) == self.manager
        self.command(['systemctl', 'stop', SOCKET])
        return {'old_main': old['main'], 'old_sentinel': sentinel_old, 'prestart': pre[-1], 'new': new,
                'final_cgroup': self.snapshot(), 'final_cleanup': True}

    def normal_bus(self):
        props = self.properties('dbus.service')
        assert props['ActiveState'] == 'active' and int(props['MainPID']) > 0, props
        pid = identity(int(props['MainPID']))
        path = '/run/dbus/system_bus_socket'
        info = os.stat(path)
        return {'main': {'pid': pid['pid'], 'starttime': pid['starttime'], 'exe': pid['exe']},
                'path': {'dev': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode)},
                'socket_unit': self.properties('dbus.socket')}

    def run(self):
        normal = None
        error = None
        try:
            normal = self.normal_bus()
            self.report['normal_bus_before'] = normal
            self.install()
            for row_id, method in zip(SELECTED, [self.row01, self.row02, self.row03, self.row04, self.row05]):
                started = time.monotonic()
                try:
                    details = method()
                    self.report['rows'].append({'id': row_id, 'result': 'passed', 'details': details, 'elapsed': time.monotonic()-started})
                except BaseException as failure:
                    self.report['rows'].append({'id': row_id, 'result': 'failed', 'error': repr(failure), 'elapsed': time.monotonic()-started})
                    raise
            assert complete(self.report['rows'])
        except BaseException as failure:
            error = failure
        finally:
            cleanup_errors = []
            for unit in [SERVICE, NEG_SERVICE, SOCKET, NEG_SOCKET]:
                try:
                    self.command(['systemctl', 'stop', unit])
                except BaseException as failure:
                    cleanup_errors.append(repr(failure))
            try:
                if self.group:
                    self.poll(lambda: not self.snapshot()['pids'], self.workload['stop_deadline_seconds'])
                assert all(gone(json.loads(path.read_text())) for path in WORK.glob('sentinel-*.json'))
                after = self.normal_bus()
                self.report['normal_bus_after'] = after
                assert normal is not None and after == normal, 'normal guest bus changed/unverified'
                verify_inventory(self.release, self.manifest['inventory'])
            except BaseException as failure:
                cleanup_errors.append(repr(failure))
            self.report['cleanup_errors'] = cleanup_errors
            self.report['cleanup_passed'] = not cleanup_errors
            try:
                self.command(['journalctl', '-b', '--no-pager', '-u', SERVICE, '-u', NEG_SERVICE, '-u', SOCKET, '-u', NEG_SOCKET], check=False)
            except BaseException as failure:
                cleanup_errors.append('journal capture: '+repr(failure))
                self.report['cleanup_passed'] = False
            self.report['generations'] = self.generations
            rows = self.report['rows']
            self.report['counts'] = {'selected': 5, 'executed': len(rows), 'passed': sum(row['result'] == 'passed' for row in rows),
                                     'failed': sum(row['result'] == 'failed' for row in rows), 'skipped': 0, 'blocked': 5-len(rows)}
            self.report['result'] = 'passed' if complete(rows) and not cleanup_errors and error is None else 'failed'
            evidence = BASE/'evidence'
            evidence.mkdir(mode=0o700, exist_ok=True)
            for path in WORK.glob('*.json*'):
                (evidence/path.name).write_bytes(path.read_bytes())
            (evidence/'evidence.json').write_text(json.dumps(self.report, indent=2)+'\n')
            # Export contains redacted fixture evidence only; make copied reports readable.
            for path in evidence.iterdir():
                assert path.is_file() and not path.is_symlink(), 'unexpected evidence export entry'
                path.chmod(0o644)
            evidence.chmod(0o755)
        assert self.report['result'] == 'passed', (repr(error), self.report['cleanup_errors'], self.report['counts'])
        print(json.dumps({'result': self.report['result'], 'counts': self.report['counts']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frozen', type=Path, nargs='?')
    parser.add_argument('--transport', type=Path)
    parser.add_argument('--prestart', action='store_true')
    parser.add_argument('--sentinel', action='store_true')
    args = parser.parse_args()
    if args.prestart:
        prestart()
    elif args.sentinel:
        sentinel()
    else:
        vm_guard()
        assert args.frozen and args.transport
        assert BASE.is_dir() and not WORK.exists(), 'fresh private fixture root required'
        Gate(args.frozen.resolve(), args.transport.resolve()).run()


if __name__ == '__main__':
    main()
