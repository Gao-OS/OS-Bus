"""Private P01 inherited FD launcher test. Never uses a host bus endpoint."""
import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import time

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='osbus-inherit-') as temp:
    os.chmod(temp, 0o700)
    path = temp + '/bus'
    listener = socket.socket(socket.AF_UNIX)
    listener.settimeout(5)
    listener.bind(path)
    listener.listen()
    before = os.stat(path)
    rd, wr = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(rd)
        os.dup2(wr, 1)
        os.dup2(wr, 2)
        if wr != 3:
            os.close(wr)
        os.dup2(listener.fileno(), 3, inheritable=True)
        # dup2(fd, fd) is a no-op: explicitly clear CLOEXEC in that case too.
        os.set_inheritable(3, True)
        print(f'PRE_EXEC fd3={os.readlink("/proc/self/fd/3")} inheritable={os.get_inheritable(3)} pid={os.getpid()}', flush=True)
        env = dict(os.environ, LISTEN_PID=str(os.getpid()), LISTEN_FDS='1',
                   ERL_FLAGS='+S 2:2', PATH=str(root / '.devenv/profile/bin') + ':' + os.environ['PATH'])
        os.execvpe('elixir', ['elixir', str(root / 'scripts/foundation/inherited_listener.exs')], env)
    os.close(wr)
    reaped = False
    try:
        output = b''
        deadline = time.monotonic() + 15
        while b'READY ' not in output:
            assert time.monotonic() < deadline, 'launcher readiness timed out: ' + repr(output)
            if select.select([rd], [], [], 0.1)[0]:
                chunk = os.read(rd, 4096)
                assert chunk, 'launcher failed: ' + repr(output)
                output += chunk
        assert f'READY {child}'.encode() in output, output
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(5)
            probe.connect(path)
            probe.sendall(b'probe')
            assert probe.recv(128) == b'inherited-ok'
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                reaped = True
                assert os.waitstatus_to_exitcode(status) == 0, status
                break
            assert time.monotonic() < deadline, 'launcher exit timed out'
            if select.select([rd], [], [], 0.1)[0]:
                output += os.read(rd, 4096)
        after = os.stat(path)
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        # Closing the daemon copy must leave the manager's listener usable.
        with socket.socket(socket.AF_UNIX) as second:
            second.settimeout(5)
            second.connect(path)
            accepted, _ = listener.accept()
            accepted.close()
        print(output.decode().strip())
        print('PASS inherited listener survived real elixir/erl/BEAM launcher, PID validation and daemon close')
    finally:
        if not reaped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        os.close(rd)
        listener.close()
