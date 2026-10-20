"""Private manager handoffs to exact compiled production BEAMs; no host bus."""
import glob
import os
from pathlib import Path
import select
import signal
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
CASES = ["healthy", "owner-death", "owner-kill", "native", "native-reused-file", "native-mismatch", "wrong-pid",
         "wrong-count", "wrong-name", "missing-name", "wrong-path", "wrong-fd",
         "wrong-domain", "wrong-type", "not-listening", "native-wrong-domain",
         "native-wrong-type", "native-not-listening", "dup-probe"]


def run(case):
    with tempfile.TemporaryDirectory(prefix="osbus-p11-inherited-") as temp:
        os.chmod(temp, 0o700)
        path = temp + "/bus"
        manager = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        manager.settimeout(3)
        manager.bind(path)
        manager.listen()
        os.chmod(path, 0o620)
        before = os.stat(path)
        supplied = manager
        extra = None
        if case in ("wrong-domain", "native-wrong-domain"):
            extra = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            extra.bind(("127.0.0.1", 0))
            extra.listen()
        elif case in ("wrong-type", "native-wrong-type"):
            extra = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            extra.bind(temp + "/dgram")
        elif case in ("not-listening", "native-not-listening"):
            extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            extra.bind(temp + "/unlistened")
        elif case == "native-reused-file":
            # Reuse the closed listener's descriptor for a regular file before
            # entering BEAM, proving the integer alone cannot authorize mutation.
            extra = open(temp + "/reused", "w+b")
        if extra is not None:
            supplied = extra
        rd, wr = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(rd)
            os.dup2(wr, 1)
            os.dup2(wr, 2)
            if wr not in (1, 2):
                os.close(wr)
            target = 4 if case == "wrong-fd" else 3
            os.dup2(supplied.fileno(), target, inheritable=True)
            os.set_inheritable(target, True)
            if target != 3:
                os.close(3)
            # Close non-handoff descriptors; Python-created descriptors already
            # carry CLOEXEC, including the manager's extra copy.
            env = dict(os.environ, LISTEN_PID=str(os.getpid()), LISTEN_FDS="1",
                       LISTEN_FDNAMES="dbus", P11_CASE=case, P11_PATH=path,
                       ERL_FLAGS="+S 2:2")
            if case == "wrong-pid":
                env["LISTEN_PID"] = str(os.getppid())
            elif case == "wrong-count":
                env["LISTEN_FDS"] = "2"
            elif case == "wrong-name":
                env["LISTEN_FDNAMES"] = "other"
            elif case == "missing-name":
                del env["LISTEN_FDNAMES"]
            args = [str(ROOT / ".devenv/profile/bin/elixir")]
            for ebin in sorted(glob.glob(str(ROOT / "_build/test/lib/*/ebin"))):
                args.extend(["-pa", ebin])
            args.append(str(ROOT / "apps/gao_bus/test/fixtures/inherited_listener_child.exs"))
            os.execve(args[0], args, env)
        os.close(wr)
        output = bytearray()
        reaped = False
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if select.select([rd], [], [], 0.1)[0]:
                    chunk = os.read(rd, 65536)
                    output.extend(chunk)
                pid, status = os.waitpid(child, os.WNOHANG)
                if pid:
                    reaped = True
                    while select.select([rd], [], [], 0)[0]:
                        chunk = os.read(rd, 65536)
                        if not chunk:
                            break
                        output.extend(chunk)
                    assert os.waitstatus_to_exitcode(status) == 0, output.decode()
                    assert b"1 test, 0 failures" in output, output.decode()
                    break
            else:
                raise AssertionError("child timeout: " + output.decode())
            after = os.stat(path)
            assert (before.st_dev, before.st_ino, before.st_mode) == (
                after.st_dev, after.st_ino, after.st_mode)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(path)
                accepted, _ = manager.accept()
                accepted.close()
            assert not os.path.exists(path + "-expected"), "owned-path fallback"
            print(f"PASS {case}: exact child test, manager inode/mode/listener survived")
            print(output.decode().strip())
        finally:
            if not reaped:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            os.close(rd)
            if extra is not None:
                extra.close()
            manager.close()


if __name__ == "__main__":
    for selected in sys.argv[1:] or CASES:
        assert selected in CASES
        run(selected)
