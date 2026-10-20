"""Private native checks. Never invokes the installed privileged helper."""
import errno
import ctypes
import os
from pathlib import Path
import select
import resource
import signal
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "c_src/gao_helper_bridge.c"
FIXTURES = ROOT / "test/fixtures"


class BridgeChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert SOURCE.is_file(), "standalone bounded helper bridge is missing"
        # Own and reap harmless daemonized fixture descendants in this runner.
        assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        cls.temp = tempfile.TemporaryDirectory(prefix="gao-helper-native-")
        cls.directory = Path(cls.temp.name)
        cls.actor = cls.directory / "actor"
        cls.compile([FIXTURES / "helper_bridge_actor.c"], cls.actor,
                    [f'-DFIXTURE_DIRECTORY="{cls.directory}"'])
        cls.bridge = cls.build("bridge", cls.actor)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def compile(cls, sources, output, extra=()):
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fstack-protector-strong", *extra, *map(str, sources),
                        "-Wl,-z,relro,-z,now", "-o", str(output)], check=True)

    @classmethod
    def build(cls, label, actor=None, fault=None, wrapper=None):
        output = cls.directory / label
        options = [f'-DGAO_HELPER_PATH="{actor}"'] if actor else []
        sources = [SOURCE]
        if fault:
            sources.append(FIXTURES / "helper_bridge_faults.c")
            options += [f"-DFAULT_{fault}", f"-Wl,--wrap={wrapper}"]
        cls.compile(sources, output, options)
        return output

    def record(self, name="org.fixture.Exit0", bridge=None, **options):
        completed = subprocess.run([str(bridge or self.bridge), name],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=5, **options)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(len(completed.stdout), 16)
        magic, kind, stage, reserved, value, tail = struct.unpack(">4sBBHII", completed.stdout)
        self.assertEqual((magic, reserved, tail), (b"GHB\x01", 0, 0))
        return kind, stage, value

    def test_exact_exit_codes(self):
        for code in [0, 1, *range(2, 12), 127, 137, 255]:
            with self.subTest(code=code):
                self.assertEqual(self.record(f"org.fixture.Exit{code}"), (3, 0, code))

    def test_signals_are_distinct_from_exit137(self):
        self.assertEqual(self.record("org.fixture.Kill"), (4, 0, signal.SIGKILL))
        self.assertEqual(self.record("org.fixture.Term"), (4, 0, signal.SIGTERM))
        self.assertEqual(self.record("org.fixture.Exit137"), (3, 0, 137))

    def test_missing_and_non_executable(self):
        missing = self.build("missing", self.directory / "missing-helper")
        self.assertEqual(self.record(bridge=missing), (2, 9, errno.ENOENT))
        forbidden = self.directory / "forbidden-helper"
        forbidden.write_text("no executable permission\n")
        bridge = self.build("forbidden", forbidden)
        self.assertEqual(self.record(bridge=bridge), (2, 9, errno.EACCES))

    def test_invalid_arguments_never_start(self):
        for name in ["org.freedesktop.DBus", ":1.1", "single", "org..Bad", "org.1bad", "org.bad/name", "a." + "b" * 254]:
            with self.subTest(name=name):
                self.assertEqual(self.record(name), (1, 1, errno.EINVAL))
        for args in [[], ["org.fixture.Exit0", "extra"]]:
            completed = subprocess.run([str(self.bridge), *args], capture_output=True, timeout=5)
            self.assertEqual(len(completed.stdout), 16)
            self.assertEqual(struct.unpack(">4sBBHII", completed.stdout)[1:3], (1, 1))

    def test_unbound_build_fails_before_fork(self):
        bridge = self.build("unbound")
        self.assertEqual(self.record(bridge=bridge), (1, 2, errno.ENOENT))

    def binding_metadata(self, bridge):
        data = bridge.read_bytes()
        self.assertEqual(data[:5], b"\x7fELF\x02")
        self.assertIn(data[5], (1, 2))
        order = "<" if data[5] == 1 else ">"
        table = struct.unpack_from(order + "Q", data, 40)[0]
        width, count, names_index = struct.unpack_from(order + "HHH", data, 58)
        sections = [struct.unpack_from(order + "IIQQQQIIQQ", data, table + index * width)
                    for index in range(count)]
        names_section = sections[names_index]
        names = data[names_section[4]:names_section[4] + names_section[5]]
        matching = [section for section in sections
                    if names[section[0]:].split(b"\0", 1)[0] == b".gao_helper_binding"]
        self.assertEqual(len(matching), 1)
        section = matching[0]
        self.assertEqual(section[2] & 1, 0, "binding metadata must be read-only")
        self.assertEqual(section[2] & 2, 2, "binding metadata must survive normal ELF stripping")
        return data[section[4]:section[4] + section[5]]

    def test_retained_binding_is_exact_read_only_metadata(self):
        self.assertEqual(self.binding_metadata(self.bridge), os.fsencode(self.actor) + b"\0")
        unbound = self.build("metadata-unbound")
        self.assertEqual(self.binding_metadata(unbound), b"\0")
        collected = self.directory / "metadata-gc"
        self.compile([SOURCE], collected, ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])
        self.assertEqual(self.binding_metadata(collected), b"\0")

    def test_make_rebuild_applies_changed_package_binding(self):
        app = self.directory / "make-app"
        bridge = app / "priv/gao_helper_bridge"
        command = ["make", "-C", str(ROOT), str(bridge), f"MIX_APP_PATH={app}"]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(self.record(bridge=bridge), (1, 2, errno.ENOENT))
        subprocess.run([*command, f"GAO_HELPER_PATH={self.actor}"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(self.record(bridge=bridge), (3, 0, 0))

    def test_complete_fd_environment_and_signal_isolation(self):
        fd = os.open("/dev/null", os.O_RDONLY)
        high = 8192
        previous_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(previous_limit[0], high + 1), previous_limit[1]))
        os.dup2(fd, high, inheritable=True)
        def inherited_signals():
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        try:
            self.assertEqual(self.record("org.fixture.Inspect", pass_fds=(fd, high),
                                         env={"LD_PRELOAD": "", "NOTIFY_SOCKET": "hostile", "TEST_LAUNCH_HELPER_CONFIG": "hostile"},
                                         preexec_fn=inherited_signals), (3, 0, 0))
        finally:
            os.close(fd)
            os.close(high)
            resource.setrlimit(resource.RLIMIT_NOFILE, previous_limit)

    def test_closed_stdin_or_stderr_is_replaced_without_cloexec(self):
        for fd in [0, 2]:
            with self.subTest(fd=fd):
                self.assertEqual(self.record("org.fixture.Inspect", preexec_fn=lambda: os.close(fd)), (3, 0, 0))

    def test_service_stdout_stderr_cannot_reach_record(self):
        self.assertEqual(self.record("org.fixture.Flood"), (3, 0, 0))

    def test_daemon_descendant_cannot_hold_status_pipe(self):
        gate = self.directory / "daemon.gate"
        os.mkfifo(gate)
        try:
            # subprocess.run must see EOF even while descendant is blocked at its gate.
            self.assertEqual(self.record("org.fixture.Daemon"), (3, 0, 0))
            with gate.open("wb", buffering=0) as writer:
                pid = int((self.directory / "daemon.pid").read_text())
                pidfd = os.pidfd_open(pid)
                writer.write(b"x")
            try:
                self.assertEqual(select.select([pidfd], [], [], 5)[0], [pidfd])
                self.assertEqual(os.waitpid(pid, 0), (pid, 0))
            finally:
                os.close(pidfd)
        finally:
            gate.unlink()

    def test_prefork_failures_are_proven_not_started(self):
        for fault, wrapper, stage, error in [("FORK", "fork", 7, errno.EAGAIN),
                                             ("PIPE", "pipe2", 6, errno.EMFILE),
                                             ("CLOSE", "close_range", 5, errno.ENOSYS),
                                             ("HARDENING", "prctl", 3, errno.EPERM)]:
            with self.subTest(fault=fault):
                bridge = self.build(fault, self.actor, fault, wrapper)
                self.assertEqual(self.record(bridge=bridge), (1, stage, error))

    def test_child_setup_failure_requires_reaping(self):
        bridge = self.build("child-close", self.actor, "CHILD_CLOSE", "close_range")
        self.assertEqual(self.record(bridge=bridge), (2, 5, errno.ENOSYS))
        bridge = self.build("child-move", self.actor, "MOVE", "dup3")
        self.assertEqual(self.record(bridge=bridge), (2, 5, errno.EBUSY))

    def test_private_error_pipe_read_failure_is_observation_loss(self):
        bridge = self.build("read-failure", self.actor, "READ", "read")
        self.assertEqual(self.record(bridge=bridge), (5, 11, errno.EIO))

    def test_wait_failure_is_observation_loss(self):
        bridge = self.build("wait-failure", self.actor, "WAIT", "waitpid")
        self.assertEqual(self.record(bridge=bridge), (5, 10, errno.ECHILD))

    def test_interrupted_wait_retries_exact_child(self):
        bridge = self.build("interrupted-wait", self.actor, "EINTR", "waitpid")
        self.assertEqual(self.record(bridge=bridge), (3, 0, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
