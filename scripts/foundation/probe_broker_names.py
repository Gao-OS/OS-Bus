"""Isolated broker-37 observation; never substitutes the mandatory daemon oracle."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone


sys.dont_write_bytecode = True
ROOT = Path("/") if sys.argv[1:2] == ["--launch"] else Path(__file__).resolve().parents[2]
BROKER = Path("/nix/store/52k47shyn682b1blwrryiha1inib69gq-dbus-broker-37/bin/dbus-broker")
BROKER_SOURCE = "https://github.com/bus1/dbus-broker/blob/e5b413f573b2c158bff88370944d571379977b7e/src/bus/name.c"
EXPECTED = [
    (1, [0]), (4, [0]), (2, [0, 1]), (2, [0, 1, 2]),
    (2, [0, 1, 2]), (1, [3, 0, 1, 2]), (2, [3, 0, 1, 2]),
    (1, [0, 1, 2]), (1, [1, 0, 2]), (4, [1, 0, 2]),
    (1, [3, 0, 2]), (3, [3, 2]), (1, [3]), (1, None),
]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def emit(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def launch(launcher):
    # Executed after entering the private PID/mount/network/user namespaces.
    listener = socket.socket(fileno=3)
    assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    os.set_inheritable(3, True)
    os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS="1", LISTEN_FDNAMES="dbus")
    emit(Path("/probe/activation.json"), {
        "pid": os.getpid(), "uid": os.getuid(), "listener_fd": 3,
        "listener": listener.getsockname(), "inheritable": os.get_inheritable(3),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "listen_pid": os.environ["LISTEN_PID"], "listen_fds": "1",
    })
    os.execv(launcher, [launcher, "--scope=user", "--config-file=/probe/bus.conf"])


def string_array(body):
    size = struct.unpack_from("<I", body)[0]
    assert size + 4 == len(body), (size, len(body))
    offset, values = 4, []
    while offset < len(body):
        offset += -offset % 4
        length = struct.unpack_from("<I", body, offset)[0]
        values.append(body[offset + 4:offset + 4 + length].decode())
        assert body[offset + 4 + length] == 0
        offset += 5 + length
    assert offset == len(body)
    return values


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    broker = args.broker.resolve(strict=True)
    launcher = broker.with_name("dbus-broker-launch")
    version = subprocess.check_output([str(broker), "--version"], text=True).strip()
    assert version == "dbus-broker 37", version
    launcher_version = subprocess.check_output([str(launcher), "--version"], text=True).strip()
    assert launcher_version == "dbus-broker-launch 37", launcher_version
    actor_path = ROOT / "apps/gao_bus/test/fixtures/transport_actor.py"
    spec = importlib.util.spec_from_file_location("transport_actor", actor_path)
    actor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(actor)
    reference_path = ROOT / "apps/gao_bus/test/name_reference_test.exs"
    sequence_text = reference_path.read_text().split("sequence = [", 1)[1].split("]", 1)[0]
    actions = [tuple([kind, int(peer)] + ([int(flags)] if flags else []))
               for kind, peer, flags in re.findall(r"\{:(request|release), (\d+)(?:, (\d+))?\}", sequence_text)]
    assert len(actions) == len(EXPECTED) == 14, actions
    metadata = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, *sys.argv], "cwd": str(ROOT),
        "source_baseline": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "python": sys.version, "kernel": platform.release(), "uid": os.getuid(), "gid": os.getgid(),
        "broker": str(broker), "broker_version": version, "broker_sha256": sha256(broker),
        "launcher": str(launcher), "launcher_version": launcher_version, "launcher_sha256": sha256(launcher),
        "broker_source": BROKER_SOURCE,
        "broker_name_c_sha256": "566ef8f4a46118ade65d635b70c603ffcc2810fafa0d2ce3dd9acf0eb1259e2a",
        "profile": "private EXTERNAL-only session; no activation/services; independent broker observation",
        "actions": actions, "expected": EXPECTED,
        "source_hashes": {str(path.relative_to(ROOT)): sha256(path) for path in [
            Path(__file__).resolve(), actor_path, reference_path,
            ROOT / "apps/gao_bus/lib/gao_bus/name_registry.ex", ROOT / "devenv.lock",
            ROOT / "test/reports/foundation/references/dbus-specification.html",
            ROOT / "test/reports/foundation/p07-names-matches-final.log",
            ROOT / "test/reports/foundation/p07-reference-1.16.2.log",
        ]},
        "mandatory_dbus_daemon_gate": "FAIL preserved; this probe does not replace or pass it",
        "sol_repair_rounds": 2,
    }
    clients, process, observations, journal = [], None, [], []
    stop_journal = threading.Event()
    runtime = Path(tempfile.mkdtemp(prefix="osbus-broker-names-"))
    cleanup = {"runtime_directory": str(runtime)}
    status, failure = "BLOCKED", None
    try:
        os.chmod(runtime, 0o700)
        (runtime / "run/systemd/journal").mkdir(parents=True)
        (runtime / "etc").mkdir()
        (runtime / "etc/machine-id").write_text("76e566c070114f87bf55d8f2276b6da2\n")
        (runtime / "etc/passwd").write_text(f"probe:x:{os.getuid()}:{os.getgid()}::/probe:/bin/false\n")
        (runtime / "etc/group").write_text(f"probe:x:{os.getgid()}:\n")
        config = """<busconfig>
  <type>session</type>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"""
        (runtime / "bus.conf").write_text(config)
        (output / "bus.conf").write_text(config)
        metadata["config_sha256"] = sha256(output / "bus.conf")
        shutil.copyfile(__file__, runtime / "probe.py")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        assert listener.fileno() == 3, listener.fileno()
        listener.bind(str(runtime / "bus"))
        listener.listen(16)
        os.chmod(runtime / "bus", 0o600)
        sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sink.bind(str(runtime / "run/systemd/journal/socket"))
        sink.settimeout(0.1)
        bwrap = str(Path(shutil.which("bwrap")).resolve(strict=True))
        python = str(Path(sys.executable).resolve(strict=True))
        command = [bwrap, "--die-with-parent", "--unshare-all",
                   "--ro-bind", "/nix/store", "/nix/store", "--bind", str(runtime), "/probe",
                   "--bind", str(runtime / "run"), "/run", "--ro-bind", str(runtime / "etc"), "/etc",
                   "--proc", "/proc", "--dev", "/dev", "--clearenv",
                   "--setenv", "PATH", str(broker.parent),
                   "--setenv", "DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/probe/bus",
                   "--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=/probe/bus",
                   python, "/probe/probe.py", "--launch", str(launcher)]
        metadata["launcher_command"] = command
        metadata["bwrap_sha256"] = sha256(bwrap)
        metadata["python_executable"] = python
        metadata["host_pid_namespace"] = os.readlink("/proc/self/ns/pid")
        metadata["host_mount_namespace"] = os.readlink("/proc/self/ns/mnt")
        with (output / "launcher.log").open("wb") as log:
            process = subprocess.Popen(command, pass_fds=(3,), stdout=log, stderr=log, start_new_session=True)
        metadata["namespace_wrapper_host_pid"] = process.pid

        def drain_journal():
            while not stop_journal.is_set():
                try:
                    journal.append(sink.recv(65536).decode(errors="replace"))
                except socket.timeout:
                    pass

        thread = threading.Thread(target=drain_journal)
        thread.start()
        for _ in range(4):
            clients.append(actor.Client(str(runtime / "bus"), negotiate=False))
        names = [client.name for client in clients]
        metadata["participants"] = dict(zip("ABCD", names))
        serial = 10
        for index, (action, (expected_result, expected_queue)) in enumerate(zip(actions, EXPECTED), 1):
            member = "RequestName" if action[0] == "request" else "ReleaseName"
            body = actor.string("org.foundation.ReferenceQueue")
            if member == "RequestName":
                body += actor.padding(len(body), 4) + actor.u32(action[2])
            client = clients[action[1]]
            client.sock.sendall(actor.call(member, serial, "su" if member == "RequestName" else "s", body))
            reply = client.reply(serial)
            serial += 1
            assert reply["type"] == 2 and reply["fields"].get(8) == "u", reply
            result = struct.unpack("<I", reply["body"])[0]
            client.sock.sendall(actor.call("ListQueuedOwners", serial, "s", actor.string("org.foundation.ReferenceQueue")))
            reply = client.reply(serial)
            serial += 1
            if expected_queue is None:
                queue, error = None, reply["fields"].get(4)
                matches = reply["type"] == 3 and error == "org.freedesktop.DBus.Error.NameHasNoOwner"
            else:
                assert reply["type"] == 2 and reply["fields"].get(8) == "as", reply
                queue, error = string_array(reply["body"]), None
                matches = queue == [names[n] for n in expected_queue]
            observation = {"step": index, "action": action, "result": result,
                           "expected_result": expected_result, "queue": queue, "error": error,
                           "expected_queue": None if expected_queue is None else [names[n] for n in expected_queue],
                           "pass": result == expected_result and matches}
            observations.append(observation)
            print(json.dumps(observation), flush=True)
        assert all(item["pass"] for item in observations), "queued-repeat sequence diverged"
        status = "PASS"
    except Exception as error:
        status = "FAIL" if observations else "BLOCKED"
        failure = f"{type(error).__name__}: {error}"
        print(failure, file=sys.stderr, flush=True)
    finally:
        for client in clients:
            client.close()
        if process is not None:
            if process.poll() is None:
                assert os.getpgid(process.pid) == process.pid
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            cleanup["wrapper_exit"] = process.returncode
            cleanup["wrapper_reaped"] = process.poll() is not None
        stop_journal.set()
        if "thread" in locals():
            thread.join(timeout=2)
            cleanup["journal_thread_stopped"] = not thread.is_alive()
        if "sink" in locals():
            sink.close()
        if "listener" in locals():
            listener.close()
        if (runtime / "activation.json").exists():
            metadata["activation"] = json.loads((runtime / "activation.json").read_text())
            assert metadata["activation"]["pid_namespace"] != metadata["host_pid_namespace"]
            assert metadata["activation"]["mount_namespace"] != metadata["host_mount_namespace"]
        shutil.rmtree(runtime)
        cleanup["runtime_directory_removed"] = not runtime.exists()
        metadata.update(result=status, failure=failure, selected=14, executed=len(observations),
                        passed=sum(item["pass"] for item in observations),
                        failed=sum(not item["pass"] for item in observations), skipped=0,
                        finished_utc=datetime.now(timezone.utc).isoformat(), cleanup=cleanup)
        emit(output / "result.json", metadata)
        emit(output / "observations.json", observations)
        emit(output / "private-journal.json", journal)
        print(json.dumps({"result": status, "executed": len(observations), "output": str(output), "cleanup": cleanup}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--launch":
        launch(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--broker", type=Path, default=BROKER)
        parser.add_argument("--output", required=True, type=Path)
        sys.exit(run(parser.parse_args()))
