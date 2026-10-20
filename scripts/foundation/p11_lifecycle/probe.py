"""Exercise the actual foreground release with private manager-owned sockets.

Reuses the independent FD workload's wire actor; never uses a default bus.
This is a bounded SYS prerequisite, not installed-profile/activation acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/foundation/p08_sustained"))
from transport import Client, call, read_string

CASES = ["owned", "inherited", "abstract-notify", "wrong-pid", "wrong-count",
         "wrong-name", "missing-name", "missing-fd", "wrong-path", "wrong-domain",
         "wrong-type", "not-listening", "invalid-config", "missing-config",
         "relative-config", "invalid-mode", "missing-notify"]
POSITIVE = {"owned", "inherited", "abstract-notify"}


def inventory(release):
    return {str(path.relative_to(release)): {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": stat.S_IMODE(path.stat().st_mode)}
            for path in sorted(release.rglob("*")) if path.is_file()}


def wait_child(pid, deadline):
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.02)
    raise AssertionError("release did not exit within the fixed deadline")


def socket_fds(pid, inode):
    result = []
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.readlink(entry) == f"socket:[{inode}]":
                flags = int(next(line.split()[1] for line in
                    Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text().splitlines()
                    if line.startswith("flags:")), 8)
                result.append({"fd": int(entry.name), "flags": flags})
        except FileNotFoundError:
            pass
    return result


def run_case(release, reports, case):
    log_path = reports / (case + ".log")
    child = None
    reaped = False
    client = None
    with tempfile.TemporaryDirectory(prefix="osbus-rel-") as directory:
        os.chmod(directory, 0o700)
        private = Path(directory)
        path = str(private / "bus")
        expected = path + "-expected" if case == "wrong-path" else path
        configuration = private / "bus.conf"
        config = (f"<busconfig><type>system</type><listen>unix:path={expected}</listen>"
                  f'<policy context="default"><allow user="{os.getuid()}"/>'
                  '<allow own="*"/><allow send_destination="*"/>'
                  '<allow receive_sender="*"/></policy></busconfig>')
        if case == "invalid-config":
            config = config.replace("</busconfig>", "<unknown_security/></busconfig>")
        configuration.write_text(config)
        os.chmod(configuration, 0o600)
        manager = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        manager.settimeout(3)
        supplied = manager
        extra = None
        inherited = case != "owned"
        if inherited:
            manager.bind(path)
            manager.listen()
            os.chmod(path, 0o620)
            before = os.stat(path)
            inode = os.fstat(manager.fileno()).st_ino
        if case == "wrong-domain":
            extra = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            extra.bind(("127.0.0.1", 0))
            extra.listen()
        elif case == "wrong-type":
            extra = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            extra.bind(str(private / "dgram"))
        elif case == "not-listening":
            extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            extra.bind(str(private / "unlistened"))
        if extra is not None:
            supplied = extra
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify.settimeout(15)
        notify.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        destination = str(private / "notify")
        if case == "abstract-notify":
            destination = f"@osbus-rel-{os.getpid()}-{private.name}"
        notify.bind("\0" + destination[1:] if destination.startswith("@") else destination)
        env = {key: value for key, value in os.environ.items() if not key.startswith(
            ("LISTEN_", "OS_BUS_", "DBUS_", "GAO_", "PHX_", "RELEASE_"))}
        env.update(OS_BUS_CONFIG=str(configuration), OS_BUS_INHERITED_LISTENER=str(inherited).lower(),
                   NOTIFY_SOCKET=destination, RELEASE_TMP=str(private / "release-tmp"),
                   ERL_FLAGS="+S 2:2", ERL_CRASH_DUMP_SECONDS="0")
        if case == "missing-config":
            del env["OS_BUS_CONFIG"]
        elif case == "relative-config":
            env["OS_BUS_CONFIG"] = "bus.conf"
        elif case == "invalid-mode":
            env["OS_BUS_INHERITED_LISTENER"] = "1"
        if case == "missing-notify":
            del env["NOTIFY_SOCKET"]
        row = {"case": case, "config_sha256": hashlib.sha256(config.encode()).hexdigest(),
               "inherited": inherited, "private_address": path, "result": "running"}
        try:
            with log_path.open("wb") as log:
                child = os.fork()
                if child == 0:
                    os.dup2(log.fileno(), 1)
                    os.dup2(log.fileno(), 2)
                    if inherited and case != "missing-fd":
                        os.dup2(supplied.fileno(), 3, inheritable=True)
                        os.set_inheritable(3, True)
                    else:
                        try:
                            os.close(3)
                        except OSError:
                            pass
                    if inherited:
                        env.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS="1", LISTEN_FDNAMES="dbus")
                    if case == "wrong-pid":
                        env["LISTEN_PID"] = str(os.getppid())
                    elif case == "wrong-count":
                        env["LISTEN_FDS"] = "2"
                    elif case == "wrong-name":
                        env["LISTEN_FDNAMES"] = "other"
                    elif case == "missing-name":
                        del env["LISTEN_FDNAMES"]
                    os.chdir(directory)
                    os.execve(str(release / "bin/os_bus"), [str(release / "bin/os_bus"), "start"], env)
                row["pid"] = child
                if case in POSITIVE:
                    data, controls, flags, _ = notify.recvmsg(128, socket.CMSG_SPACE(12))
                    assert data == b"READY=1" and flags == 0, (data, controls, flags)
                    credentials = [struct.unpack("3i", value) for level, kind, value in controls
                                   if (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)]
                    assert credentials == [(child, os.getuid(), os.getgid())], credentials
                    row["readiness_credentials"] = credentials
                    assert Path(os.readlink(f"/proc/{child}/exe")).name == "beam.smp"
                    command = Path(f"/proc/{child}/cmdline").read_bytes().split(b"\0")
                    assert b"-name" not in command and b"-sname" not in command, command
                    owned_inodes = set()
                    for fd in Path(f"/proc/{child}/fd").iterdir():
                        try:
                            target = os.readlink(fd)
                            if target.startswith("socket:["):
                                owned_inodes.add(target[8:-1])
                        except FileNotFoundError:
                            pass
                    for table in ("tcp", "tcp6"):
                        for line in Path(f"/proc/{child}/net/{table}").read_text().splitlines()[1:]:
                            fields = line.split()
                            assert not (fields[3] == "0A" and fields[9] in owned_inodes), line
                    row["no_tcp_listener"] = True
                    client = Client(path)
                    client.sock.sendall(call("GetId", 3))
                    reply = client.reply(3)
                    assert reply["type"] == 2 and not reply["fds"], reply
                    row["bus_id"] = read_string(reply["body"])
                    assert len(row["bus_id"]) == 32
                    if inherited:
                        descriptors = socket_fds(child, inode)
                        assert len(descriptors) == 1 and descriptors[0]["fd"] != 3, descriptors
                        assert descriptors[0]["flags"] & 0o2000000, descriptors
                        row["owned_listener_fds"] = descriptors
                    os.kill(child, signal.SIGTERM)
                    code = wait_child(child, time.monotonic() + 10)
                    reaped = True
                    assert code == 0, code
                else:
                    code = wait_child(child, time.monotonic() + 20)
                    reaped = True
                    assert code != 0, (case, code)
                    notify.setblocking(False)
                    try:
                        notification = notify.recv(128)
                    except BlockingIOError:
                        notification = None
                    assert notification is None, notification
                row["exit_status"] = code
            if inherited:
                after = os.stat(path)
                assert (before.st_dev, before.st_ino, before.st_mode) == (
                    after.st_dev, after.st_ino, after.st_mode)
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(3)
                    probe.connect(path)
                    accepted, _ = manager.accept()
                    accepted.close()
                row["manager_survived"] = True
            else:
                assert not os.path.exists(path), "owned endpoint was not removed"
            assert not os.path.exists(path + "-expected"), "pathname fallback"
            row["result"] = "passed"
            return row
        finally:
            if child is not None and not reaped:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            if client:
                client.close()
            if extra is not None:
                extra.close()
            manager.close()
            notify.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    release = args.release.resolve()
    reports = args.reports.resolve()
    assert (release / "bin/os_bus").is_file()
    assert not reports.exists(), "preserve earlier evidence; choose a new directory"
    reports.mkdir(mode=0o700, parents=True)
    apps = sorted(path.name for path in (release / "lib").iterdir())
    assert not any(name.startswith(("gao_bus_web-", "gao_config-", "gao_bus_test-", "phoenix-",
                                    "bandit-", "dns_cluster-")) for name in apps), apps
    evidence = {"release": str(release), "apps": apps, "package_before": inventory(release),
                "selected": args.case or CASES, "rows": [], "not_profile_acceptance": True}
    try:
        for case in evidence["selected"]:
            try:
                row = run_case(release, reports, case)
            except BaseException as error:
                evidence["rows"].append({"case": case, "result": "failed", "error": repr(error)})
                raise
            evidence["rows"].append(row)
            print(json.dumps(row), flush=True)
        evidence["result"] = "passed"
    except BaseException as error:
        evidence["result"] = "failed"
        evidence["error"] = repr(error)
        raise
    finally:
        evidence["counts"] = {"selected": len(evidence["selected"]),
                              "executed": len(evidence["rows"]),
                              "passed": sum(row["result"] == "passed" for row in evidence["rows"]),
                              "failed": sum(row["result"] == "failed" for row in evidence["rows"]),
                              "skipped": 0, "blocked": len(evidence["selected"]) - len(evidence["rows"])}
        evidence["package_after"] = inventory(release)
        assert evidence["package_before"] == evidence["package_after"], "package mutated"
        (reports / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
