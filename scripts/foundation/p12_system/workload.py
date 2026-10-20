"""Normal real-service workload for the canonical disposable-VM system bus.

This is an acceptance entrypoint, not a complete M4 gate. It does not execute
the separate security, malformed-input, sustained-resource or NetworkManager suites.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ADDRESS = "unix:path=/run/dbus/system_bus_socket"
BUS = "org.freedesktop.DBus"
BUS_PATH = "/org/freedesktop/DBus"
FIXTURE = "com.test.ExternalFixture"
FIXTURE_PATH = "/com/test/ExternalFixture"
SELECTED = ["canonical-owner", "systemd-api", "logind-api", "polkit-decisions",
            "automatic-activation", "fixture-fd", "logind-inhibitor",
            "vm05-policy-reload", "vm05-faulty-clients", "vm05-service-failure",
            "vm05-bounded-overload"]


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def guard():
    require(Path("/etc/osbus-system-guest").read_text() == "isolated-vm\n",
            "disposable VM marker required")
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    require("QEMU" in product or "KVM" in product or "Standard PC" in product,
            "unexpected virtual machine identity: " + product)
    inputs = json.loads(Path("/etc/osbus-system-inputs.json").read_text())
    require(inputs["schema"] == 1, "unknown qualification inputs")
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == inputs["workloadSha256"],
            "workload differs from immutable VM input")
    require(hashlib.sha256(Path(__file__).with_name("vm05.py").read_bytes()).hexdigest() ==
            inputs["vm05Sha256"], "VM-05 actors differ from immutable VM input")
    verify_release(inputs)
    return inputs


def verify_release(inputs):
    """Bind every frozen package entry to the captured manifest before clients run."""
    manifest_bytes = Path(inputs["releaseManifest"]).read_bytes()
    require(hashlib.sha256(manifest_bytes).hexdigest() == inputs["manifestSha256"],
            "release manifest differs from the VM input")
    manifest = json.loads(manifest_bytes)
    require(manifest["schema"] == 1 and manifest["not_a_release"] is False and
            manifest["nixpkgs"] == inputs["pinned"], "unexpected release capture")
    require(all(manifest["sources"].get(path) == digest
                for path, digest in inputs["sourceHashes"].items()),
            "release source binding differs from the current implementation")
    require(inputs["releaseImport"] == "nix-nar-readonly-v1",
            "unknown release import permission mapping")
    expected = {}
    for name, captured in manifest["inventory"].items():
        mode = captured["mode"]
        require(type(mode) is int and 0 <= mode <= 0o7777 and not mode & 0o6000,
                "invalid or privileged captured release mode: " + name)
        row = dict(captured)
        # NAR retains a regular file's owner-executable flag; store import
        # makes all entries read-only and normalizes directory/symlink modes.
        if row["type"] == "file":
            row["mode"] = 0o555 if mode & 0o100 else 0o444
        elif row["type"] == "directory":
            row["mode"] = 0o555
        elif row["type"] == "symlink":
            row["mode"] = 0o777
        else:
            raise RuntimeError("special captured release artifact: " + name)
        expected[name] = row
    root = Path(inputs["release"])
    actual = {}
    for path in root.rglob("*"):
        info = path.lstat()
        row = {"mode": stat.S_IMODE(info.st_mode)}
        require(not row["mode"] & 0o6000, "privileged release artifact")
        if stat.S_ISLNK(info.st_mode):
            row.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as artifact:
                for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                    digest.update(chunk)
            row.update(type="file", sha256=digest.hexdigest(), size=info.st_size)
        elif stat.S_ISDIR(info.st_mode):
            row["type"] = "directory"
        else:
            raise RuntimeError("special release artifact: " + str(path))
        actual[str(path.relative_to(root))] = row
    require(actual == expected, "frozen release differs from its exact NAR-imported inventory")


def command(argv, timeout=20):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    require(result.returncode == 0, {"argv": argv, "status": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
    return result.stdout.strip()


def connect():
    import dbus
    # Explicit address prevents system/session/autolaunch fallback.
    return dbus.bus.BusConnection(ADDRESS)


def call(bus, destination, path, interface, member, signature="", arguments=()):
    return bus.call_blocking(destination, path, interface, member, signature, arguments,
                             timeout=10)


def bus_call(bus, member, signature="", arguments=()):
    return call(bus, BUS, BUS_PATH, BUS, member, signature, arguments)


def credentials(bus, name):
    owner = str(bus_call(bus, "GetNameOwner", "s", (name,)))
    return {"owner": owner,
            "uid": int(bus_call(bus, "GetConnectionUnixUser", "s", (owner,))),
            "pid": int(bus_call(bus, "GetConnectionUnixProcessID", "s", (owner,)))}


def canonical_owner(bus, backend, inputs):
    require(Path("/etc/osbus-system-backend").read_text().strip() == backend,
            "booted backend marker mismatch")
    pid = int(command(["systemctl", "show", "dbus.service", "--property=MainPID", "--value"]))
    require(pid > 1, "canonical service has no MainPID")
    executable = os.readlink(f"/proc/{pid}/exe")
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if backend == "candidate":
        require(Path(executable).name == "beam.smp", "candidate is not the release BEAM")
        require(any(inputs["release"].encode() in item for item in arguments),
                "candidate process is not the frozen release")
        require(b"-name" not in arguments and b"-sname" not in arguments,
                "headless release unexpectedly enables distribution")
    else:
        require(Path(executable).name == "dbus-daemon", "reference process mismatch")
    socket_path = "/run/dbus/system_bus_socket"
    require(stat.S_ISSOCK(Path(socket_path).stat().st_mode), "canonical endpoint is not a socket")
    inodes = set()
    for line in Path("/proc/net/unix").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) == 8 and fields[7] == socket_path and int(fields[3], 16) & 0x10000:
            inodes.add(fields[6])
    require(len(inodes) == 1, "canonical listening endpoint is ambiguous")
    owned = set()
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            owned.add(os.readlink(path))
        except FileNotFoundError:
            # Unrelated transient runtime descriptors can close during sampling.
            continue
    require("socket:[" + next(iter(inodes)) + "]" in owned,
            "canonical unit does not own the canonical listening socket")
    return {"id": str(bus_call(bus, "GetId")), "pid": pid,
            "executable": executable, "address": ADDRESS, "listener_inode": next(iter(inodes))}


def inventory():
    """Capture every effective XML include and service file without pruning."""
    files, directories, visiting = {}, {}, set()

    def record(path):
        data = path.read_bytes()
        require(len(data) <= 4 * 1024 * 1024, "inventory file exceeds fixture budget")
        files[str(path)] = hashlib.sha256(data).hexdigest()
        return data

    def directory(path, kind):
        if not path.exists():
            directories[str(path)] = {"kind": kind, "missing": True}
            return
        entries = sorted(path.iterdir())
        require(len(entries) <= 8192, "inventory directory exceeds fixture budget")
        directories[str(path)] = {"kind": kind, "entries": [entry.name for entry in entries]}
        for entry in entries:
            if kind == "policy" and entry.name.endswith(".conf"):
                xml(entry)
            elif kind == "services" and entry.name.endswith(".service"):
                record(entry)

    def xml(path):
        resolved = str(path.resolve())
        require(resolved not in visiting, "cyclic XML include")
        require(len(visiting) < 32 and len(files) < 4096, "inventory recursion budget exceeded")
        visiting.add(resolved)
        try:
            root = ET.fromstring(record(path))
            for child in root:
                value = (child.text or "").strip()
                if child.tag in ("include", "includedir", "servicedir"):
                    target = Path(value)
                    if not target.is_absolute():
                        target = path.parent / target
                    if child.tag == "include":
                        if not target.exists() and child.get("ignore_missing") == "yes":
                            files[str(target)] = "missing-optional"
                        else:
                            xml(target)
                    else:
                        directory(target, "policy" if child.tag == "includedir" else "services")
                elif child.tag == "standard_system_servicedirs":
                    raise RuntimeError("profile inventory requires explicit service directories")
        finally:
            visiting.remove(resolved)

    xml(Path("/etc/dbus-1/system.conf"))
    return {"files": files, "directories": directories}


def polkit_actor():
    import dbus
    bus = connect()
    try:
        own = credentials(bus, str(bus.get_unique_name()))
        require(own["uid"] == os.getuid() and own["pid"] == os.getpid(), "actor identity mismatch")
        subject = ("system-bus-name", {"name": dbus.String(bus.get_unique_name(), variant_level=1)})
        result = call(bus, "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                      "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
                      "(sa{sv})sa{ss}us", (subject, "org.foundation.OSBus.accept", {}, 0, ""))
        expected = pwd.getpwuid(os.getuid()).pw_name == "foundationA"
        require(bool(result[0]) == expected and not bool(result[1]), "polkit decision mismatch")
        return {"identity": own, "authorized": bool(result[0]), "challenge": bool(result[1])}
    finally:
        bus.close()


def fixture_fd(bus):
    import dbus
    contents = b"OS-Bus canonical activation FD"
    source = os.memfd_create("osbus-system-fixture", os.MFD_CLOEXEC)
    received = None
    try:
        require(os.write(source, contents) == len(contents), "short fixture write")
        descriptor, text = call(bus, FIXTURE, FIXTURE_PATH, FIXTURE, "ReadAndReturnFD",
                                "h", (dbus.types.UnixFd(source),))
        received = descriptor.take()
        require(str(text).encode() == contents and os.pread(received, len(contents) + 1, 0) == contents,
                "independent fixture FD readback mismatch")
        require(os.fstat(source).st_ino == os.fstat(received).st_ino, "returned FD is not the input object")
        return {"bytes": len(contents), "readback": contents.decode()}
    finally:
        if received is not None:
            os.close(received)
        os.close(source)


def inhibitor(bus):
    service, path, interface = "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager"
    token = "osbus-inhibitor-" + str(os.getpid())
    descriptor = call(bus, service, path, interface, "Inhibit", "ssss",
                      ("sleep", "os-bus-foundation", token, "block"))
    received = descriptor.take()
    try:
        require(stat.S_ISFIFO(os.fstat(received).st_mode), "logind did not return a live inhibitor FIFO")
        rows = call(bus, service, path, interface, "ListInhibitors")
        require(any(str(row[2]) == token and int(row[4]) == os.getuid() for row in rows),
                "live inhibitor is missing")
    finally:
        os.close(received)
    deadline = time.monotonic() + 5
    for _ in range(100):
        rows = call(bus, service, path, interface, "ListInhibitors")
        if not any(str(row[2]) == token for row in rows):
            return {"acquired": True, "released": True}
        if time.monotonic() >= deadline:
            break
    raise RuntimeError("logind retained inhibitor after its FD was closed")


def suite(backend, inputs):
    require(os.geteuid() == 0, "suite must run as root inside the disposable VM")
    report = {"schema": 1, "backend": backend, "selected": SELECTED, "rows": [],
              "inputs": inputs,
              "scope": "normal real-service workload; other mandatory gates remain separate"}
    bus = None
    try:
        bus = connect()
        report["bus"] = canonical_owner(bus, backend, inputs)
        report["configuration"] = inventory()
        import vm05
        report["normal_resources"] = {}

        def row(name, operation):
            entry = {"id": name, "result": "failed"}
            report["rows"].append(entry)
            started = time.monotonic()
            try:
                entry["evidence"] = operation()
                entry["result"] = "passed"
            except Exception as error:
                entry["error"] = str(error)
                raise
            finally:
                entry["elapsed_seconds"] = time.monotonic() - started

        row("canonical-owner", lambda: report["bus"])
        def systemd_api():
            path = call(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager", "GetUnit", "s", ("dbus.service",))
            main = call(bus, "org.freedesktop.systemd1", path, "org.freedesktop.DBus.Properties",
                        "Get", "ss", ("org.freedesktop.systemd1.Service", "MainPID"))
            require(int(main) == report["bus"]["pid"], "systemd API reports a different bus process")
            return credentials(bus, "org.freedesktop.systemd1")
        row("systemd-api", systemd_api)
        def logind_api():
            sessions = call(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
                            "org.freedesktop.login1.Manager", "ListSessions")
            evidence = {"sessions_before": len(sessions), **credentials(bus, "org.freedesktop.login1")}
            report["logind_session"] = evidence
            return vm05.login_session(bus, evidence)
        row("logind-api", logind_api)
        def polkit_decisions():
            return {user: json.loads(command(["runuser", "-u", user, "--", sys.executable,
                                               "-B", str(Path(__file__)), "polkit"]))
                    for user in ("foundationA", "foundationB")}
        row("polkit-decisions", polkit_decisions)
        def automatic_activation():
            command(["systemctl", "stop", "osbus-foundation-fixture.service"])
            require(not bool(bus_call(bus, "NameHasOwner", "s", (FIXTURE,))), "fixture was not stopped")
            response = call(bus, FIXTURE, FIXTURE_PATH, FIXTURE, "Echo", "s", ("canonical-activation",))
            require(str(response) == "canonical-activation", "activation response mismatch")
            owner = credentials(bus, FIXTURE)
            require(owner["uid"] == pwd.getpwnam("foundationSvc").pw_uid, "activation UID mismatch")
            return owner
        row("automatic-activation", automatic_activation)
        for name, operation in (("fixture-fd", lambda: fixture_fd(bus)),
                                ("logind-inhibitor", lambda: inhibitor(bus))):
            evidence = report["normal_resources"][name] = {}
            row(name, lambda operation=operation, evidence=evidence:
                vm05.normal_resources(bus, report["bus"]["pid"], operation, evidence))
        report["vm05"] = {}
        for name in SELECTED[7:]:
            evidence = report["vm05"][name] = {}
            row(name, lambda name=name, evidence=evidence:
                vm05.scenario(name, bus, report["bus"], report["configuration"], evidence))
        report["configuration_restored"] = inventory()
        require(report["configuration_restored"] == report["configuration"],
                "complete policy/service inventory changed after VM-05")
        require([entry["id"] for entry in report["rows"]] == SELECTED, "incomplete workload execution")
        report["result"] = "passed"
    except Exception as error:
        report.update(result="failed", error=str(error))
    finally:
        report["counts"] = {"selected": len(SELECTED), "executed": len(report["rows"]),
                            "passed": sum(entry["result"] == "passed" for entry in report["rows"]),
                            "failed": sum(entry["result"] == "failed" for entry in report["rows"]),
                            "unrun": len(SELECTED) - len(report["rows"])}
        if bus is not None:
            bus.close()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    normal = commands.add_parser("suite")
    normal.add_argument("--backend", choices=["reference", "candidate"], required=True)
    normal.add_argument("--output", type=Path, required=True)
    commands.add_parser("polkit")
    arguments = parser.parse_args()
    inputs = guard()
    if arguments.command == "polkit":
        print(json.dumps(polkit_actor(), sort_keys=True))
    else:
        report = suite(arguments.backend, inputs)
        arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, sort_keys=True))
        sys.exit(0 if report["result"] == "passed" else 1)
