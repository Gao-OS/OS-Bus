#!/usr/bin/env python3
"""Capture H01 offline feasibility evidence; this does not qualify the bus."""

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(pid):
    base = Path("/proc", str(pid))
    result = {"pid": pid}
    try:
        status = base.joinpath("status").read_text()
        fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line}
        result.update(starttime_ticks=int(base.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]),
                      uid=[int(value) for value in fields["Uid"].split()],
                      gid=[int(value) for value in fields["Gid"].split()])
        result.update(
            argv=base.joinpath("cmdline").read_bytes().decode(errors="replace").split("\0")[:-1],
            exe=os.readlink(base / "exe"),
            status=status,
            netns=os.readlink(base / "ns/net"),
        )
    except (FileNotFoundError, ProcessLookupError):
        result["already_exited"] = True
    return result


def network(init_netns):
    dev = Path("/proc/net/dev").read_text()
    routes = Path("/proc/net/route").read_text()
    ipv6_routes = Path("/proc/net/ipv6_route").read_text()
    ipv6_rows = [{"raw": line, "flags": int(line.split()[8], 16),
                  "reject": bool(int(line.split()[8], 16) & 0x200)}
                 for line in ipv6_routes.splitlines() if line.strip()]
    interfaces = [line.split(":", 1)[0].strip() for line in dev.splitlines()[2:]]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        flags = {name: struct.unpack_from("H", fcntl.ioctl(
            control, 0x8913, struct.pack("256s", name.encode())), 16)[0] for name in interfaces}
    return {
        "self_netns": os.readlink("/proc/self/ns/net"),
        "init_netns": init_netns,
        "init_netns_source": "root readlink /proc/1/ns/net before unshare; evidence/init-netns",
        "interfaces": interfaces, "flags": flags, "proc_net_dev": dev,
        "proc_net_route": routes, "proc_net_ipv6_route": ipv6_routes, "ipv6_routes": ipv6_rows,
        "route_rule": "No IPv4 routes; IPv6 permits only kernel RTF_REJECT (0x200) entries, which cannot forward traffic.",
    }


def require_isolation(state):
    assert state["self_netns"] != state["init_netns"], "network namespace was not isolated"
    assert state["interfaces"] == ["lo"], "unexpected network interface"
    assert state["flags"]["lo"] & 1 == 0, "loopback is up"
    assert not state["proc_net_route"].splitlines()[1:], "unexpected IPv4 route"
    assert all(row["reject"] for row in state["ipv6_routes"]), "usable IPv6 route present"


def group_members(pgid):
    members = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                if os.getpgid(int(entry.name)) == pgid:
                    members.append(int(entry.name))
            except ProcessLookupError:
                pass
    return members


def terminate_and_reap(process):
    # A leader that has not been reaped retains its PID and owns this group ID.
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)


def readback(snapshot, project, manifest, target):
    result = {}
    mismatches = []
    for relative, expected in manifest["files"].items():
        assert relative.startswith("project/") and ".." not in Path(relative).parts
        original, copied = snapshot / relative, project / Path(relative).relative_to("project")
        actual = {"sha256": digest(copied), "bytes": copied.stat().st_size,
                  "source_mode": expected["mode"], "store_mode": stat.S_IMODE(original.stat().st_mode),
                  "copied_mode": stat.S_IMODE(copied.stat().st_mode)}
        result[relative] = actual
        if (actual["sha256"] != expected["sha256"] or actual["bytes"] != expected["bytes"]
                or actual["copied_mode"] != (actual["store_mode"] | stat.S_IWUSR)
                or bool(actual["store_mode"] & 0o111) != bool(expected["mode"] & 0o111)):
            mismatches.append(relative)
    save(target, result)
    assert not mismatches, {"input_mismatches": mismatches}


def run_command(index, name, argv, cwd, env, evidence, expected_exit=None):
    directory = evidence / f"{index:02d}-{name}"
    directory.mkdir()
    row = {
        "name": name, "argv": argv, "cwd": str(cwd), "env": env,
        "started_at": now(), "timeout_seconds": 60, "expected_exit": expected_exit,
        "stdout": str(directory / "stdout"), "stderr": str(directory / "stderr"),
        "timed_out": False, "reaped": False, "adopted_reaped": [],
    }
    save(directory / "command.json", row)
    started = time.monotonic()
    process = None
    try:
        with (directory / "stdout").open("wb") as stdout, (directory / "stderr").open("wb") as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            row["identity_after_spawn"] = identity(process.pid)
            save(directory / "command.json", row)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                terminate_and_reap(process)
            row.update(returncode=process.returncode, reaped=True)
    except Exception:
        row["error"] = traceback.format_exc()
    finally:
        if process is not None:
            row["remaining_group_before_cleanup"] = group_members(process.pid)
            if not row["reaped"]:
                try:
                    terminate_and_reap(process)
                    row.update(returncode=process.returncode, reaped=True)
                except subprocess.TimeoutExpired:
                    row["cleanup_error"] = "command leader did not reap"
            deadline = time.monotonic() + 3
            while True:
                try:
                    child, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if child:
                    row["adopted_reaped"].append({"pid": child, "returncode": os.waitstatus_to_exitcode(status)})
                elif time.monotonic() < deadline:
                    time.sleep(0.02)
                else:
                    row["cleanup_error"] = "adopted command child remained after cleanup deadline"
                    break
            row["remaining_group_after_cleanup"] = group_members(process.pid)
            if row["remaining_group_after_cleanup"]:
                row["cleanup_error"] = "command descendants remain; VM shutdown required"
        row.update(completed_at=now(), duration_seconds=time.monotonic() - started)
        row["output_sha256"] = {name: digest(directory / name) for name in ("stdout", "stderr")}
        save(directory / "command.json", row)
    return row


def main():
    bindings_path = Path(sys.argv[1])
    bindings = json.loads(bindings_path.read_text())
    evidence, project = Path(bindings["evidence"]), Path(bindings["project"])
    report = {"started_at": now(), "scope": "H01 feasibility only; no qualification or readiness claim", "commands": []}
    exit_status = 1
    try:
        shutil.copyfile(bindings_path, evidence / "bindings.json")
        shutil.copyfile(Path(bindings["snapshot"]) / "MANIFEST.json", evidence / "MANIFEST.json")
        shutil.copyfile(bindings["runtime_manifest"], evidence / "runtime-manifest.json")
        report["inputs"] = {name: digest(evidence / name) for name in ("bindings.json", "MANIFEST.json", "runtime-manifest.json")}
        report["guest_sha256"] = digest(Path(__file__))
        report["identity"] = identity(os.getpid())
        report["env"] = dict(os.environ)
        report["uid"], report["gid"] = os.getuid(), os.getgid()
        assert os.getuid() == os.geteuid() == 1101 and os.getgid() == os.getegid() == 1101
        assert Path("/etc/osbus-h01-guest").read_text().strip() == "isolated-vm"
        init_netns = (evidence / "init-netns").read_text().strip()
        assert init_netns.startswith("net:[") and init_netns.endswith("]"), "missing init network namespace baseline"
        report["network_before"] = network(init_netns)
        require_isolation(report["network_before"])
        # Adopt and reap any children left by a command's own support processes.
        assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, "subreaper setup failed"
        report["child_subreaper"] = True
        snapshot = Path(bindings["snapshot"])
        manifest = json.loads((evidence / "MANIFEST.json").read_text())
        readback(snapshot, project, manifest, evidence / "input-readback-before.json")
        private = {name: evidence / name for name in ("home", "mix-home", "hex-home", "xdg-config", "xdg-cache", "xdg-data", "tmp")}
        for directory in private.values():
            directory.mkdir(mode=0o700)
        env = {
            "PATH": bindings["path"], "HOME": str(private["home"]),
            "MIX_HOME": str(private["mix-home"]), "HEX_HOME": str(private["hex-home"]),
            "XDG_CONFIG_HOME": str(private["xdg-config"]), "XDG_CACHE_HOME": str(private["xdg-cache"]),
            "XDG_DATA_HOME": str(private["xdg-data"]), "TMPDIR": str(private["tmp"]),
            "MIX_ENV": "test", "HEX_OFFLINE": "1", "LANG": "C.UTF-8",
            "ERL_LIBS": bindings["hex"] + "/lib/erlang/lib", "ERL_FLAGS": "+S 2:2 +SDcpu 1 +SDio 1",
        }
        elixir, mix = bindings["elixir"] + "/bin/elixir", bindings["elixir"] + "/bin/mix"
        inspect = 'IO.inspect(%{hex_module: :code.which(Hex), hex_scm: :code.which(Hex.SCM), hex_version: Hex.version(), otp: :erlang.system_info(:otp_release), elixir: System.version()})'
        commands = [
            ("elixir-version", [elixir, "--version"], None),
            ("hex-discovery", [elixir, "-e", inspect], None),
            ("help-deps", [mix, "help", "deps"], None),
            ("help-deps-loadpaths", [mix, "help", "deps.loadpaths"], None),
            ("deps", [mix, "deps"], None),
            ("deps-loadpaths", [mix, "deps.loadpaths", "--no-compile", "--no-path-loading"], None),
        ]
        for index, (name, argv, expected) in enumerate(commands, 1):
            row = run_command(index, name, argv, project, env, evidence, expected)
            report["commands"].append(row)
            assert (row["reaped"] and not row["timed_out"] and not row.get("error")
                    and not row.get("cleanup_error") and not row.get("remaining_group_after_cleanup")), name
        readback(snapshot, project, manifest, evidence / "input-readback-after.json")
        report["input_bytes_unchanged"] = True
        report["network_after"] = network(init_netns)
        require_isolation(report["network_after"])
        report["outcome"] = "bounded-probe-evidence-captured"
        report["command_failures"] = [row["name"] for row in report["commands"] if row["returncode"] != 0]
        report["limitations"] = "Dependency inventory and captured exit statuses do not establish compilation, test, application-start, or H01 acceptance."
        exit_status = 0
    except Exception:
        report.update(outcome="containment-or-evidence-failure", error=traceback.format_exc())
    finally:
        report.update(completed_at=now(), guest_exit_status=exit_status)
        save(evidence / "report.json", report)
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
