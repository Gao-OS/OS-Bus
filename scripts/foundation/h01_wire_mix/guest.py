#!/usr/bin/env python3
"""Scoped command sequence using the immutable H01 guest containment helpers."""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

def main():
    bindings_path = Path(sys.argv[1])
    bindings = json.loads(bindings_path.read_text())
    helper = Path(bindings["base_guest"])
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == "1e206497313038fd07328a316f5a19d840e69a4383d63d74557afb7e0e3aaecb"
    spec = importlib.util.spec_from_file_location("h01_immutable_guest_helpers", helper)
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    globals().update({name: getattr(original, name) for name in
                      ("now", "save", "digest", "identity", "network", "require_isolation", "readback", "run_command")})
    evidence, project = Path(bindings["evidence"]), Path(bindings["project"])
    report = {"started_at": now(), "scope": "Partial H01 normal Mix wire baseline; not full H01 acceptance", "commands": []}
    exit_status = 1
    try:
        shutil.copyfile(bindings_path, evidence / "bindings.json")
        shutil.copyfile(Path(bindings["snapshot"]) / "MANIFEST.json", evidence / "MANIFEST.json")
        shutil.copyfile(bindings["runtime_manifest"], evidence / "runtime-manifest.json")
        shutil.copyfile(Path(bindings["snapshot"]) / "COMMANDS.json", evidence / "COMMANDS.json")
        report["inputs"] = {name: digest(evidence / name) for name in ("bindings.json", "MANIFEST.json", "runtime-manifest.json", "COMMANDS.json")}
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
        cwd = project / "apps/ex_d_bus"
        assert not (project / "_build").exists() and not (cwd / "_build").exists(), "build directory is not clean"
        selection = json.loads((snapshot / "COMMANDS.json").read_text())
        commands = [
            ("elixir-version", [elixir, "--version"]),
            ("hex-discovery", [elixir, "-e", inspect]),
            ("help-compile", [mix, "help", "compile"]),
            ("help-test", [mix, "help", "test"]),
            ("help-format", [mix, "help", "format"]),
            ("compile", [mix, "compile", "--warnings-as-errors"]),
            ("format", [mix, "format", "--check-formatted"] + selection["format_paths"]),
            ("wire-tests", [mix, "test", "--no-start", "--seed", "4321", "test/wire"]),
        ]
        check_failure = None
        for index, (name, argv) in enumerate(commands, 1):
            row = run_command(index, name, argv, cwd, env, evidence, 0)
            report["commands"].append(row)
            assert (row["reaped"] and not row.get("error")
                    and not row.get("cleanup_error") and not row.get("remaining_group_after_cleanup")), name
            if row["timed_out"] or row["returncode"] != 0:
                check_failure = name
                break
        report["stopped_after_first_failed_check"] = check_failure
        report["not_run"] = [name for name, _ in commands[len(report["commands"]):]]
        readback(snapshot, project, manifest, evidence / "input-readback-after.json")
        report["input_bytes_unchanged"] = True
        report["network_after"] = network(init_netns)
        require_isolation(report["network_after"])
        report["outcome"] = "command-check-failure" if check_failure else "scoped-wire-mix-checks-passed"
        report["command_failures"] = [row["name"] for row in report["commands"] if row["timed_out"] or row["returncode"] != 0]
        report["limitations"] = "Only the scoped normal Mix compile/format/wire suite is covered; no full H01/precommit, bus, application-start or replacement acceptance."
        exit_status = 2 if check_failure else 0
    except Exception:
        report.update(outcome="containment-or-evidence-failure", error=traceback.format_exc())
    finally:
        report.update(completed_at=now(), guest_exit_status=exit_status)
        save(evidence / "report.json", report)
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
