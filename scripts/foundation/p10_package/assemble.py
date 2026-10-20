"""Finite VM-only P10 package assembly. Never start a bus or execute its helper."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time


BASE = Path("/var/lib/osbus-p10-package")
ENTRYPOINT = Path("/run/wrappers/bin/dbus-daemon-launch-helper")
SOCKET = Path("/run/dbus/system_bus_socket")
PROFILE = Path("/etc/osbus-p10-package-profile.json")
ROOT_CONFIG = Path("/etc/dbus-1/system.conf")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def bounded(path, maximum, virtual=False):
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "unbounded input: " + str(path))
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    require((virtual or len(data) == before.st_size) and len(data) <= maximum, "short/oversized read")
    require(all(getattr(before, key) == getattr(after, key) for key in keys), "input changed")
    return data


def sha(path):
    return hashlib.sha256(bounded(path, 134_217_728)).hexdigest()


def no_bus():
    require(not os.path.lexists(SOCKET), "canonical socket exists; assembly refused")
    unix = bounded("/proc/net/unix", 1_048_576, virtual=True).decode()
    require(not any(line.split()[-1:] == [str(SOCKET)] for line in unix.splitlines()[1:]),
            "canonical socket is registered; assembly refused")


def isolation(root_installer=True):
    # No subprocess, directory creation, chown, network namespace or other
    # mutation may precede these checks. A denial writes only stderr.
    if root_installer:
        require(os.getuid() == os.geteuid() == 0, "VM stdlib installer must be root")
    else:
        require(os.getresuid() == (1900, 1900, 1900) and os.getresgid() == (1900, 1900, 1900)
                and os.getgroups() == [], "build child retained privileged identity/groups")
    require("osbus.p10-package-builder=1" in bounded("/proc/cmdline", 16_384, virtual=True).decode().split(),
            "dedicated package-image kernel marker missing")
    marker = Path("/etc/osbus-p10-package-builder")
    require(bounded(marker, 128) == b"offline-disposable-image-v1\n", "package-image marker missing")
    info = marker.stat()
    require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022, "untrusted image marker")
    vendor = bounded("/sys/class/dmi/id/sys_vendor", 4096, virtual=True).decode().strip()
    product = bounded("/sys/class/dmi/id/product_name", 4096, virtual=True).decode().strip()
    require(vendor in ("QEMU", "Bochs") or product in ("Standard PC (Q35 + ICH9, 2009)",
                                                    "Standard PC (i440FX + PIIX, 1996)"),
            "dedicated QEMU image required")
    no_bus()


def store_file(path):
    path = Path(path)
    require(str(path).startswith("/nix/store/") and path.is_absolute(), "immutable input required")
    info = path.stat()
    require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022, "untrusted store input")
    return path


def installed(profile):
    helper = store_file(profile["helper"])
    header = store_file(profile["helper_config_header"])
    receipt = json.loads(bounded(store_file(profile["helper_build_receipt"]), 16_384))
    require(receipt == {"helper": str(helper), "helper_sha256": sha(helper),
                        "config_header": str(header), "config_header_sha256": sha(header)},
            "helper and generated config.h are not the same build receipt")
    require(profile["installed_helper_source"] == str(helper), "NixOS wrapper targets another helper")
    require(re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/]+\.drv", profile["helper_derivation"]),
            "helper derivation identity missing")
    roots = re.findall(rb'^#define[ \t]+DBUS_SYSTEM_CONFIG_FILE[ \t]+"([^"\n]+)"[ \t]*$',
                       bounded(header, 1_048_576), re.M)
    require(roots == [str(ROOT_CONFIG).encode()], "unsupported compiled helper configuration root")
    require(ROOT_CONFIG.resolve().is_relative_to(store_file(profile["configuration_directory"])),
            "installed XML is outside NixOS-generated configuration")
    wrappers = re.findall(r'^\s*cp (/nix/store/[^\s]+/bin/security-wrapper) "\$wrapperDir/dbus-daemon-launch-helper"\s*$',
                          profile["wrapper_script"], re.M)
    require(len(wrappers) == 1, "missing/ambiguous generated standard wrapper")
    wrapper = store_file(wrappers[0])
    wrapper_bytes = bounded(wrapper, 33_554_432)
    require(str(helper).encode() + b"\0" in wrapper_bytes, "wrapper fixed helper target missing")
    require(bounded(ENTRYPOINT, 33_554_432) == wrapper_bytes, "installed standard wrapper bytes differ")
    entry = ENTRYPOINT.stat()
    require(entry.st_uid == 0 and entry.st_gid == profile["daemon_gid"] and
            stat.S_IMODE(entry.st_mode) in (0o4550, 0o4750), "installed wrapper metadata differs")
    passwd = bounded("/etc/passwd", 1_048_576)
    group = bounded("/etc/group", 1_048_576)
    accounts = [line.split(b":") for line in passwd.splitlines() if line.split(b":", 1)[0] == profile["daemon"].encode()]
    require(len(accounts) == 1 and int(accounts[0][2]) == profile["daemon_uid"] and
            int(accounts[0][3]) == profile["daemon_gid"], "installed daemon account differs")
    return {"wrapper": str(wrapper), "wrapper_sha256": sha(wrapper),
            "helper_sha256": sha(helper), "helper_config_header_sha256": sha(header),
            "passwd_sha256": hashlib.sha256(passwd).hexdigest(),
            "group_sha256": hashlib.sha256(group).hexdigest(), "entrypoint_mode": stat.S_IMODE(entry.st_mode)}


def normalize(root, uid, gid, directories_writable):
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            require(target.is_relative_to(root.resolve()) or str(target).startswith("/nix/store/"),
                    "package/source symlink escaped")
            os.chown(path, uid, gid, follow_symlinks=False)
        elif stat.S_ISDIR(info.st_mode):
            os.chown(path, uid, gid)
            path.chmod(0o755 if directories_writable else 0o555)
        else:
            require(stat.S_ISREG(info.st_mode) and not stat.S_IMODE(info.st_mode) & 0o6000,
                    "special/privileged build output refused")
            os.chown(path, uid, gid)
            path.chmod(0o555 if info.st_mode & 0o111 else 0o444)


def command(argv, profile, cwd, deadline, log):
    no_bus()
    remaining = deadline - time.monotonic()
    require(remaining > 0, "assembly deadline exhausted")
    env = {"PATH": profile["build_path"], "HOME": str(BASE / "builder/home"),
           "MIX_HOME": str(BASE / "builder/mix"), "HEX_HOME": str(BASE / "builder/hex"),
           "HEX_OFFLINE": "1", "MIX_ENV": "prod", "MIX_DEPS_PATH": str(cwd / "deps"),
           "MIX_REBAR3": profile["rebar3"], "GAO_HELPER_PATH": str(ENTRYPOINT),
           "ERL_FLAGS": "+S 2:2 +SDcpu 1 +SDio 1", "LANG": "C.UTF-8"}
    identity_path = BASE / "builder" / (log.stem + ".identity.json")
    launch = [sys.executable, str(Path(__file__).resolve()), "--exec-child", str(identity_path), *argv]
    with log.open("xb") as output:
        child = None
        try:
            child = subprocess.Popen(launch, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                     user=profile["builder_uid"], group=profile["builder_gid"],
                                     extra_groups=[], start_new_session=True, umask=0o022)
            status = child.wait(timeout=min(remaining, 900))
        finally:
            # A leader may fail or exit successfully while a descendant still
            # holds its process group. Always terminate that owned group and
            # reap the direct child before inspecting status or identity.
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=10)
    require(status == 0, "build command failed; inspect " + str(log))
    actual = json.loads(bounded(identity_path, 16_384))
    require(actual["pid"] == child.pid and actual["uids"] == [1900] * 3 and
            actual["gids"] == [1900] * 3 and actual["supplementary_groups"] == [],
            "successful build child identity was not recorded")
    return actual


def exec_child(arguments):
    isolation(root_installer=False)
    identity_path, *argv = arguments
    require(Path(identity_path).parent == BASE / "builder" and argv, "invalid build child record")
    record = {"pid": os.getpid(), "uids": list(os.getresuid()), "gids": list(os.getresgid()),
              "supplementary_groups": os.getgroups(), "executable": argv[0]}
    with Path(identity_path).open("x") as output:
        json.dump(record, output, sort_keys=True)
        output.write("\n")
    # Same observed non-root process becomes Mix/Elixir; no runuser assertion is
    # substituted for actual IDs. Store tools may not carry setuid/setgid bits.
    executable = store_file(argv[0])
    require(not stat.S_IMODE(executable.stat().st_mode) & 0o6000, "privileged build tool refused")
    os.execve(str(executable), argv, os.environ)


def installed_package(package):
    manifests = list(package.glob("lib/gao_bus-*/priv/helper_binding.json"))
    require(len(manifests) == 1, "fixed installed manifest missing")
    manifest_path = manifests[0]
    manifest = json.loads(bounded(manifest_path, 1_048_576))
    for path in [package, *sorted(package.rglob("*"))]:
        info = path.lstat()
        require(info.st_uid == 0 and (stat.S_ISLNK(info.st_mode) or
                not stat.S_IMODE(info.st_mode) & 0o222), "installed package remains builder-writable")
    for name in ("bridge", "helper", "wrapper_source", "entrypoint"):
        expected = manifest[name]
        path = manifest_path.parent / "gao_helper_bridge" if name == "bridge" else Path(expected["path"])
        require(name != "bridge" or expected["path"] == "gao_helper_bridge", "relocated bridge binding differs")
        info = path.stat()
        require(sha(path) == expected["sha256"] and info.st_uid == expected["uid"] and
                info.st_gid == expected["gid"] and stat.S_IMODE(info.st_mode) == expected["mode"],
                "installed artifact differs from generated manifest: " + name)
    for path, expected in manifest["files"].items():
        require(not os.path.lexists(path) if expected is None else sha(path) == expected,
                "captured installed file changed: " + path)
    for path, expected in manifest["directories"].items():
        require(not os.path.lexists(path) if expected is None else
                sorted(os.listdir(path)) == expected, "captured installed directory changed: " + path)
    return {"artifact_records_checked": 4, "files_checked": len(manifest["files"]),
            "directories_checked": len(manifest["directories"]), "owner": 0,
            "builder_write_bits": False, "runtime_validator": "UNRUN"}


def assemble():
    isolation()
    # Everything below is guarded and VM-local. Existing paths are never reset.
    require(not os.path.lexists(BASE), "existing assembly output must be preserved")
    info = PROFILE.stat()
    require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022 and
            str(PROFILE.resolve()).startswith("/nix/store/"), "untrusted generated profile")
    profile = json.loads(bounded(PROFILE, 1_048_576))
    require(profile["schema"] == 1, "unsupported package profile")
    require(profile["builder_uid"] == profile["builder_gid"] == 1900, "fixed builder account missing")
    original = installed(profile)
    source, dependencies = map(store_file, (profile["source"], profile["dependencies"]))
    require(not any((source / name).exists() for name in (".git", ".trees", "_build", "deps")),
            "a clean source-only immutable snapshot is required")
    archive = store_file(profile["hex_archive"])
    require(sha(archive) == profile["hexArchiveSha256"], "Hex archive digest differs")
    BASE.mkdir(mode=0o755)
    deadline = time.monotonic() + 1800
    report = {"schema": 1, "status": "assembling", "qualification": "UNRUN",
              "profile_sha256": sha(PROFILE), "assembler_sha256": sha(__file__),
              "installed": original, "build_children": []}
    try:
        (BASE / "profile.json").write_bytes(bounded(PROFILE, 1_048_576))
        (BASE / "helper-build-receipt.json").write_bytes(
            bounded(profile["helper_build_receipt"], 16_384))
        # No network is available even to accidental dependency fetch commands.
        require(hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNET"), "network namespace facility missing")
        os.unshare(os.CLONE_NEWNET)
        build = BASE / "builder"
        build.mkdir(mode=0o755)
        work = build / "source"
        shutil.copytree(source, work, symlinks=True)
        shutil.copytree(dependencies, work / "deps", symlinks=True)
        # Source/dependencies need writable build directories; files retain only
        # their source executable bit, with no inherited privileged permissions.
        for path in [build, *sorted(build.rglob("*"))]:
            if path.is_symlink():
                os.chown(path, 1900, 1900, follow_symlinks=False)
            else:
                os.chown(path, 1900, 1900)
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        for name in ("home", "mix", "hex"):
            directory = build / name
            directory.mkdir(mode=0o700)
            os.chown(directory, 1900, 1900)
        for tool in ("mix", "elixir", "rebar3"):
            store_file(profile[tool])
        report["build_children"].append(command(
            [profile["mix"], "archive.install", "--force", str(archive)], profile, work,
            deadline, BASE / "01-hex.log"))
        report["build_children"].append(command(
            [profile["mix"], "compile"], profile, work, deadline, BASE / "02-compile.log"))
        release = build / "release"
        report["build_children"].append(command(
            [profile["mix"], "release", "os_bus", "--path", str(release)], profile, work,
            deadline, BASE / "03-release.log"))
        normalize(release, 1900, 1900, directories_writable=True)
        beams = sorted((release / "lib").glob("*/ebin"))
        require(any(path.parent.name.startswith("gao_bus-") for path in beams), "headless release missing")
        argv = [profile["elixir"]]
        for directory in beams:
            argv += ["-pa", str(directory)]
        argv += [str(work / "scripts/foundation/helper_binding_manifest.exs"),
                 "--helper", profile["helper"], "--helper-config-header", profile["helper_config_header"],
                 "--wrapper-source", original["wrapper"], "--passwd", "/etc/passwd", "--group", "/etc/group",
                 "--daemon", profile["daemon"], "--derivation", profile["helper_derivation"]]
        report["build_children"].append(command(argv, profile, work, deadline, BASE / "04-manifest.log"))
        require(installed(profile) == original, "installed helper/config/accounts changed during assembly")
        manifests = list(release.glob("lib/gao_bus-*/priv/helper_binding.json"))
        require(len(manifests) == 1, "fixed release manifest missing")
        package = BASE / "release"
        release.rename(package)
        normalize(package, 0, 0, directories_writable=False)
        report["installation_inventory"] = installed_package(package)
        manifest = next(package.glob("lib/gao_bus-*/priv/helper_binding.json"))
        report.update(status="assembled-unqualified", manifest_sha256=sha(manifest),
                      manifest=str(manifest.relative_to(BASE)),
                      producer_provenance=json.loads(bounded(str(manifest) + ".provenance.json", 1_048_576)),
                      helper_derivation=profile["helper_derivation"], source=profile["source"],
                      source_nar_hash=profile["sourceNarHash"], dependencies=profile["dependencies"],
                      dependencies_nar_hash=profile["depsNarHash"], pinned=profile["pinned"],
                      stable_pinned=profile["stablePinned"], endpoint="unix:path=/run/dbus/system_bus_socket")
        # Preserve all build logs and exact inputs. No service/socket start,
        # helper execution, runtime acceptance or publication occurs here.
        no_bus()
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (BASE / "assembly.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--exec-child"]:
            exec_child(sys.argv[2:])
        else:
            require(len(sys.argv) == 1, "assembly takes no caller-selected paths or commands")
            assemble()
    except BaseException as error:
        print("P10 offline package assembly refused/failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
