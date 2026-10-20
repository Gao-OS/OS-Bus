"""Check the production coordinator/worker in a private fixture application."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
FIXTURES = Path(__file__).resolve().parent
APP = ROOT / "_build/test/lib/gao_bus"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence = {"suites": []}
    with tempfile.TemporaryDirectory(prefix="gao-helper-coordinator-") as temporary:
        directory = Path(temporary)
        app = directory / "gao_bus"
        shutil.copytree(APP / "ebin", app / "ebin")
        (app / "priv").mkdir()
        shutil.copyfile(APP / "priv/gao_unix.so", app / "priv/gao_unix.so")
        evidence["production_artifacts"] = {
            str(path.relative_to(APP)): digest(path)
            for path in sorted([*APP.joinpath("ebin").glob("*"), APP / "priv/gao_unix.so"])
            if path.is_file()
        }
        for relative, expected in evidence["production_artifacts"].items():
            assert digest(app / relative) == expected
        actor = directory / "actor"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        f'-DFIXTURE_DIRECTORY="{directory}"',
                        str(FIXTURES / "helper_bridge_actor.c"), "-o", str(actor)], check=True)
        for kind, source, defines in [
            ("real", ROOT / "apps/gao_bus/c_src/gao_helper_bridge.c",
             [f'-DGAO_HELPER_PATH="{actor}"']),
            ("protocol", FIXTURES / "helper_worker_protocol_actor.c", [])
        ]:
            bridge = app / "priv/gao_helper_bridge"
            subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            *defines, str(source), "-o", str(bridge)], check=True)
            environment = dict(os.environ)
            environment.update(ERL_FLAGS="+S 4:4", GAO_HELPER_FIXTURE_PRIV=str(app / "priv"),
                               GAO_HELPER_COORDINATOR_SUITE=kind)
            environment["PATH"] = str(ROOT / ".devenv/profile/bin") + ":" + environment["PATH"]
            command = ["elixir", "-pa", str(app / "ebin"),
                       "-pa", str(ROOT / "_build/test/lib/ex_d_bus/ebin"),
                       str(FIXTURES / "helper_coordinator_check.exs")]
            completed = subprocess.run(command, cwd=ROOT, env=environment, timeout=45)
            evidence["suites"].append({"kind": kind, "exit_status": completed.returncode,
                                       "bridge_sha256": digest(bridge)})
    print(json.dumps(evidence, indent=2))
    raise SystemExit(1 if any(suite["exit_status"] for suite in evidence["suites"]) else 0)


if __name__ == "__main__":
    main()
