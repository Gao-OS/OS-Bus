"""Run the exact production worker BEAM against a private harmless bridge."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
FIXTURES = Path(__file__).resolve().parent
APP = ROOT / "_build/test/lib/gao_bus"
EXDBUS = ROOT / "_build/test/lib/ex_d_bus/ebin"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    selected = set(sys.argv[1:] or ["real", "protocol"])
    assert selected <= {"real", "protocol"}, "unknown suite selection"
    binding = {"production_worker_beam_sha256": digest(APP / "ebin/Elixir.GaoBus.Activation.HelperWorker.beam"),
               "production_worker_source_sha256": digest(ROOT / "apps/gao_bus/lib/gao_bus/activation/helper_worker.ex"),
               "bridge_source_sha256": digest(ROOT / "apps/gao_bus/c_src/gao_helper_bridge.c"),
               "suites": []}
    with tempfile.TemporaryDirectory(prefix="gao-helper-worker-") as temporary:
        directory = Path(temporary)
        app = directory / "gao_bus"
        shutil.copytree(APP / "ebin", app / "ebin")
        (app / "priv").mkdir()
        copied = app / "ebin/Elixir.GaoBus.Activation.HelperWorker.beam"
        assert digest(copied) == binding["production_worker_beam_sha256"]
        for label, suite, sources, defines in [
            ("real", "helper_worker_check.exs", [ROOT / "apps/gao_bus/c_src/gao_helper_bridge.c"], []),
            ("protocol", "helper_worker_protocol_check.exs", [FIXTURES / "helper_worker_protocol_actor.c"], [])]:
            if label not in selected:
                continue
            actor = directory / "actor"
            if label == "real":
                subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                f'-DFIXTURE_DIRECTORY="{directory}"', str(FIXTURES / "helper_bridge_actor.c"),
                                "-o", str(actor)], check=True)
                defines = [f'-DGAO_HELPER_PATH="{actor}"']
            bridge = app / "priv/gao_helper_bridge"
            subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            *defines, *map(str, sources), "-o", str(bridge)], check=True)
            environment = dict(os.environ)
            environment["PATH"] = str(ROOT / ".devenv/profile/bin") + ":" + environment["PATH"]
            environment["ERL_FLAGS"] = "+S 4:4"
            environment["GAO_HELPER_FIXTURE_PRIV"] = str(app / "priv")
            completed = subprocess.run(["elixir", "-pa", str(app / "ebin"), "-pa", str(EXDBUS),
                                        str(FIXTURES / suite)], cwd=ROOT, env=environment, timeout=60)
            binding["suites"].append({"name": label, "status": completed.returncode,
                                      "fixture_bridge_sha256": digest(bridge)})
            if completed.returncode:
                print(json.dumps(binding, indent=2))
                raise SystemExit(completed.returncode)
    print(json.dumps(binding, indent=2))


if __name__ == "__main__":
    main()
