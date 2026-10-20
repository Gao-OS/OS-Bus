"""Bind the accepted native RES01 and UID controllers to the current product."""
import hashlib
import json
from pathlib import Path
import stat
import sys

ARTIFACT_SHA = "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1"
RUNTIME_SHA = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5"
CANDIDATE_SHA = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82"
SOURCE_SHA = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c"
HERE = Path(__file__).resolve().parent


def row(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode), path
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                sha256=hashlib.sha256(data).hexdigest())


def leaves(root):
    paths = list(root.rglob("*"))
    assert not any(path.is_symlink() for path in paths), root
    return {path.relative_to(root).as_posix() for path in paths if path.is_file()}


def normalize(candidate, artifact, runtime_path, sources, output):
    assert not output.exists(), output
    assert row(candidate / "candidate.json")["sha256"] == CANDIDATE_SHA
    assert row(artifact / "artifact.json")["sha256"] == ARTIFACT_SHA
    assert row(runtime_path)["sha256"] == RUNTIME_SHA
    manifest = json.loads((candidate / "candidate.json").read_text())
    product = json.loads((artifact / "artifact.json").read_text())
    runtime = json.loads(runtime_path.read_text())
    assert manifest["not_a_release"] and product["not_a_release"] and runtime["not_a_release"]
    assert product["origin_pin"]["sha256"] == RUNTIME_SHA
    assert manifest["runtime"] == runtime["runtime"]
    product_sources = {name: pin["sha256"] for name, pin in product["sources"].items()}
    assert manifest["sources"] == product_sources
    assert hashlib.sha256(json.dumps(product_sources, sort_keys=True).encode()).hexdigest() == SOURCE_SHA
    assert manifest["source_sha256"] == SOURCE_SHA
    assert set(product_sources) == set(runtime["sources"])
    assert manifest["source_beams"] == runtime["source_beams"]
    assert (len(product_sources), len(manifest["source_beams"]),
            sum(map(len, manifest["source_beams"].values())), len(product["files"])) == (71, 57, 61, 80)
    assert set(manifest["source_beams"]) <= set(product_sources)
    assert all("lib/" + beam in product["files"]
               for beams in manifest["source_beams"].values() for beam in beams)
    assert manifest["files"] == {name: pin["sha256"] for name, pin in product["files"].items()}
    assert manifest["file_modes"] == {name: pin["mode"] for name, pin in product["files"].items()}
    assert leaves(candidate) == set(product["files"]) | {"candidate.json"}
    assert leaves(artifact) == set(product["files"]) | {"artifact.json"}
    candidate_rows = {}
    for name, expected in product["files"].items():
        assert name.startswith("lib/") and ".." not in Path(name).parts
        observed = row(candidate / name)
        assert observed == row(artifact / name), name
        assert (candidate / name).read_bytes() == (artifact / name).read_bytes(), name
        assert observed["sha256"] == expected["sha256"] and observed["bytes"] == expected["bytes"]
        assert observed["mode"] == expected["mode"] & ~0o222
        candidate_rows[name] = observed

    pins = json.loads((HERE / "inputs.json").read_text())
    assert leaves(sources) == {pin["path"] for pin in pins.values()}
    input_rows = {}
    for key, pin in pins.items():
        path = sources / pin["path"]
        observed = row(path)
        assert observed == dict(bytes=pin["bytes"], mode=pin["mode"] & ~0o222,
                                sha256=pin["sha256"]), key
        input_rows[key] = observed

    def read(key):
        return (sources / pins[key]["path"]).read_bytes()

    historical = json.loads(read("base_bindings"))
    for name, pin in historical.items():
        key = name if name.startswith("original/") else "res01/" + name
        assert pins[key]["sha256"] == pin["sha256"] and pins[key]["bytes"] == pin["bytes"]

    acceptance = json.loads(read("res01_acceptance"))
    assert acceptance["status"] == "ACCEPTED_DIAGNOSTIC_NATIVE_RES01_EIGHT_DIMENSIONS"
    assert acceptance["independent_saved_evidence_review_accepted"] is True
    assert acceptance["counts"] == dict(selected=8, executed=8, passed=8, failed=0, blocked=0, skipped=0)
    assert b"ACCEPT_SCOPED_UID_VM2_EVIDENCE_V1" in read("uid_review")

    # Start from the actually accepted transformed controller, then undo only its
    # recorded timing instrumentation. Exact reversal proves all trials, checks,
    # policies, persistence deferral, clocks and cleanup remain the original ones.
    recipes = json.loads(read("recipe"))
    accepted_runner = read("accepted_runner")
    runner = accepted_runner
    for change in reversed(recipes["runner"]):
        before, after = change["before"].encode(), change["after"].encode()
        assert runner.count(after) == change["count"], after
        runner = runner.replace(after, before)
    assert runner == read("res01/run.py")
    replay = runner
    for change in recipes["runner"]:
        before, after = change["before"].encode(), change["after"].encode()
        assert replay.count(before) == change["count"]
        replay = replay.replace(before, after)
    assert replay == accepted_runner

    # Preserve the accepted compiled mapping setup verbatim. Its only serializer
    # correction is the pinned ref_to_list branch; the runner's #Ref predicate is
    # unchanged. Compilation still occurs inside the original authority clock.
    accepted_launcher = read("accepted_launcher")
    begin = b"# COMPILED_MAPPING_SETUP_BEGIN\n"
    end = b"# COMPILED_MAPPING_SETUP_END\n"
    assert accepted_launcher.count(begin) == accepted_launcher.count(end) == 1
    setup = accepted_launcher.split(begin)[1].split(end)[0]
    launcher = (b'# Direct accepted compiled mapper; original daemon remains pinned.\n'
                b'here = __DIR__\n'
                b'source = File.read!(Path.join(here, "base-launcher.exs"))\n'
                b'digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end\n'
                b'unless digest.(source) == "0ed30bbe2a8b7a412f023afb78d2c8987064738bb5ab788323ba9eb41ccfda65", do: raise("base launcher drift")\n'
                + setup
                + b'Code.eval_string(mapping_source, [], file: Path.join(here, "base-launcher.exs"))\n')
    mapping = json.loads(read("mapping_bindings"))
    assert mapping["helper_source_sha256"] == input_rows["mapper_corrected"]["sha256"]
    assert mapping["original_anchor_source_sha256"] == input_rows["mapper_original"]["sha256"]
    anchor = read("mapper_original")
    assert read("res01/launcher.exs").count(anchor) == 1
    assert b"is_reference(value) -> List.to_string(:erlang.ref_to_list(value))" in read("mapper_corrected")

    output.mkdir()
    res01 = output / "res01"
    uid = output / "uid"
    original = output / "original"
    for directory in (res01, uid, original):
        directory.mkdir()

    def write(path, data):
        path.write_bytes(data)
        path.chmod(0o444)

    write(res01 / "run.py", runner)
    write(res01 / "launcher.exs", launcher)
    write(res01 / "base-launcher.exs", read("res01/launcher.exs"))
    for key, name in (("mapper_original", "mapper-helper.exs"),
                      ("mapper_corrected", "mapper-helper2.exs"),
                      ("mapping_bindings", "MAPPING_BINDINGS1.json")):
        write(res01 / name, read(key))
    for name in ("actor.py", "cleanup.py", "workload.json"):
        write(res01 / name, read("res01/" + name))
    for name in ("run.py", "launcher.exs"):
        write(uid / name, read("uid/" + name))
    for key in pins:
        if key.startswith("original/"):
            write(original / key.split("/", 1)[1], read(key))
    write(output / "contract.py", (HERE / "contract.py").read_bytes())
    write(output / "inputs.json", (HERE / "inputs.json").read_bytes())
    fixtures = {name: row(output / name) for name in sorted(leaves(output))}
    bindings = dict(adapter_revision=2, adapter=row(Path(__file__)),
                    candidate_store=str(candidate), candidate_manifest_sha256=CANDIDATE_SHA,
                    candidate_source_sha256=SOURCE_SHA, candidate_manifest=manifest,
                    candidate_files=candidate_rows, artifact_store=str(artifact),
                    artifact_sha256=ARTIFACT_SHA, runtime_store=str(runtime_path),
                    runtime_sha256=RUNTIME_SHA, source_store=str(sources),
                    input_files=input_rows, fixture_files=fixtures,
                    derivation=dict(accepted_runner_sha256=input_rows["accepted_runner"]["sha256"],
                                    timing_recipe_reversed=True, exact_base_runner=True,
                                    runner_replay_equals_accepted=True,
                                    accepted_compiled_setup_preserved=True,
                                    compiled_setup_sha256=hashlib.sha256(setup).hexdigest(),
                                    reference_fn_ast_sha256=mapping["fn_ast_sha256"],
                                    authority_deadline_reset=False),
                    selected_native_dimensions=10, independent_daemon_phases=2,
                    runnable_files_unchanged=80, reference_executed=False,
                    full_RES01_qualified=False, product_qualified=False, not_a_release=True)
    write(output / "bindings.json", (json.dumps(bindings, indent=2, sort_keys=True) + "\n").encode())


if __name__ == "__main__":
    assert len(sys.argv) == 6 and sys.dont_write_bytecode and sys.flags.optimize == 0
    normalize(*(Path(value) for value in sys.argv[1:]))

