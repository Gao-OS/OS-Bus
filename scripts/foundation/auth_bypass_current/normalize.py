"""Verify current immutable product metadata and rebind the accepted SEC04 fixture."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

ARTIFACT_SHA = "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1"
RUNTIME_SHA = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5"
CANDIDATE_SHA = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82"
SOURCE_SHA = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c"
CORPUS_SHA = "d574c6b62b7c6fa3005b1170286bbc2d0dd619457c22f7a50eb131cf6757c206"
OLD_MANIFEST = "MANIFEST_SHA = '372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'"
OLD_SOURCE = "SOURCE_SHA = 'efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'"
RUNNER_SHA = "a61cdc9721d307fe64c998b6ff9b2ea951171d60bdf7db2642025b13e80e6c53"
OLD_REQUEST_BLOCK = b"""                response = worker['channel'].read(timeout=remaining(limit))
                receipt = dict(identity=worker['public']['identity'], request=command,
                               response=response, elapsed_ms=(time.monotonic()-began)*1000)
                current['receipts'].append(receipt)
                persist()
                assert time.monotonic() <= limit, 'SEC04 request exceeded fixed caller deadline'
                assert response['ok'] is True, response
                return response
"""
NEW_REQUEST_BLOCK = b"""                response = worker['channel'].read(timeout=remaining(limit))
                received = time.monotonic()
                try:
                    assert received <= limit, 'SEC04 request exceeded fixed caller deadline'
                    assert response['ok'] is True, response
                    return response
                finally:
                    receipt = dict(identity=worker['public']['identity'], request=command,
                                   response=response, elapsed_ms=(received-began)*1000)
                    current['receipts'].append(receipt)
"""


def patch_runner(original):
    assert hashlib.sha256(original).hexdigest() == RUNNER_SHA, 'SEC04 donor runner drift'
    assert original.count(OLD_REQUEST_BLOCK) == 1 and NEW_REQUEST_BLOCK not in original
    patched = original.replace(OLD_REQUEST_BLOCK, NEW_REQUEST_BLOCK)
    assert patched.count(NEW_REQUEST_BLOCK) == 1
    assert patched.replace(NEW_REQUEST_BLOCK, OLD_REQUEST_BLOCK) == original
    return patched


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


def normalize(candidate, artifact, runtime_path, fixtures, corpus_path, output):
    assert not output.exists(), output
    assert row(candidate / "candidate.json")["sha256"] == CANDIDATE_SHA
    assert row(artifact / "artifact.json")["sha256"] == ARTIFACT_SHA
    assert row(runtime_path)["sha256"] == RUNTIME_SHA
    assert row(corpus_path)["sha256"] == CORPUS_SHA
    manifest = json.loads((candidate / "candidate.json").read_text())
    product = json.loads((artifact / "artifact.json").read_text())
    runtime = json.loads(runtime_path.read_text())
    corpus = json.loads(corpus_path.read_text())
    assert manifest["not_a_release"] and product["not_a_release"] and runtime["not_a_release"]
    assert product["origin_pin"]["sha256"] == RUNTIME_SHA
    assert manifest["runtime"] == runtime["runtime"]
    sources = {name: pin["sha256"] for name, pin in product["sources"].items()}
    assert manifest["sources"] == sources
    assert hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest() == SOURCE_SHA
    assert manifest["source_sha256"] == SOURCE_SHA
    assert set(sources) == set(runtime["sources"])
    assert manifest["source_beams"] == runtime["source_beams"]
    assert (len(sources), len(manifest["source_beams"]),
            sum(map(len, manifest["source_beams"].values())), len(product["files"])) == (71, 57, 61, 80)
    assert set(manifest["source_beams"]) <= set(sources)
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

    fixture_pins = {}
    assert len(corpus["fixture_files"]) == 20
    for name in corpus["fixture_files"]:
        expected, = [pin for path, pin in corpus["files"].items()
                     if path.endswith("/m1-sec04-complete1/source1/fixture1/" + name)]
        fixture_pins[name] = expected
    assert len(fixture_pins) == 20
    assert leaves(fixtures) == set(fixture_pins)
    fixture_rows = {}
    for name, expected in sorted(fixture_pins.items()):
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        observed = row(fixtures / name)
        assert observed["sha256"] == expected["sha256"] and observed["bytes"] == expected["bytes"]
        assert observed["mode"] == expected["mode"] & ~0o222
        fixture_rows[name] = observed

    output.mkdir()
    copied = output / "fixtures"
    shutil.copytree(fixtures, copied)
    contract = copied / "contract.py"
    original = contract.read_bytes()
    replacements = [(OLD_MANIFEST.encode(), f"MANIFEST_SHA = '{CANDIDATE_SHA}'".encode()),
                    (OLD_SOURCE.encode(), f"SOURCE_SHA = '{SOURCE_SHA}'".encode())]
    patched = original
    for before, after in replacements:
        assert patched.count(before) == 1 and after not in patched
        patched = patched.replace(before, after)
    restored = patched
    for before, after in reversed(replacements):
        assert restored.count(after) == 1
        restored = restored.replace(after, before)
    assert restored == original
    contract.chmod(0o644)
    contract.write_bytes(patched)
    contract.chmod(fixture_rows["contract.py"]["mode"])
    assert contract.read_bytes() == patched
    runner = copied / "run.py"
    original_runner = runner.read_bytes()
    patched_runner = patch_runner(original_runner)
    runner.chmod(0o644)
    runner.write_bytes(patched_runner)
    runner.chmod(fixture_rows["run.py"]["mode"])
    assert runner.read_bytes() == patched_runner
    assert leaves(copied) == leaves(fixtures)
    for name in set(fixture_rows) - {"contract.py", "run.py"}:
        assert row(copied / name) == fixture_rows[name], name
        assert (copied / name).read_bytes() == (fixtures / name).read_bytes(), name
    bindings = dict(
        adapter_revision=4, adapter=row(Path(__file__)),
        candidate_store=str(candidate), candidate_manifest_sha256=CANDIDATE_SHA,
        candidate_source_sha256=SOURCE_SHA, candidate_manifest=manifest,
        candidate_files=candidate_rows,
        artifact_store=str(artifact), artifact_sha256=ARTIFACT_SHA,
        runtime_store=str(runtime_path), runtime_sha256=RUNTIME_SHA,
        corpus_store=str(corpus_path), corpus_manifest_sha256=CORPUS_SHA,
        fixtures_store=str(fixtures), fixture_inputs=fixture_rows,
        patched_contract=row(contract),
        patched_run=row(runner),
        patch_provenance=dict(origin=str(fixtures / "contract.py"),
                              before=fixture_rows["contract.py"], after=row(contract),
                              assignments=[dict(original=before.decode(), replacement=after.decode())
                                           for before, after in replacements],
                              reversible_byte_change=True),
        runner_patch_provenance=dict(origin=str(fixtures / "run.py"),
                                     before=fixture_rows["run.py"], after=row(runner),
                                     original=OLD_REQUEST_BLOCK.decode(),
                                     replacement=NEW_REQUEST_BLOCK.decode(),
                                     replacement_count=1, reversible_byte_change=True,
                                     response_deadline_checked_before_persistence=True,
                                     receipt_persisted_on_assertion_failure=True,
                                     per_request_full_graph_persistence=False,
                                     persistence_at_original_enclosing_boundaries=True,
                                     numerical_bounds_unchanged=True),
        fixture_files_unchanged=18, runnable_files_unchanged=80,
        cases_per_backend=5, corpus_pairs=10, positive_controls_per_backend=2,
        actors_per_backend=8, total_actors=16,
        product_qualified=False, not_a_release=True)
    (output / "bindings.json").write_text(json.dumps(bindings, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError("Run with -B and without Python optimization")
    assert len(sys.argv) == 7
    normalize(*(Path(value) for value in sys.argv[1:]))
