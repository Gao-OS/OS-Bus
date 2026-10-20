"""Verify current immutable product metadata and rebind the existing PRO03 fixture."""
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
CORPUS_SHA = "67c242dca990713e54bd9a635533b7803a2f307fe7ef04c24d72359cae16cb6f"
OLD_MANIFEST = "MANIFEST_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'"
OLD_SOURCE = "SOURCE_SHA = '4e334b95bc0ddd0afed797f9640c6971ba2a339c2a369f6500a0d7230d9e8350'"
RUNNER_SHA = "84e53fa3d40bc9ebe620aa4fdf9bfbfde52826d0b526fe696fbc76978137a405"
PERSISTENCE_REPLACEMENTS = [
    (b"                current['receipts'].append(receipt)\n                persist()\n                assert time.monotonic()",
     b"                current['receipts'].append(receipt)\n                assert time.monotonic()"),
    (b"                        snapshot_start=snapshot_start, snapshot_end=len(current['snapshots'])))\n                    persist()\n\n            def positive(observer, flow):",
     b"                        snapshot_start=snapshot_start, snapshot_end=len(current['snapshots'])))\n\n            def positive(observer, flow):"),
]


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


def patch_runner(original):
    """Keep timed observations in memory; existing safe boundaries flush them."""
    assert hashlib.sha256(original).hexdigest() == RUNNER_SHA, "PRO03 runner drift"
    patched = original
    for before, after in PERSISTENCE_REPLACEMENTS:
        assert patched.count(before) == 1 and after not in patched
        patched = patched.replace(before, after)
    restored = patched
    for before, after in reversed(PERSISTENCE_REPLACEMENTS):
        assert restored.count(after) == 1
        restored = restored.replace(after, before)
    assert restored == original
    return patched


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

    fixture_pins = {name.removeprefix("fixture1/"): pin
                    for name, pin in corpus["files"].items() if name.startswith("fixture1/")}
    assert len(fixture_pins) == 22
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
    patched_runner = patch_runner(runner.read_bytes())
    runner.chmod(0o644)
    runner.write_bytes(patched_runner)
    runner.chmod(fixture_rows["run.py"]["mode"])
    assert runner.read_bytes() == patched_runner
    assert leaves(copied) == leaves(fixtures)
    for name in set(fixture_rows) - {"contract.py", "run.py"}:
        assert row(copied / name) == fixture_rows[name], name
        assert (copied / name).read_bytes() == (fixtures / name).read_bytes(), name
    bindings = dict(
        adapter_revision=3, adapter=row(Path(__file__)),
        candidate_store=str(candidate), candidate_manifest_sha256=CANDIDATE_SHA,
        candidate_source_sha256=SOURCE_SHA, candidate_manifest=manifest,
        candidate_files=candidate_rows,
        artifact_store=str(artifact), artifact_sha256=ARTIFACT_SHA,
        runtime_store=str(runtime_path), runtime_sha256=RUNTIME_SHA,
        corpus_store=str(corpus_path), corpus_manifest_sha256=CORPUS_SHA,
        fixtures_store=str(fixtures), fixture_inputs=fixture_rows,
        patched_contract=row(contract),
        patched_runner=row(runner),
        patch_provenance=dict(origin=str(fixtures / "contract.py"),
                              before=fixture_rows["contract.py"], after=row(contract),
                              assignments=[dict(original=before.decode(), replacement=after.decode())
                                           for before, after in replacements],
                              reversible_byte_change=True),
        persistence_patch_provenance=dict(origin=str(fixtures / "run.py"),
            before=fixture_rows["run.py"], after=row(runner),
            replacements=[dict(original=before.decode(), replacement=after.decode())
                          for before, after in PERSISTENCE_REPLACEMENTS],
            reversible_byte_change=True,
            flush_boundaries="existing case/backend success, exception and finally"),
        fixture_files_unchanged=20, runnable_files_unchanged=80,
        cases_per_backend=8, corpus_pairs=16, positive_controls_per_backend=2,
        product_qualified=False, not_a_release=True)
    (output / "bindings.json").write_text(json.dumps(bindings, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    assert len(sys.argv) == 7 and sys.dont_write_bytecode and sys.flags.optimize == 0
    normalize(*(Path(value) for value in sys.argv[1:]))
