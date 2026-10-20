"""Offline current-candidate binding for the previously executed complete corpus."""
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
CORPUS_SHA = '7cca46b15337e01485482092bc6ed8ae70880baa1f75955a9cce9004119dcdbe'
OLD_MANIFEST = '372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'
OLD_SOURCE = 'efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'
FIXTURE_COUNT = 21
PATCHED_INPUT_SHA = {'contract.py': '01d832829e25aee5410a47f69f39661eac5028e5111745946861973ed3b8e209', 'test.nix': '88399e37d6294b0b59142842ea91b7efa69b865f7817b7978d73289603ea1f66'}


def patch_bindings(name, source):
    assert hashlib.sha256(source).hexdigest() == PATCHED_INPUT_SHA[name], name
    replacements = [(OLD_MANIFEST.encode(), CANDIDATE_SHA.encode()),
                    (OLD_SOURCE.encode(), SOURCE_SHA.encode())]
    patched = source
    for before, after in replacements:
        assert patched.count(before) == 1 and after not in patched
        patched = patched.replace(before, after)
    restored = patched
    for before, after in reversed(replacements):
        assert restored.count(after) == 1
        restored = restored.replace(after, before)
    assert restored == source
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

    names = set(corpus['fixture_files'])
    expected_rows = {}
    for name in names:
        expected_rows[name], = [pin for path, pin in corpus['files'].items()
                               if path.endswith('/source3/fixture2/' + name)]
    assert len(names) == FIXTURE_COUNT and leaves(fixtures) == names
    fixture_rows = {}
    for name in sorted(names):
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        expected = expected_rows[name]
        observed = row(fixtures / name)
        assert observed['sha256'] == expected['sha256'] and observed['bytes'] == expected['bytes'], name
        assert observed['mode'] == expected['mode'] & ~0o222, name
        fixture_rows[name] = observed
    output.mkdir()
    copied = output / 'fixtures'
    shutil.copytree(fixtures, copied)
    provenance = {}
    for name in ('contract.py', 'test.nix'):
        target = copied / name
        original = target.read_bytes()
        corrected = patch_bindings(name, original)
        try:
            target.chmod(fixture_rows[name]['mode'] | stat.S_IWUSR)
            target.write_bytes(corrected)
        finally:
            target.chmod(fixture_rows[name]['mode'])
        assert target.read_bytes() == corrected
        provenance[name] = dict(origin=str(fixtures / name), before=fixture_rows[name], after=row(target),
            replacements=[dict(original=OLD_MANIFEST, replacement=CANDIDATE_SHA),
                          dict(original=OLD_SOURCE, replacement=SOURCE_SHA)],
            reversible_byte_change=True)
    assert leaves(copied) == names
    for name in names - set(provenance):
        assert row(copied / name) == fixture_rows[name], name
        assert (copied / name).read_bytes() == (fixtures / name).read_bytes(), name
    bindings = dict(adapter_revision=1, adapter=row(Path(__file__)),
        candidate_store=str(candidate), candidate_manifest_sha256=CANDIDATE_SHA,
        candidate_source_sha256=SOURCE_SHA, candidate_manifest=manifest, candidate_files=candidate_rows,
        artifact_store=str(artifact), artifact_sha256=ARTIFACT_SHA,
        runtime_store=str(runtime_path), runtime_sha256=RUNTIME_SHA,
        corpus_store=str(corpus_path), corpus_manifest_sha256=CORPUS_SHA,
        fixtures_store=str(fixtures), fixture_inputs=fixture_rows, patch_provenance=provenance,
        fixture_files_unchanged=FIXTURE_COUNT - 2, runnable_files_unchanged=80,
        assertions_identities_deadlines_workload_policy_unchanged=True,
        product_qualified=False, not_a_release=True)
    (output / 'bindings.json').write_text(json.dumps(bindings, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    assert len(sys.argv) == 7 and sys.dont_write_bytecode and sys.flags.optimize == 0
    normalize(*(Path(value) for value in sys.argv[1:]))
