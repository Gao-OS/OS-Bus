"""Create only RES02 identity metadata; never import or run the donor fixture."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

BASELINE = '7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4'
CORPUS_SHA = '4ecd9caef208b1e05d5d4f5994ce2360485c9235d729f9cfd368a1e69eb05c3f'
ARTIFACT_SHA = 'b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1'
RUNTIME_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
INPUT_SHA = 'fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82'
MANIFEST_SHA = 'e4b26b031c0a70a330dbafe9285c605dd3c15d291894ddc33d8b15e71125f06c'
SOURCE_SHA = 'f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c'
OLD_MANIFEST = '372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'
OLD_SOURCE = 'efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'
CHANGED = {'contract.py', 'workload.json', 'test.nix'}


def row(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), path
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                sha256=hashlib.sha256(data).hexdigest())


def inventory(root):
    paths = list(root.rglob('*'))
    assert not any(path.is_symlink() for path in paths), root
    assert all(path.is_dir() or stat.S_ISREG(path.lstat().st_mode) for path in paths), root
    return {path.relative_to(root).as_posix(): row(path)
            for path in sorted(paths) if path.is_file()}


def materialize(candidate, runtime_path, artifact, corpus_path, fixture, output):
    assert not output.exists() and not output.is_symlink(), output
    assert row(corpus_path)['sha256'] == CORPUS_SHA
    assert row(runtime_path)['sha256'] == RUNTIME_SHA
    assert row(artifact / 'artifact.json')['sha256'] == ARTIFACT_SHA
    assert row(candidate / 'candidate.json')['sha256'] == INPUT_SHA
    corpus = json.loads(corpus_path.read_text())
    runtime = json.loads(runtime_path.read_text())
    product = json.loads((artifact / 'artifact.json').read_text())
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert 'baseline' not in manifest and runtime['baseline'] == BASELINE
    assert runtime['not_a_release'] is manifest['not_a_release'] is product['not_a_release'] is True
    assert product['origin_pin']['sha256'] == RUNTIME_SHA
    assert manifest['runtime'] == runtime['runtime']
    assert manifest['source_beams'] == runtime['source_beams']
    assert manifest['sources'] == {name: pin['sha256'] for name, pin in product['sources'].items()}
    assert set(manifest['sources']) == set(runtime['sources'])
    assert len(manifest['sources']) == 71 and len(manifest['source_beams']) == 57
    assert sum(map(len, manifest['source_beams'].values())) == 61
    assert set(manifest['source_beams']) <= set(manifest['sources'])
    assert all('lib/' + beam in manifest['files']
               for beams in manifest['source_beams'].values() for beam in beams)
    assert len(manifest['files']) == 80
    assert manifest['source_sha256'] == SOURCE_SHA
    assert hashlib.sha256(json.dumps(manifest['sources'], sort_keys=True).encode()).hexdigest() == SOURCE_SHA
    candidate_before = inventory(candidate)
    artifact_before = inventory(artifact)
    assert set(candidate_before) == set(manifest['files']) | {'candidate.json'}
    assert set(artifact_before) == set(product['files']) | {'artifact.json'}
    assert set(manifest['file_modes']) == set(manifest['files']) == set(product['files'])
    for name, expected in product['files'].items():
        assert name.startswith('lib/') and '..' not in Path(name).parts
        pin = dict(expected, mode=expected['mode'] & ~0o222)
        assert candidate_before[name] == artifact_before[name] == pin, name
        assert manifest['files'][name] == expected['sha256']
        assert manifest['file_modes'][name] == expected['mode']
        assert (candidate / name).read_bytes() == (artifact / name).read_bytes()
    fixture_before = inventory(fixture)
    expected_fixture = {name: corpus['files'][str(fixture / name)] for name in corpus['fixture_files']}
    assert len(fixture_before) == 28 and fixture_before == expected_fixture
    derived = dict(manifest, baseline=runtime['baseline'])
    descriptor = (json.dumps(derived, indent=2, sort_keys=True) + '\n').encode()
    assert hashlib.sha256(descriptor).hexdigest() == MANIFEST_SHA
    inverse = dict(derived)
    del inverse['baseline']
    assert inverse == manifest
    assert (json.dumps(inverse, indent=2, sort_keys=True) + '\n').encode() == (candidate / 'candidate.json').read_bytes()
    patches = {}
    transformations = []
    for name in sorted(CHANGED):
        original = (fixture / name).read_bytes()
        patched = original
        changes = [(OLD_MANIFEST.encode(), MANIFEST_SHA.encode()),
                   (OLD_SOURCE.encode(), SOURCE_SHA.encode())]
        for before, after in changes:
            assert patched.count(before) == 1 and after not in patched, name
            patched = patched.replace(before, after)
        restored = patched
        for before, after in reversed(changes):
            assert restored.count(after) == 1
            restored = restored.replace(after, before)
        assert restored == original
        patches[name] = patched
        transformations.append(dict(path=name, substitutions=[dict(before=a.decode(), after=b.decode(), count=1)
            for a, b in changes], inverse_byte_exact=True))
    output.mkdir()
    copied = output / 'candidate'
    copied.mkdir()
    shutil.copytree(candidate / 'lib', copied / 'lib')
    with (copied / 'candidate.json').open('xb') as stream:
        stream.write(descriptor)
    (copied / 'candidate.json').chmod(candidate_before['candidate.json']['mode'])
    destination = output / 'fixture1'
    shutil.copytree(fixture, destination)
    for name, data in patches.items():
        (destination / name).write_bytes(data)
    fixture_after = inventory(destination)
    assert set(fixture_after) == set(fixture_before)
    for name, pin in fixture_before.items():
        assert fixture_after[name]['mode'] == pin['mode']
        assert fixture_after[name]['bytes'] == pin['bytes']
        assert (destination / name).read_bytes() == patches.get(name, (fixture / name).read_bytes())
    candidate_after = inventory(copied)
    assert candidate_after['candidate.json']['sha256'] == MANIFEST_SHA
    assert {name: pin for name, pin in candidate_after.items() if name != 'candidate.json'} == {
        name: pin for name, pin in candidate_before.items() if name != 'candidate.json'}
    assert inventory(candidate) == candidate_before and inventory(fixture) == fixture_before
    assert inventory(artifact) == artifact_before
    bindings = dict(candidate_input=str(candidate), candidate_input_inventory=candidate_before,
        candidate_output=str(copied), candidate_output_inventory=candidate_after,
        fixture_input=str(fixture), fixture_input_inventory=fixture_before,
        fixture_output=str(destination), fixture_output_inventory=fixture_after,
        source_manifest=dict(path=str(corpus_path), pin=row(corpus_path)),
        runtime=dict(path=str(runtime_path), pin=row(runtime_path)),
        artifact=dict(path=str(artifact), manifest=row(artifact / 'artifact.json'), inventory=artifact_before),
        baseline_addition_only=True, descriptor_inverse_byte_exact=True,
        fixture_transformations=transformations, identity_substitutions=6,
        unchanged_fixture_leaves=25, unchanged_runnable_files=80,
        donor_and_candidate_preserved=True, product_qualified=False, readiness='L0')
    with (output / 'BINDINGS.json').open('x') as stream:
        json.dump(bindings, stream, indent=2, sort_keys=True)
        stream.write('\n')


if __name__ == '__main__':
    assert sys.dont_write_bytecode and sys.flags.optimize == 0 and len(sys.argv) == 7
    materialize(*(Path(value) for value in sys.argv[1:]))
