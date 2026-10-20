"""Rebind the passing complete SEC07 source5 corpus to immutable XML product bytes."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

ARTIFACT_SHA = 'b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1'
RUNTIME_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
CORPUS_SHA = '391bf23fa14ec2cd1595fd9913618bd179d2f5fd3a8b6675b0564cd1a9034641'
CANDIDATE_SHA = 'fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82'
SOURCE_SHA = 'f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c'
OLD_MANIFEST = "MANIFEST_SHA='0d4ab06f469256785d4cb952563a2e5a471c4babf89e198cc5d6578f360e340b'"
OLD_SOURCE = "SOURCE_SHA='4e334b95bc0ddd0afed797f9640c6971ba2a339c2a369f6500a0d7230d9e8350'"
CONTRACT_SHA = 'd64fbe9bd3ed100399673e1a803196631bcef0159b56a5bdc1cd4fd30a3527e5'


def row(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), path
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                sha256=hashlib.sha256(data).hexdigest())


def leaves(root):
    paths = list(root.rglob('*'))
    assert not any(path.is_symlink() for path in paths), root
    return {path.relative_to(root).as_posix() for path in paths if path.is_file()}


def patch_contract(original):
    assert hashlib.sha256(original).hexdigest() == CONTRACT_SHA, 'SEC07 source5 contract drift'
    changes = [(OLD_MANIFEST.encode(), f"MANIFEST_SHA='{CANDIDATE_SHA}'".encode()),
               (OLD_SOURCE.encode(), f"SOURCE_SHA='{SOURCE_SHA}'".encode())]
    patched = original
    for before, after in changes:
        assert patched.count(before) == 1 and after not in patched
        patched = patched.replace(before, after)
    restored = patched
    for before, after in reversed(changes):
        assert restored.count(after) == 1
        restored = restored.replace(after, before)
    assert restored == original
    return patched


def normalize(artifact, runtime_path, fixtures, corpus_path, output):
    assert not output.exists(), output
    assert row(artifact / 'artifact.json')['sha256'] == ARTIFACT_SHA
    assert row(runtime_path)['sha256'] == RUNTIME_SHA
    assert row(corpus_path)['sha256'] == CORPUS_SHA
    product = json.loads((artifact / 'artifact.json').read_text())
    runtime = json.loads(runtime_path.read_text())
    corpus = json.loads(corpus_path.read_text())
    assert product['not_a_release'] is runtime['not_a_release'] is True
    assert product['origin_pin']['sha256'] == RUNTIME_SHA
    assert len(product['sources']) == 71 and len(product['files']) == 80
    assert leaves(artifact) == set(product['files']) | {'artifact.json'}
    artifact_rows = {}
    for name, expected in product['files'].items():
        assert name.startswith('lib/') and '..' not in Path(name).parts
        observed = row(artifact / name)
        assert observed == dict(expected, mode=expected['mode'] & ~0o222), name
        artifact_rows[name] = observed
    assert len(corpus['fixture_files']) == 34 and leaves(fixtures) == set(corpus['fixture_files'])
    fixture_rows = {}
    for name in sorted(corpus['fixture_files']):
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        expected, = [pin for path, pin in corpus['files'].items()
                     if path.endswith('/source5/fixture1/' + name)]
        observed = row(fixtures / name)
        assert observed == dict(expected, mode=expected['mode'] & ~0o222), name
        fixture_rows[name] = observed
    sources = {name: pin['sha256'] for name, pin in product['sources'].items()}
    assert set(sources) == set(runtime['sources'])
    assert hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest() == SOURCE_SHA
    mappings = runtime['source_beams']
    assert len(mappings) == 57 and sum(map(len, mappings.values())) == 61
    assert set(mappings) <= set(sources)
    assert all('lib/' + beam in product['files'] for beams in mappings.values() for beam in beams)
    manifest = dict(version=1, not_a_release=True, runtime=runtime['runtime'], sources=sources,
                    source_sha256=SOURCE_SHA, source_beams=mappings,
                    files={name: pin['sha256'] for name, pin in product['files'].items()},
                    file_modes={name: pin['mode'] for name, pin in product['files'].items()})
    output.mkdir()
    candidate = output / 'candidate'
    candidate.mkdir()
    shutil.copytree(artifact / 'lib', candidate / 'lib')
    (candidate / 'candidate.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    assert row(candidate / 'candidate.json')['sha256'] == CANDIDATE_SHA
    for name, expected in artifact_rows.items():
        assert row(candidate / name) == expected and (candidate / name).read_bytes() == (artifact / name).read_bytes()
    copied = output / 'fixtures'
    shutil.copytree(fixtures, copied)
    contract = copied / 'contract.py'
    original = contract.read_bytes()
    patched = patch_contract(original)
    contract.chmod(0o644)
    contract.write_bytes(patched)
    contract.chmod(fixture_rows['contract.py']['mode'])
    assert contract.read_bytes() == patched and leaves(copied) == leaves(fixtures)
    for name in set(fixture_rows) - {'contract.py'}:
        assert row(copied / name) == fixture_rows[name]
        assert (copied / name).read_bytes() == (fixtures / name).read_bytes()
    (output / 'manifest-sha256').write_text(CANDIDATE_SHA + '\n')
    (output / 'source-sha256').write_text(SOURCE_SHA + '\n')
    bindings = dict(adapter_revision=1, adapter=row(Path(__file__)),
        artifact_store=str(artifact), artifact_sha256=ARTIFACT_SHA, artifact_files=artifact_rows,
        runtime_store=str(runtime_path), runtime_sha256=RUNTIME_SHA,
        corpus_store=str(corpus_path), corpus_manifest_sha256=CORPUS_SHA,
        fixtures_store=str(fixtures), fixture_inputs=fixture_rows,
        candidate_store=str(candidate), candidate_manifest_sha256=CANDIDATE_SHA,
        candidate_source_sha256=SOURCE_SHA, candidate_manifest=manifest,
        patched_contract=row(contract),
        patch_provenance=dict(origin=str(fixtures / 'contract.py'), before=fixture_rows['contract.py'],
            after=row(contract), assignments=[dict(original=OLD_MANIFEST, replacement=f"MANIFEST_SHA='{CANDIDATE_SHA}'"),
                dict(original=OLD_SOURCE, replacement=f"SOURCE_SHA='{SOURCE_SHA}'")], reversible_byte_change=True),
        unchanged_fixture_files=33, production_sources=71, source_mappings=57, mapped_beams=61,
        runnable_files_unchanged=80, cases_per_backend=17, corpus_pairs=34,
        requirement_qualification=False, accepted_index_mutation=False, product_qualified=False,
        readiness='L0', not_a_release=True)
    (output / 'bindings.json').write_text(json.dumps(bindings, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    assert len(sys.argv) == 6 and sys.dont_write_bytecode and sys.flags.optimize == 0
    normalize(*(Path(value) for value in sys.argv[1:]))
