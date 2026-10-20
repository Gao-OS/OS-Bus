"""Bind the unchanged candidate and helpers to the isolated H04-only fixture."""
import hashlib
import json
from pathlib import Path
import sys

output, donor, candidate, artifact, runtime, reference, elixir, python, runuser, jason = map(Path, sys.argv[1:])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


assert sha(candidate / 'candidate.json') == 'fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82'
assert sha(artifact / 'artifact.json') == 'b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1'
assert sha(runtime) == '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
manifest = json.loads((candidate / 'candidate.json').read_text())
assert len(manifest['files']) == 80 and len(manifest['sources']) == 71
assert manifest['source_sha256'] == 'f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c'
for name, digest in manifest['files'].items():
    assert sha(candidate / name) == digest, name
tree = output / 'tree'
guard = tree / 'fixture/process_guard'
assert sha(guard) == '5fff74cc84d9ed0597ed0992f22d9329351668371b1c117e341785808176ad66'
provenance = dict(
    schema=1, candidate_manifest_sha256=sha(candidate / 'candidate.json'),
    candidate_source_sha256=manifest['source_sha256'], production_source_count=71,
    candidate_file_count=80, not_a_release=True, installed_policy_qualified=False,
    helper_sources={str(p): sha(p) for p in sorted(tree.rglob('*.ex'))},
    helpers={str(p): sha(p) for p in sorted((output / 'ebin').glob('*.beam'))},
    fixture_sources={str(p): sha(p) for p in sorted(tree.rglob('*')) if p.is_file()},
    guard_sha256=sha(guard), reference_version='1.14.10', reference_patches=[],
    original_daemon_prefix_sha256='44f0c5e68e97f7d2822830b85cbe4ca75126b14d34835fea52a7939922a24f59')
(output / 'provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
paths = [p for p in tree.rglob('*') if p.is_file()]
paths += list((output / 'ebin').glob('*.beam')) + list((jason / 'ebin').glob('*.beam'))
paths += [output / 'provenance.json', output / 'run_suite.exs', candidate / 'candidate.json', artifact / 'artifact.json',
          runtime, reference, elixir, python, runuser]
paths += [candidate / name for name in manifest['files']]
paths += [donor / 'reference.conf', donor / 'policy.exs']
paths += [donor / 'inherited/security' / name for name in ('actor.py', 'daemon.exs', 'state.ex')]
binding = dict(schema=1, profile='core', installed_policy_qualified=False,
               candidate=str(candidate), donor=str(donor), original=str(donor / 'inherited/security'),
               elixir=str(elixir), python=str(python), runuser=str(runuser), reference=str(reference),
               guard=str(guard), runtime_manifest=str(runtime),
               support_ebins=[str(output / 'ebin'), str(jason / 'ebin')],
               inputs={str(p): sha(p) for p in sorted(set(paths))})
(output / 'bindings.json').write_text(json.dumps(binding, indent=2, sort_keys=True) + '\n')
