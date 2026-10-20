"""Create a source-only scoped Mix snapshot; never execute Mix/compiler/tests."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / 'test/reports/foundation/resume-20261019/h01-wire-mix1'
SNAPSHOT = HERE / 'snapshot'
SNAPSHOT.mkdir()
files = set()
for name in ('mix.exs', 'mix.lock', '.formatter.exs', 'README.md', 'LICENSE'):
    files.add(ROOT / name)
files.update((ROOT / 'config').glob('*.exs'))
files.update((ROOT / 'apps').glob('*/mix.exs'))
for name in ('.formatter.exs', 'README.md', 'LICENSE', 'test/test_helper.exs'):
    files.add(ROOT / 'apps/ex_d_bus' / name)
for name in ('lib', 'test/wire', 'test/fixtures'):
    files.update(p for p in (ROOT / 'apps/ex_d_bus' / name).rglob('*') if p.is_file())
excluded = []
for directory, dirs, names in os.walk(ROOT / 'deps', followlinks=False):
    base = Path(directory)
    for name in list(dirs):
        path = base / name
        assert not path.is_symlink(), ('unresolved directory symlink', path)
        if name in ('_build', 'ebin', '.mix', '.git', '.elixir_ls'):
            excluded.append(str(path.relative_to(ROOT)))
            dirs.remove(name)
    for name in names:
        path = base / name
        if path.suffix in ('.beam', '.app', '.ez', '.o', '.so', '.a', '.dll', '.dylib'):
            excluded.append(str(path.relative_to(ROOT)))
        else:
            files.add(path)
manifest = {'created_at': datetime.now(timezone.utc).isoformat(), 'scope': 'source-only ex_d_bus normal Mix wire baseline', 'files': {}, 'excluded_compiled_or_build_inputs': sorted(excluded)}
for source in sorted(files):
    assert source.is_file() and not {'_build', 'ebin', '.mix'} & set(source.relative_to(ROOT).parts)
    assert source.suffix not in ('.beam', '.app', '.ez', '.o', '.so', '.a', '.dll', '.dylib')
    resolved = source.resolve(strict=True)
    data = resolved.read_bytes()
    mode = stat.S_IMODE(resolved.stat().st_mode)
    name = 'project/' + str(source.relative_to(ROOT))
    target = SNAPSHOT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(data)
    target.chmod(mode)
    manifest['files'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'mode': mode,
                               'source_absolute': str(source), 'source_resolved': str(resolved),
                               'source_symlink': source.is_symlink(), 'source_lstat_mode': stat.S_IMODE(source.lstat().st_mode)}
format_sources = ['lib/ex_dbus/introspection.ex', 'lib/ex_dbus/message.ex', 'lib/ex_dbus/wire/decoder.ex', 'lib/ex_dbus/wire/encoder.ex', 'lib/ex_dbus/wire/types.ex']
wire_tests = sorted(str(p.relative_to(ROOT / 'apps/ex_d_bus')) for p in (ROOT / 'apps/ex_d_bus/test/wire').glob('*.exs'))
commands = {'cwd': 'project/apps/ex_d_bus', 'mix_env': 'test', 'seed': 4321,
            'format_paths': format_sources + wire_tests,
            'commands': [['elixir', '--version'], ['elixir', '-e', 'IO.inspect(%{hex_module: :code.which(Hex), hex_scm: :code.which(Hex.SCM), hex_version: Hex.version(), otp: :erlang.system_info(:otp_release), elixir: System.version()})'],
                         ['mix', 'help', 'compile'], ['mix', 'help', 'test'], ['mix', 'help', 'format'],
                         ['mix', 'compile', '--warnings-as-errors'], ['mix', 'format', '--check-formatted'] + format_sources + wire_tests,
                         ['mix', 'test', '--no-start', '--seed', '4321', 'test/wire']]}
for command in commands['commands']:
    command[0] = '/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3/bin/' + command[0]
(SNAPSHOT / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
(SNAPSHOT / 'COMMANDS.json').write_text(json.dumps(commands, indent=2, sort_keys=True) + '\n')
assert not (SNAPSHOT / 'project/_build').exists()
for name, pin in manifest['files'].items():
    assert hashlib.sha256((SNAPSHOT / name).read_bytes()).hexdigest() == pin['sha256']
    assert hashlib.sha256(Path(pin['source_absolute']).read_bytes()).hexdigest() == pin['sha256']
(HERE / 'SNAPSHOT.json').write_text(json.dumps({'files': len(manifest['files']), 'bytes': sum(p['bytes'] for p in manifest['files'].values()),
    'manifest_sha256': hashlib.sha256((SNAPSHOT / 'MANIFEST.json').read_bytes()).hexdigest(),
    'commands_sha256': hashlib.sha256((SNAPSHOT / 'COMMANDS.json').read_bytes()).hexdigest(),
    'compiled_artifacts_copied': False, 'clean_build_directory': True, 'mix_executed': False}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'snapshot_files': len(manifest['files']), 'wire_test_files': len(wire_tests), 'compiled_artifacts_copied': False}))
