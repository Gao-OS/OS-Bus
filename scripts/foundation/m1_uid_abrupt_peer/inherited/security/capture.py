"""Capture a parent-frozen compiled candidate; never compile or start a bus."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
APPS = ('gao_bus', 'ex_d_bus', 'phoenix_pubsub')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_state():
    paths = [ROOT / 'mix.exs', ROOT / 'mix.lock', ROOT / 'devenv.lock', ROOT / 'apps/gao_bus/Makefile', Path(__file__).resolve()]
    paths += list((ROOT / 'config').glob('*.exs'))
    for app in APPS[:2]:
        paths += list((ROOT / 'apps' / app / 'lib').rglob('*.ex'))
        paths.append(ROOT / 'apps' / app / 'mix.exs')
    paths += list((ROOT / 'apps/gao_bus/c_src').glob('*.c'))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def helper_binding(bridge):
    # Read metadata only: executing a configured bridge could launch a service.
    data = bridge.read_bytes()
    assert len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'bridge must be little-endian ELF64'
    offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count, names_index = struct.unpack_from('<HHH', data, 58)
    assert entry_size == 64 and count > 0 and names_index < count, 'invalid bridge section table'
    assert offset + entry_size * count <= len(data), 'truncated bridge section table'
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + entry_size * index)
                for index in range(count)]

    def contents(section):
        start, size = section[4:6]
        assert start + size <= len(data), 'truncated bridge section'
        return data[start:start + size]

    assert sections[names_index][1] == 3, 'invalid bridge section names'
    names = contents(sections[names_index])
    matching = []
    for section in sections:
        start = section[0]
        end = names.find(b'\0', start)
        assert start < len(names) and end >= start, 'invalid bridge section name'
        if names[start:end] == b'.gao_helper_binding':
            matching.append(section)
    assert len(matching) == 1, 'bridge must have exactly one .gao_helper_binding section'
    section = matching[0]
    assert section[1] == 1 and section[2] & 2 and not section[2] & 1, 'binding section must be allocated and read-only'
    binding = contents(section)
    assert 1 <= len(binding) <= 4097 and binding[-1:] == b'\0' and b'\0' not in binding[:-1], 'invalid helper binding bytes'
    try:
        path = binding[:-1].decode('utf-8')
    except UnicodeDecodeError:
        raise AssertionError('helper binding must be UTF-8') from None
    assert not path or Path(path).is_absolute(), 'helper binding must be absolute or unconfigured'
    return {
        'section': '.gao_helper_binding', 'path': path or None, 'configured': bool(path),
        'section_sha256': hashlib.sha256(binding).hexdigest(),
        'runtime_overrides': False, 'installed_entrypoint_qualified': False,
        'unbound_outcome': None if path else 'NOT_STARTED/BINDING/ENOENT',
    }


def store_root(path):
    match = re.match(r'(/nix/store/[^/]+)', str(path.resolve()))
    assert match, ('non-store runtime', str(path))
    return match.group(1)


def verify_source_beams(build):
    probe = '''
    rows = for path <- Path.wildcard("_build/test/lib/{gao_bus,ex_d_bus}/ebin/*.beam") do
      {:ok, {_, [{:compile_info, info}]}} = :beam_lib.chunks(String.to_charlist(path), [:compile_info])
      %{beam: path, source: to_string(Keyword.fetch!(info, :source))}
    end
    IO.puts(:json.encode(rows))
    '''
    rows = json.loads(subprocess.check_output(
        [str(ROOT / '.devenv/profile/bin/elixir'), '--erl', '+S 2:2', '-e', probe],
        cwd=ROOT, text=True))
    mapping = {}
    for row in rows:
        source = Path(row['source']).resolve()
        beam = ROOT / row['beam']
        mapping.setdefault(source, []).append(beam)
    for app in APPS[:2]:
        for source in (ROOT / 'apps' / app / 'lib').rglob('*.ex'):
            beams = mapping.get(source.resolve(), [])
            assert beams, ('source has no compiled module', str(source))
            assert all(beam.stat().st_mtime_ns >= source.stat().st_mtime_ns for beam in beams), ('stale source module', str(source))
    return {str(source.relative_to(ROOT)): [str(beam.relative_to(build)) for beam in beams]
            for source, beams in sorted(mapping.items())}


def capture(destination):
    destination = destination.resolve()
    assert not destination.exists(), 'capture destination must be new'
    before = source_state()
    build = ROOT / '_build/test/lib'
    mandatory = build / 'gao_bus/ebin/Elixir.GaoBus.Limits.beam'
    assert mandatory.is_file(), 'BLOCKED: frozen candidate must include compiled GaoBus.Limits'
    # Check every source's actual compile-info module mapping, not newest beam.
    source_beams = verify_source_beams(build)
    native = build / 'gao_bus/priv/gao_unix.so'
    assert native.stat().st_mtime_ns >= (ROOT / 'apps/gao_bus/c_src/gao_unix.c').stat().st_mtime_ns, 'stale native build'
    bridge = build / 'gao_bus/priv/gao_helper_bridge'
    assert bridge.is_file() and not bridge.is_symlink(), 'BLOCKED: frozen candidate must include the helper bridge'
    bridge_mode = stat.S_IMODE(bridge.stat().st_mode)
    assert bridge_mode & 0o111 and not bridge_mode & 0o6000, 'helper bridge must be an unprivileged executable'
    assert all(bridge.stat().st_mtime_ns >= source.stat().st_mtime_ns
               for source in [ROOT / 'apps/gao_bus/c_src/gao_helper_bridge.c', ROOT / 'apps/gao_bus/Makefile']), 'stale helper bridge build'
    binding = helper_binding(bridge)
    files = {}
    for app in APPS:
        assert (build / app / 'ebin' / f'{app}.app').is_file(), ('missing application metadata', app)
        assert list((build / app / 'ebin').glob('*.beam')), ('missing compiled application', app)
        for source in sorted((build / app / 'ebin').glob('*')):
            assert source.is_file()
            files[f'lib/{app}/ebin/{source.name}'] = source
    files['lib/gao_bus/priv/gao_unix.so'] = native
    files['lib/gao_bus/priv/gao_helper_bridge'] = bridge
    hashes = {name: digest(source) for name, source in files.items()}
    modes = {name: stat.S_IMODE(source.stat().st_mode) for name, source in files.items()}
    runtime = {
        'elixir_store': store_root(ROOT / '.devenv/profile/bin/elixir'),
        'otp_store': store_root(ROOT / '.devenv/profile/bin/erl'),
        'native_store_roots': sorted({value for artifact in [native, bridge]
                                      for value in re.findall(rb'/nix/store/[a-z0-9]{32}-[A-Za-z0-9+_.-]+', artifact.read_bytes())}),
    }
    runtime['native_store_roots'] = [value.decode() for value in runtime['native_store_roots']]
    destination.mkdir(mode=0o700)
    for name, source in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(modes[name])
        assert digest(target) == hashes[name], ('changed artifact during capture', name)
        assert stat.S_IMODE(target.stat().st_mode) == modes[name], ('changed artifact mode during capture', name)
    assert before == source_state(), 'sources changed during capture'
    assert all(digest(source) == hashes[name] for name, source in files.items()), 'compiled artifacts changed during capture'
    assert all(stat.S_IMODE(source.stat().st_mode) == modes[name] for name, source in files.items()), 'compiled artifact modes changed during capture'
    manifest = {
        'version': 1, 'fixture': 'system-security', 'not_a_release': True,
        'baseline': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
        'sources': before, 'source_beams': source_beams, 'files': hashes, 'file_modes': modes,
        'runtime': runtime, 'helper_binding': binding,
    }
    manifest['source_sha256'] = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    path = destination / 'candidate.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'candidate': str(destination), 'manifest_sha256': digest(path),
                      'source_sha256': manifest['source_sha256'], 'artifacts': len(files)}))


if __name__ == '__main__':
    capture(Path(sys.argv[1]))
