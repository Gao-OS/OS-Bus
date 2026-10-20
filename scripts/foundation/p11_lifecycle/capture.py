"""Freeze a real, source-fresh production release; never compile or start it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
CORE = ('gao_bus', 'ex_d_bus')
FORBIDDEN = {'gao_bus_web', 'gao_config', 'gao_bus_test', 'phoenix', 'bandit', 'dns_cluster'}
STORE = re.compile(rb'/nix/store/[a-z0-9]{32}-[A-Za-z0-9+_.-]+')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    rows = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        assert not mode & 0o6000, ('privileged package mode', str(path))
        row = {'mode': mode}
        if path.is_symlink():
            target = os.readlink(path)
            resolved = path.resolve()
            assert resolved.is_relative_to(root.resolve()) or str(resolved).startswith('/nix/store/'), ('escaping package symlink', str(path), target)
            row.update(type='symlink', target=target)
        elif stat.S_ISREG(info.st_mode):
            row.update(type='file', sha256=digest(path), size=info.st_size)
        elif stat.S_ISDIR(info.st_mode):
            row['type'] = 'directory'
        else:
            raise AssertionError(('special package file', str(path)))
        rows[str(path.relative_to(root))] = row
    return rows


def source_state():
    paths = [ROOT/'mix.exs', ROOT/'mix.lock', ROOT/'devenv.lock', ROOT/'devenv.nix', ROOT/'apps/gao_bus/Makefile', ROOT/'nix/tests/lifecycle.nix', ROOT/'scripts/foundation/vm_security/capture.py', ROOT/'scripts/foundation/p08_sustained/transport.py']
    for app in CORE:
        paths += list((ROOT/'apps'/app/'lib').rglob('*.ex'))
        paths.append(ROOT/'apps'/app/'mix.exs')
    for directory in ['config', 'rel/os_bus', 'apps/gao_bus/c_src', 'scripts/foundation/p11_lifecycle']:
        paths += [path for path in (ROOT/directory).rglob('*') if path.is_file() and '__pycache__' not in path.parts]
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(set(paths)) if path.is_file()}


def validate_apps(apps):
    assert set(CORE) | {'phoenix_pubsub'} <= set(apps), ('missing core application', apps)
    assert not FORBIDDEN.intersection(apps), ('non-headless application', apps)


def read_only_probe(paths, operation):
    before = {str(path): (digest(path), stat.S_IMODE(path.stat().st_mode)) for path in paths}
    try:
        return operation()
    finally:
        after = {str(path): (digest(path), stat.S_IMODE(path.stat().st_mode)) for path in paths}
        assert before == after, 'metadata probe modified an input artifact'


def metadata(release, build):
    # The pinned inspection runtime reads BEAM chunks/terms only. No application loads.
    code = '''
    root = System.fetch_env!("P11_RELEASE_INSPECT")
    build = System.fetch_env!("P11_BUILD_INSPECT")
    [erts, version] = String.split(File.read!(Path.join(root, "releases/start_erl.data")))
    {:ok, [{:release, _, _, rel_apps}]} = :file.consult(String.to_charlist(Path.join([root, "releases", version, "os_bus.rel"])))
    apps = for path <- Path.wildcard(Path.join(root, "lib/*/ebin/*.app")) do
      {:ok, [{:application, name, props}]} = :file.consult(String.to_charlist(path))
      %{name: name, path: Path.relative_to(path, root), dependencies: Keyword.get(props, :applications, [])}
    end
    beams = for path <- Path.wildcard(Path.join(root, "lib/{gao_bus,ex_d_bus}-*/ebin/*.beam")) do
      [app_version, "ebin", name] = Path.split(Path.relative_to(path, Path.join(root, "lib")))
      app = if String.starts_with?(app_version, "gao_bus-"), do: "gao_bus", else: "ex_d_bus"
      production = Path.join([build, "lib", app, "ebin", name])
      bytes = File.read!(production)
      {:ok, {_, [{:compile_info, info}]}} = :beam_lib.chunks(bytes, [:compile_info])
      {:ok, stripped} = Mix.Release.strip_beam(bytes)
      packaged = File.read!(path)
      true = packaged == bytes or packaged == stripped
      %{beam: Path.relative_to(path, root), production_beam: production,
        strip_operation: if(packaged == bytes, do: "identity", else: "Mix.Release.strip_beam(binary)"),
        source: to_string(Keyword.fetch!(info, :source))}
    end
    {:script, _, instructions} = :erlang.binary_to_term(File.read!(Path.join([root, "releases", version, "start.boot"])))
    boot = for {:apply, {:application, :load, [{:application, name, _}]}} <- instructions, do: name
    IO.puts(:json.encode(%{erts: erts, version: version, apps: apps, rel_apps: Enum.map(rel_apps, &elem(&1, 0)), boot_apps: boot, beams: beams}))
    '''
    tool = ROOT/'.devenv/profile/bin/elixir'
    paths = [path for app in CORE for path in (build/'lib'/app/'ebin').glob('*') if path.is_file()]
    paths += [path for path in release.rglob('*') if path.is_file()]
    result = read_only_probe(paths, lambda: subprocess.run([str(tool), '--erl', '+S 2:2', '-e', code], cwd=ROOT,
                            env={**os.environ, 'P11_RELEASE_INSPECT': str(release), 'P11_BUILD_INSPECT': str(build)}, text=True,
                            capture_output=True, timeout=30, check=True))
    data = json.loads(result.stdout)
    validate_apps([row['name'] for row in data['apps']])
    validate_apps(data['rel_apps'])
    validate_apps(data['boot_apps'])
    mapping = {}
    for row in data['beams']:
        source = Path(row['source']).resolve()
        assert source.is_relative_to(ROOT), ('unexpected compile source', str(source))
        beam = Path(row['production_beam'])
        assert beam.is_relative_to(build), ('unexpected production build path', str(beam))
        row['production_sha256'] = digest(beam)
        row['packaged_sha256'] = digest(release/row['beam'])
        assert beam.stat().st_mtime_ns >= source.stat().st_mtime_ns, ('stale packaged BEAM', str(source), row['beam'])
        mapping.setdefault(str(source.relative_to(ROOT)), []).append(row['beam'])
    for app in CORE:
        for source in (ROOT/'apps'/app/'lib').rglob('*.ex'):
            assert str(source.relative_to(ROOT)) in mapping, ('source has no packaged module', str(source))
    data['source_beams'] = mapping
    return data


def runtime_roots(release, rows):
    roots, elf = set(), {}
    for name, row in rows.items():
        path = release/name
        if row['type'] == 'symlink':
            roots.update(match.decode() for match in STORE.findall(str(path.resolve()).encode()))
        elif row['type'] == 'file':
            with path.open('rb') as file:
                prefix = file.read(256)
            if prefix.startswith(b'\x7fELF'):
                roots.update(match.decode() for match in STORE.findall(path.read_bytes()))
                elf[name] = subprocess.check_output(['readelf', '-l', '-d', str(path)], text=True, stderr=subprocess.STDOUT, timeout=10)
            elif prefix.startswith(b'#!'):
                roots.update(match.decode() for match in STORE.findall(prefix.splitlines()[0]))
    assert roots, 'actual packaged ELF runtime roots required'
    assert all(Path(root).is_dir() for root in roots), 'missing captured Nix runtime root'
    return {'store_roots': sorted(roots), 'elf': elf}


def verify_build(record, release, sources):
    assert record['schema'] == 2 and record['exit_status'] == 0, 'successful schema2 build record required'
    argv = record['argv']
    assert 'MIX_ENV=prod' in argv and ['mix', 'release', 'os_bus'] == argv[argv.index('mix'):argv.index('mix')+3], 'production release command required'
    assert Path(argv[argv.index('--path')+1]).resolve() == release, 'build record release path mismatch'
    assert Path(record['cwd']).resolve() == ROOT, 'build record worktree mismatch'
    for name, value in sources.items():
        if name.startswith(('apps/', 'config/', 'rel/')) or name in ('mix.exs', 'mix.lock', 'devenv.lock'):
            assert record['source_after'].get(name) == value, ('build source mismatch', name)
            assert record['source_before'].get(name) == value, ('source changed during build', name)


def capture(release, destination, build_record, restoration_record=None):
    release, destination = release.resolve(), destination.resolve()
    assert not destination.exists(), 'capture destination must be new'
    assert (release/'bin/os_bus').is_file(), 'real release launcher required'
    before = source_state()
    record = json.loads(build_record.read_text())
    verify_build(record, release, before)
    rows = inventory(release)
    build = Path(next(value.split('=', 1)[1] for value in record['argv'] if value.startswith('MIX_BUILD_PATH='))).resolve()
    assert build.is_relative_to(ROOT/'_build'), 'isolated production build required'
    restoration = None
    if restoration_record:
        restoration = json.loads(restoration_record.read_text())
        assert restoration['schema'] == 2 and restoration['exit_status'] == 0, 'successful restoration record required'
        assert 'MIX_ENV=prod' in restoration['argv'] and 'MIX_BUILD_PATH='+str(build) in restoration['argv'], 'restoration build mismatch'
        assert ['mix', 'compile', '--force', '--warnings-as-errors'] == restoration['argv'][-4:], 'strict restoration compile required'
        for name, value in before.items():
            if name.startswith(('apps/', 'config/', 'rel/')) or name in ('mix.exs', 'mix.lock', 'devenv.lock'):
                assert restoration['source_after'].get(name) == value, ('restoration source mismatch', name)
    meta = metadata(release, build)
    runtime = runtime_roots(release, rows)
    app = next((release/'lib').glob('gao_bus-*'))
    for name, inputs in [('gao_unix.so', ['gao_unix.c']), ('gao_helper_bridge', ['gao_helper_bridge.c'])]:
        artifact = app/'priv'/name
        assert artifact.is_file() and not artifact.is_symlink(), ('native artifact missing', name)
        assert digest(artifact) == digest(build/'lib/gao_bus/priv'/name), ('native release/build mismatch', name)
        assert all(artifact.stat().st_mtime_ns >= source.stat().st_mtime_ns for source in [ROOT/'apps/gao_bus/Makefile'] + [ROOT/'apps/gao_bus/c_src'/item for item in inputs]), ('stale native artifact', name)
    bridge = app/'priv/gao_helper_bridge'
    assert bridge.stat().st_mode & 0o111, 'helper bridge must be executable'
    binding = runpy.run_path(str(ROOT/'scripts/foundation/vm_security/capture.py'))['helper_binding'](bridge)
    version = meta['version']
    assert re.fullmatch(r'[A-Za-z0-9_.-]+', version) and re.fullmatch(r'[A-Za-z0-9_.-]+', meta['erts']), 'unsafe release version'
    for template, packaged in [('runtime.exs', 'runtime.exs'), ('env.sh.eex', 'env.sh')]:
        assert digest(ROOT/'rel/os_bus'/template) == digest(release/'releases'/version/packaged), ('custom release configuration mismatch', template)
    destination.mkdir(mode=0o700)
    shutil.copytree(release, destination/'release', symlinks=True, copy_function=shutil.copy2)
    assert inventory(destination/'release') == rows, 'freeze differs from production package'
    assert source_state() == before and inventory(release) == rows, 'source/package changed during capture'
    assert all(digest(Path(row['production_beam'])) == row['production_sha256'] for row in meta['beams']), 'production modules changed during capture'
    shutil.copyfile(build_record, destination/'build-record.json')
    manifest = {'schema': 1, 'fixture': 'p11-packaged-lifecycle', 'not_a_release': False,
                'baseline': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
                'release_source': str(release), 'sources': before, 'inventory': rows, 'metadata': meta,
                'runtime': runtime, 'helper_binding': binding, 'build_record_sha256': digest(build_record),
                'inspection_elixir': {'path': str((ROOT/'.devenv/profile/bin/elixir').resolve()), 'sha256': digest(ROOT/'.devenv/profile/bin/elixir'), 'mix_release_sha256': digest(ROOT/'.devenv/profile/lib/elixir/lib/mix/lib/mix/release.ex')},
                'nixpkgs': json.loads((ROOT/'devenv.lock').read_text())['nodes']['nixpkgs-src']['locked'],
                'limits': ['private disposable VM only', 'no installed activation/helper qualification', 'whole-BEAM crash only; no Router-only fault', 'no system-bus replacement or production readiness promotion']}
    if restoration_record:
        shutil.copyfile(restoration_record, destination/'restoration-record.json')
        manifest['restoration_record_sha256'] = digest(restoration_record)
    manifest['source_sha256'] = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    (destination/'release.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'capture': str(destination), 'files': len(rows), 'manifest_sha256': digest(destination/'release.json'), 'source_sha256': manifest['source_sha256']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--restoration-record', type=Path)
    args = parser.parse_args()
    capture(args.release, args.destination, args.build_record, args.restoration_record)
