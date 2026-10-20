"""Freeze a schema2 packaged resource fixture without starting an application."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent
PACKAGE_SHA256 = 'dde56f6cfb2986356c382e61e2aa332020692a25c3ab9a03827fdce665289e48'
WORKLOAD_SHA256 = '337bb0ef8c0ab0a8b7af30721d7d318418d92e87864c97ddaefd205495359602'
LEGACY = {
    'workload.json': WORKLOAD_SHA256,
    'policy.exs': '21d8c5d9f4312157e45aae628218799b5d3b20fa50eb46507d66572bb65fddd6',
    'daemon.exs': '7c9c6be780dd97022399a8ab42f60bd047169de5d075f9d2126e5ad09692868d',
    'actor.py': '1a5bcf1cfd1548f1eca7edd9db81e53f41e92636233c58cafdcabdab891c1697',
    'transport.py': 'c799bc12a074addb40b2bbad8a4c6a7da1f2ad8dd54e126d480318e0c249d726',
    'channel.py': '03ca3f0526fedb5ca54fc3f1f3c300a3cbea4bd3e6a6df5aa42688add9802edf',
}
GUEST_RELEASE = '/run/osbus-p08/package/release'
GUEST_CONFIG = '/run/osbus-p08/config/bus.conf'
DESIGN_PATH = 'test/reports/foundation/continuation-20261011-full-goal/environment/p08-packaged-standard-policy-design/DESIGN.md'
DESIGN_SHA256 = '0c3c1266d08680003940efcadd42c917b0ca39a041b41eed7dec500186c246cd'
POLICY_FIXTURE = 'packaged_wire_policy.xml'


def policy_contract():
    return {'kind': 'standard-XML-valid-wire', 'fixture': POLICY_FIXTURE,
            'universal_native_equivalence': 'BLOCKED_DESIGN',
            'legacy_comparison': {'tests': 3, 'failed': 1, 'mismatches': 8, 'decisions': 400},
            'valid_wire_delta': {'uid': 1101, 'action': 'receive', 'type': 'method_call',
                                 'interface': None, 'native': 'allow', 'xml': 'deny'},
            'design': {'path': DESIGN_PATH, 'sha256': DESIGN_SHA256},
            'reference_private_policy_probe_required': True,
            'both_packaged_modes_policy_probe_required': True,
            'backends': ['reference', 'start', 'start_iex'], 'rows_per_backend': 14,
            'reference_unit': 'osbus-p08-policy-reference.service',
            'reference_socket': '/run/osbus-p08/reference/bus',
            'reference_xml_delta': 'sole listen path'}


def validate_policy_fixture(directory=FIXTURES):
    directory = Path(directory)
    expected = {'policy.exs': LEGACY['policy.exs'],
                'packaged_policy.xml': '8ed01651a71ab18a7ae9fc49a907495e0de236a28903dc56140cb9635de4fbf1',
                'packaged_policy_test.exs': '71bc6808f8723c733ee484ac670417fbf6def54b876836ad7d67b4ece98ac91d'}
    for name, sha256 in expected.items():
        assert digest(directory / name) == sha256, ('original policy fixture drift', name)
    legacy = (directory / 'packaged_policy.xml').read_bytes()
    old = b'    <deny receive_interface="org.foundation.ReceiveDenied" receive_requested_reply="true"/>'
    new = (b'    <deny receive_type="method_call" receive_interface="org.foundation.ReceiveDenied" receive_requested_reply="true"/>\n'
           b'    <deny receive_type="signal" receive_interface="org.foundation.ReceiveDenied" receive_requested_reply="true"/>')
    assert legacy.count(old) == 1, 'original interface deny identity'
    assert (directory / POLICY_FIXTURE).read_bytes() == legacy.replace(old, new), 'unauthorized packaged policy change'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def package_helpers():
    return runpy.run_path(str(ROOT/'scripts/foundation/p11_lifecycle/capture.py'))


def inventory(path):
    return package_helpers()['inventory'](Path(path))


def verify_package(frozen, root=ROOT, expected_sha256=PACKAGE_SHA256):
    frozen, root = Path(frozen).resolve(), Path(root).resolve()
    assert digest(frozen/'release.json') == expected_sha256, 'frozen package manifest identity'
    manifest = json.loads((frozen/'release.json').read_text())
    assert manifest['schema'] == 1 and manifest['not_a_release'] is False, 'real frozen release required'
    assert (frozen/'release/bin/os_bus').is_file(), 'packaged launcher required'
    assert inventory(frozen/'release') == manifest['inventory'], 'complete package inventory drift'
    for name, expected in manifest['sources'].items():
        source = (root/name).resolve()
        assert source.is_relative_to(root), ('source escapes worktree', name)
        assert digest(source) == expected, ('current source drift', name)
    for row in manifest['metadata']['beams']:
        source = Path(row['source']).resolve()
        assert source.is_relative_to(root), ('compile source escapes worktree', str(source))
        assert digest(source) == manifest['sources'][str(source.relative_to(root))], 'BEAM source binding'
        assert digest(Path(row['production_beam'])) == row['production_sha256'], 'production BEAM drift'
        assert digest(frozen/'release'/row['beam']) == row['packaged_sha256'], 'packaged BEAM drift'
    return manifest


def fixture_state(directory=FIXTURES):
    directory = Path(directory)
    result = {}
    for path in sorted(directory.rglob('*')):
        if '__pycache__' in path.parts:
            continue
        assert not path.is_symlink(), ('fixture symlink', str(path))
        if path.is_file():
            result[str(path.relative_to(directory))] = {'sha256': digest(path), 'bytes': path.stat().st_size}
    return result


def workload_contract(path=FIXTURES/'workload.json'):
    assert digest(path) == WORKLOAD_SHA256, 'immutable v1 workload changed'
    content = json.loads(Path(path).read_text())
    numbers = {}

    def collect(value, name=''):
        if type(value) in (int, float):
            numbers[name] = value
        elif isinstance(value, dict):
            for key, item in value.items():
                collect(item, name+'.'+key if name else key)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                collect(item, name+'.'+str(index))
    collect(content)
    return {'sha256': WORKLOAD_SHA256, 'bytes': Path(path).stat().st_size,
            'content': content, 'numerical_observation_ceilings': numbers}


def run_contract(mode):
    assert mode in ('preflight', 'soak'), 'unsupported packaged run mode'
    return {'mode': mode, 'qualifying': mode == 'soak',
            'duration_seconds': 10 if mode == 'preflight' else 600,
            'warmup_operations': 100, 'batches': 3, 'operations_per_batch': 1000,
            'duration_starts_after_verified_batches': True}


def account_contract():
    records = {}
    for name, uid, gid in [('root', 0, 0), ('messagebus', 4, 4),
                           ('foundationA', 1100, 100), ('foundationB', 1101, 100)]:
        records[name] = {'name': name, 'uid': uid, 'gid': gid, 'groups': [gid], 'provenance': None}
    return {'users': {name: row['uid'] for name, row in records.items()},
            'groups': {'root': 0, 'messagebus': 4, 'users': 100},
            'memberships': {str(row['uid']): row['groups'] for row in records.values()},
            'user_records': records, 'guest_must_reverify': True,
            'provenance': {'kind': 'trusted-finite-guest-model',
                           'actor_credentials': 'environment/security-current16-vm/security-vm-evidence/qualification.json',
                           'daemon_credentials': 'environment/p11-package-vm/vm6-evidence/evidence/evidence.json',
                           'profile': 'same pinned NixOS users.isNormalUser; primary users GID100',
                           'host_accounts_used': False}}


def startup_contract():
    return {'modes': ['start', 'start_iex'], 'release_path': GUEST_RELEASE,
            'launcher': GUEST_RELEASE+'/bin/os_bus', 'working_directory': '/run/osbus-p08/work',
            'evidence': {'path': '/run/osbus-p08/evidence', 'symlink_target': '/var/lib/osbus-p08-evidence',
                         'disk_backed': True},
            'manager_command': ['systemd-run', '--pipe', '--wait'], 'unit_prefix': 'osbus-p08',
            'environment': {'OS_BUS_CONFIG': GUEST_CONFIG, 'OS_BUS_INHERITED_LISTENER': 'false',
                            'ERL_FLAGS': '+S 2:2', 'RELEASE_TMP': '/run/osbus-p08/work',
                            'ERL_CRASH_DUMP_SECONDS': '0', 'RELEASE_DISTRIBUTION': 'none',
                            'PATH': '/run/current-system/sw/bin'},
            'unset_environment': ['PHX_SERVER', 'SECRET_KEY_BASE', 'DBUS_SOCKET_PATH',
                                  'DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS',
                                  'RELEASE_COOKIE', 'RELEASE_NODE', 'ELIXIR_ERL_OPTIONS',
                                  'ERL_AFLAGS', 'ERL_ZFLAGS', 'OS_BUS_CLUSTER', 'IEX_HOME'],
            'unit': {'Type': 'notify', 'NotifyAccess': 'main', 'User': 'messagebus',
                     'Group': 'messagebus', 'KillMode': 'control-group', 'TimeoutStartSec': 15,
                     'TimeoutStopSec': 3, 'TasksMax': 128, 'MemoryMax': '256M', 'Restart': 'no'},
            'iex_initialization': {'working_directory_file_absent': True,
                                   'actual_user_home_file_absent': True,
                                   'iex_home_must_be_absent': True,
                                   'actual_lookup': 'IEX_HOME || HOME'},
            'socket': '/run/osbus-p08/socket/bus', 'inherited_fd3_claimed': False}


def validate_startup(startup):
    assert startup == startup_contract(), 'fixed private nondistributed startup contract drift'


def expected_capacities():
    return {'pending_limits': {'per_peer': 4, 'per_uid': 512, 'global': 4096, 'timeout_ms': 100},
            'name_limits': {'per_peer': 4, 'global': 8192},
            'match_limits': {'per_peer': 4, 'global': 8192},
            'safety_limits': {
                'global': {'connections': 8, 'ingress_bytes': 2097152, 'egress_bytes': 537919488,
                           'ingress_messages': 512, 'egress_messages': 512,
                           'ingress_fds': 128, 'egress_fds': 128},
                'uid': {'connections': 8},
                'peer': {'ingress_bytes': 524288, 'egress_bytes': 134479872,
                         'ingress_messages': 32, 'egress_messages': 32,
                         'ingress_fds': 32, 'egress_fds': 32}},
            'xml_limits': {'max_completed_connections': 7, 'max_incomplete_connections': 1,
                           'max_connections_per_user': 7, 'max_names_per_connection': 4,
                           'max_match_rules_per_connection': 4, 'max_replies_per_connection': 4,
                           'reply_timeout': 100, 'max_message_size': 262144,
                           'max_message_unix_fds': 16, 'max_incoming_bytes': 262144,
                           'max_outgoing_bytes': 262144, 'max_incoming_unix_fds': 16,
                           'max_outgoing_unix_fds': 16}}


def validate_capacities(actual):
    def compare(expected, observed, path=''):
        for key, value in expected.items():
            assert key in observed, ('missing packaged capacity', path, key)
            if isinstance(value, dict):
                compare(value, observed[key], path+'.'+key)
            else:
                assert observed[key] == value, ('packaged capacity drift', path, key, observed[key], value)
    compare(expected_capacities(), actual)


PLAN_CODE = r'''
root = System.fetch_env!("OSBUS_CAPTURE_PACKAGE")
config_path = System.fetch_env!("OSBUS_CAPTURE_CONFIG")
out = System.fetch_env!("OSBUS_CAPTURE_PLAN")
accounts_json = :json.decode(File.read!(System.fetch_env!("OSBUS_CAPTURE_ACCOUNTS")))
records = Map.new(accounts_json["user_records"], fn {name, row} ->
  {name, %{name: name, uid: row["uid"], gid: row["gid"], groups: row["groups"], provenance: nil}}
end)
accounts = %{users: accounts_json["users"], groups: accounts_json["groups"],
  memberships: Map.new(accounts_json["memberships"], fn {uid, gids} -> {String.to_integer(uid), gids} end),
  user_records: records}
started = fn -> Enum.map(Application.started_applications(), &elem(&1, 0)) |> Enum.sort() end
before = started.()
false = :gao_bus in before or :ex_d_bus in before
{:ok, config} = GaoBus.Config.load(config_path, accounts: accounts, daemon_uid: 4)
invocation = %{profile: :system, nofork: true, nopidfile: true, log_target: :stderr, safety_limits: %{}}
{:ok, plan} = GaoBus.Config.Runtime.compile(config, invocation, %{uid: 4})
{:ok, compiled_policy} = GaoBus.Policy.compile(config)
{:error, %{reason: {:inconsistent_safety_limit, :peer, :egress_bytes}}} =
  GaoBus.Config.Runtime.compile(config, %{invocation | safety_limits: %{peer: %{egress_bytes: 262144}}}, %{uid: 4})
after_apps = started.()
false = :gao_bus in after_apps or :ex_d_bus in after_apps
for name <- [GaoBus.Supervisor, GaoBus.Router, GaoBus.Policy, GaoBus.Limits,
  GaoBus.NameRegistry, GaoBus.Listener], do: nil = Process.whereis(name)
for module <- [GaoBus.Config, GaoBus.Config.Runtime, GaoBus.Policy, GaoBus.Unix.Native] do
  path = to_string(:code.which(module))
  true = String.starts_with?(path, root <> "/lib/")
end
tagged = fn value, recur ->
  cond do
    is_map(value) -> %{"$map" => value |> Map.to_list() |> Enum.sort() |> Enum.map(fn {k, v} -> [recur.(k, recur), recur.(v, recur)] end)}
    is_tuple(value) -> %{"$tuple" => value |> Tuple.to_list() |> Enum.map(&recur.(&1, recur))}
    is_list(value) -> Enum.map(value, &recur.(&1, recur))
    is_atom(value) -> %{"$atom" => Atom.to_string(value)}
    is_binary(value) -> %{"$binary_base64" => Base.encode64(value)}
    is_integer(value) or is_float(value) -> value
    true -> raise "unexpected live resource in pure plan"
  end
end
plain = fn value, recur ->
  cond do
    is_struct(value) -> recur.(Map.from_struct(value), recur)
    is_map(value) -> Map.new(value, fn {k, v} -> {to_string(k), recur.(v, recur)} end)
    is_tuple(value) -> value |> Tuple.to_list() |> Enum.map(&recur.(&1, recur))
    is_list(value) -> Enum.map(value, &recur.(&1, recur))
    is_nil(value) -> :null
    value in [true, false] -> value
    is_atom(value) -> Atom.to_string(value)
    is_binary(value) -> String.replace(value, config_path, "/run/osbus-p08/config/bus.conf")
    is_integer(value) or is_float(value) -> value
    true -> raise "unexpected semantic plan term"
  end
end
semantic_config = Map.take(Map.from_struct(config), [:settings, :limits, :policies, :accounts, :services])
semantic = Map.put(plan, :configuration, semantic_config) |> plain.(plain)
policy = tagged.(compiled_policy, tagged)
[_, version] = String.split(File.read!(Path.join(root, "releases/start_erl.data")))
{:ok, [system_config]} = :file.consult(String.to_charlist(Path.join([root, "releases", version, "sys.config"])))
gao_config = Keyword.get(system_config, :gao_bus, [])
consumer_limits = %{name_limits: %{per_peer: plan.xml_limits["max_names_per_connection"],
    global: Keyword.get(gao_config, :max_name_entries, 8192)},
  match_limits: %{per_peer: plan.xml_limits["max_match_rules_per_connection"],
    global: Keyword.get(gao_config, :max_match_entries, 8192)}}
runtime_code_expected = Map.new(Path.wildcard(Path.join(root, "lib/{gao_bus,ex_d_bus}-*/ebin/*.beam")), fn path ->
  {:ok, {module, md5}} = :beam_lib.md5(File.read!(path))
  {Atom.to_string(module), %{path: Path.relative_to(path, root), md5: Base.encode16(md5, case: :lower)}}
end)
61 = map_size(runtime_code_expected)
etf = :erlang.term_to_binary(plan, [:deterministic])
File.write!(out <> ".etf", etf)
display = %{schema: 1, full_plan: tagged.(plan, tagged), semantic: semantic,
  compiled_policy: policy, compiled_policy_semantic: plain.(compiled_policy, plain),
  consumer_limits: consumer_limits, runtime_code_expected: runtime_code_expected,
  preview_filesystem_observations_only: true,
  application_started_before: Enum.map(before, &Atom.to_string/1),
  application_started_after: Enum.map(after_apps, &Atom.to_string/1),
  legacy_egress_override_rejected: true}
File.write!(out <> ".json", :json.encode(display))
'''


def preview_plan(frozen, xml_path, accounts=None):
    """Pure packaged Config/Runtime preview; owned temporary files only."""
    frozen, xml_path = Path(frozen).resolve(), Path(xml_path).resolve()
    manifest = verify_package(frozen)
    tool = Path(manifest['inspection_elixir']['path'])
    assert digest(tool) == manifest['inspection_elixir']['sha256'], 'pinned inspection Elixir drift'
    with tempfile.TemporaryDirectory(prefix='osbus-p08-plan-') as temporary:
        temporary = Path(temporary)
        (temporary/'config').mkdir()
        configuration = temporary/'config/bus.conf'
        configuration.write_bytes(xml_path.read_bytes())
        configuration.chmod(0o644)
        (temporary/'accounts.json').write_text(json.dumps(accounts or account_contract()))
        plan = temporary/'plan'
        env = {key: value for key, value in os.environ.items()
               if key not in ('ERL_FLAGS', 'ELIXIR_ERL_OPTIONS', 'ERL_AFLAGS', 'ERL_ZFLAGS')}
        env.update(OSBUS_CAPTURE_PACKAGE=str(frozen/'release'), OSBUS_CAPTURE_CONFIG=str(configuration),
                   OSBUS_CAPTURE_PLAN=str(plan), OSBUS_CAPTURE_ACCOUNTS=str(temporary/'accounts.json'))
        command = [str(tool), '--erl', '+S 2:2']
        for path in sorted((frozen/'release/lib').glob('*/ebin')):
            command += ['-pa', str(path)]
        command += ['-e', PLAN_CODE]
        result = subprocess.run(command, cwd=temporary, env=env, capture_output=True, timeout=30)
        assert result.returncode == 0, ('pure packaged preview failed', result.stdout.decode(), result.stderr.decode())
        raw = (temporary/'plan.etf').read_bytes()
        display = json.loads((temporary/'plan.json').read_text())
        semantic = display['semantic']
        capacities = {'safety_limits': semantic['safety_limits'], 'xml_limits': semantic['xml_limits'],
                      'pending_limits': dict(semantic['router_options'])['pending_limits'],
                      **display['consumer_limits']}
        validate_capacities(capacities)
        verify_package(frozen)
        return {'etf': raw, 'display': display, 'semantic': semantic, 'capacities': capacities,
                'runtime_code_expected': display['runtime_code_expected'],
                'etf_sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                'execution': {'command': command, 'exit_code': result.returncode,
                              'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
                              'no_product_application_started': True}}


def preview(frozen_package, mode='preflight', fixture_dir=FIXTURES):
    frozen, fixture_dir = Path(frozen_package).resolve(), Path(fixture_dir).resolve()
    package = verify_package(frozen)
    assert len(package['sources']) == 80 and len(package['metadata']['beams']) == 61, 'frozen8 source/module coverage'
    record = json.loads((frozen/'build-record.json').read_text())
    assert digest(frozen/'build-record.json') == package['build_record_sha256'], 'build-record binding drift'
    build = Path(next(value.split('=', 1)[1] for value in record['argv'] if value.startswith('MIX_BUILD_PATH='))).resolve()
    metadata = package_helpers()['metadata'](frozen/'release', build)
    assert metadata == package['metadata'], 'independent production/package BEAM mapping drift'
    fixtures = fixture_state(fixture_dir)
    for name, expected in LEGACY.items():
        assert fixtures[name]['sha256'] == expected, ('legacy fixture drift', name)
    validate_policy_fixture(fixture_dir)
    assert digest(ROOT / DESIGN_PATH) == DESIGN_SHA256, 'adopted policy design drift'
    contract = policy_contract()
    required = ['packaged_policy.xml', POLICY_FIXTURE, 'packaged_wire_policy_test.exs',
                'packaged_policy_actor.py', 'packaged_policy_probe.py', 'test_packaged_policy_probe.py',
                'packaged_inspection.exs', 'packaged_console.py',
                'packaged_capture.py', 'packaged_qualify.py', 'packaged_test.nix',
                'test_packaged_console.py', 'test_packaged_capture.py', 'test_packaged_controller.py',
                'test_packaged_policy_integration.py',
                'packaged_inspection_test.exs', 'packaged_policy_test.exs']
    assert set(required) <= set(fixtures), ('packaged fixture freeze incomplete', sorted(set(required)-set(fixtures)))
    workload = workload_contract(fixture_dir/'workload.json')
    plan = preview_plan(frozen, fixture_dir/POLICY_FIXTURE)
    startup = startup_contract()
    validate_startup(startup)
    manifest = {'schema': 2, 'fixture': 'packaged-local-console-soak', **run_contract(mode),
                'workload': workload, 'package': {'manifest_sha256': PACKAGE_SHA256, 'manifest': package,
                                                'guest_release_path': GUEST_RELEASE},
                'fixtures': fixtures, 'xml': {'path': GUEST_CONFIG, **fixtures[POLICY_FIXTURE]},
                'policy_contract': contract,
                'accounts': account_contract(), 'startup': startup,
                'runtime_plan': {key: plan[key] for key in ('etf_sha256', 'bytes', 'semantic')},
                'capacities': {'development': {key: copy.deepcopy(workload['content'][key])
                                               for key in ('pending', 'queue', 'max_name_entries', 'max_match_entries')},
                               'packaged': plan['capacities'],
                               'rationale': 'Normal XML Runtime.compile supplies protocol/message headroom and default global quotas; v1 observation ceilings remain unchanged. No runtime overrides are applied.',
                               'unqualified_boundary_claims': ['universal native-policy equivalence', 'identical development enforcement', 'larger packaged quota boundaries', 'uninstrumented start600s', 'installed activation/helper']},
                'preview_filesystem_observations_only': True, 'expected_guest_inode_equality': False}
    manifest['runtime_plan']['compiled_policy_semantic'] = plan['display']['compiled_policy_semantic']
    manifest['runtime_code_expected'] = plan['runtime_code_expected']
    assert fixture_state(fixture_dir) == fixtures, 'fixture changed during preview'
    verify_package(frozen)
    return {'manifest': manifest, 'plan': plan, 'xml_bytes': (fixture_dir/POLICY_FIXTURE).read_bytes()}


def freeze(frozen_package, new_destination, mode='preflight', fixture_dir=FIXTURES):
    destination = Path(new_destination).resolve()
    assert not destination.exists(), 'packaged capture destination must be new'
    result = preview(frozen_package, mode, fixture_dir)
    destination.mkdir(mode=0o700)
    # Preserve a failed attempt rather than deleting evidence if a later check fails.
    shutil.copytree(Path(frozen_package)/'release', destination/'release', symlinks=True, copy_function=shutil.copy2)
    shutil.copyfile(Path(frozen_package)/'release.json', destination/'release.json')
    shutil.copyfile(Path(frozen_package)/'build-record.json', destination/'build-record.json')
    shutil.copyfile(ROOT / DESIGN_PATH, destination/'policy-design.md')
    (destination/'config').mkdir()
    (destination/'config/bus.conf').write_bytes(result['xml_bytes'])
    (destination/'config/bus.conf').chmod(0o644)
    (destination/'plan.etf').write_bytes(result['plan']['etf'])
    (destination/'plan.json').write_text(json.dumps(result['plan']['display'], sort_keys=True, indent=2)+'\n')
    (destination/'preview-execution.json').write_text(json.dumps(result['plan']['execution'], sort_keys=True, indent=2)+'\n')
    assert inventory(destination/'release') == result['manifest']['package']['manifest']['inventory'], 'copied package inventory drift'
    assert fixture_state(fixture_dir) == result['manifest']['fixtures'], 'fixture changed during freeze'
    verify_package(frozen_package)
    result['manifest']['plan_json_sha256'] = digest(destination/'plan.json')
    (destination/'packaged.json').write_text(json.dumps(result['manifest'], sort_keys=True, indent=2)+'\n')
    return result['manifest']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frozen_package', type=Path)
    parser.add_argument('new_destination', type=Path)
    parser.add_argument('--mode', choices=('preflight', 'soak'), required=True)
    args = parser.parse_args()
    result = freeze(args.frozen_package, args.new_destination, args.mode)
    print(json.dumps({'capture': str(args.new_destination.resolve()), 'schema': result['schema'],
                      'mode': result['mode'], 'manifest_sha256': digest(args.new_destination/'packaged.json')}))
