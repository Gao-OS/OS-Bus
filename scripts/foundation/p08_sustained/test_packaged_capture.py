"""Pure packaged capture contract tests; no release/application/VM startup."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def implementation():
    spec = importlib.util.find_spec('packaged_capture')
    if spec is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaptureContractTests(unittest.TestCase):
    def setUp(self):
        self.module = implementation()
        self.assertIsNotNone(self.module, 'packaged schema2 capture implementation missing')
        self.workload = json.loads(Path(__file__).with_name('workload.json').read_text())

    def test_standard_policy_contract_preserves_original_failure_and_binds_new_design(self):
        contract = self.module.policy_contract()
        self.assertEqual(contract['kind'], 'standard-XML-valid-wire')
        self.assertEqual(contract['fixture'], 'packaged_wire_policy.xml')
        self.assertEqual(contract['universal_native_equivalence'], 'BLOCKED_DESIGN')
        self.assertEqual(contract['legacy_comparison'], {'tests': 3, 'failed': 1, 'mismatches': 8, 'decisions': 400})
        self.assertEqual(contract['valid_wire_delta'], {'uid': 1101, 'action': 'receive',
                         'type': 'method_call', 'interface': None, 'native': 'allow', 'xml': 'deny'})
        self.assertEqual(contract['design']['sha256'], '0c3c1266d08680003940efcadd42c917b0ca39a041b41eed7dec500186c246cd')

    def test_only_typed_interface_denial_is_a_permitted_XML_change(self):
        fixture = Path(__file__).parent
        self.module.validate_policy_fixture(fixture)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('policy.exs', 'packaged_policy.xml', 'packaged_policy_test.exs', 'packaged_wire_policy.xml'):
                (root / name).write_bytes((fixture / name).read_bytes())
            source = (root / 'packaged_wire_policy.xml').read_bytes()
            for change in (source.replace(b'user="1101"', b'user="9999"'),
                           source.replace(b'own_prefix="org.foundation.Service"', b'own="*"'),
                           (fixture / 'packaged_policy.xml').read_bytes()):
                (root / 'packaged_wire_policy.xml').write_bytes(change)
                with self.assertRaises(AssertionError):
                    self.module.validate_policy_fixture(root)

    def test_workload_numeric_contract_preserves_every_nested_number(self):
        result = self.module.workload_contract(Path(__file__).with_name('workload.json'))
        self.assertEqual(result['content'], self.workload)
        self.assertEqual(result['numerical_observation_ceilings']['queue.peer_bytes'], 262144)
        self.assertEqual(result['numerical_observation_ceilings']['pending.global'], 16)
        self.assertEqual(result['numerical_observation_ceilings']['seed'], 1703)
        self.assertEqual(result['sha256'], hashlib.sha256(Path(__file__).with_name('workload.json').read_bytes()).hexdigest())

    def test_mutated_workload_is_rejected_instead_of_refrozen(self):
        for path, value in [('warmup_operations', 99), ('packaged_duration_seconds', 599),
                            ('seed', 42), ('operations', ['transfer'])]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                data = copy.deepcopy(self.workload)
                data[path] = value
                file = Path(directory)/'workload.json'
                file.write_text(json.dumps(data))
                with self.assertRaises(AssertionError):
                    self.module.workload_contract(file)

    def test_duration_modes_do_not_change_required_work(self):
        for mode, duration, qualifying in [('preflight', 10, False), ('soak', 600, True)]:
            contract = self.module.run_contract(mode)
            self.assertEqual(contract['duration_seconds'], duration)
            self.assertEqual(contract['qualifying'], qualifying)
            self.assertEqual(contract['warmup_operations'], 100)
            self.assertEqual(contract['batches'], 3)
            self.assertEqual(contract['operations_per_batch'], 1000)
            self.assertEqual(contract['duration_starts_after_verified_batches'], True)
        with self.assertRaises(AssertionError):
            self.module.run_contract('development')

    def test_startup_has_fixed_nondistributed_private_package_contract(self):
        startup = self.module.startup_contract()
        self.module.validate_startup(startup)
        self.assertEqual(startup['modes'], ['start', 'start_iex'])
        self.assertEqual(startup['release_path'], '/run/osbus-p08/package/release')
        self.assertEqual(startup['unit']['Type'], 'notify')
        self.assertEqual(startup['unit']['User'], 'messagebus')
        for mutate in [lambda d: d['environment'].update(RELEASE_DISTRIBUTION='name'),
                       lambda d: d['environment'].update(DBUS_SOCKET_PATH='/run/dbus/system_bus_socket'),
                       lambda d: d['unit'].update(User='root'),
                       lambda d: d.update(modes=['start_iex'])]:
            data = copy.deepcopy(startup)
            mutate(data)
            with self.assertRaises(AssertionError):
                self.module.validate_startup(data)

    def test_accounts_have_real_primary_groups_and_no_implicit_daemon_admission(self):
        accounts = self.module.account_contract()
        self.assertEqual(accounts['user_records']['foundationA']['gid'], 100)
        self.assertEqual(accounts['memberships']['1101'], [100])
        self.assertEqual(accounts['user_records']['messagebus']['groups'], [4])
        self.assertEqual(accounts['guest_must_reverify'], True)

    def package(self, directory):
        root = Path(directory)
        release = root/'frozen'/'release'
        (release/'bin').mkdir(parents=True)
        (release/'bin/os_bus').write_text('launcher')
        source = root/'source.ex'
        source.write_text('current source')
        production = root/'production.beam'
        production.write_bytes(b'beam')
        (release/'module.beam').write_bytes(b'beam')
        manifest = dict(schema=1, not_a_release=False, sources={'source.ex': self.module.digest(source)},
                        inventory=self.module.inventory(release), metadata={'beams': [dict(
                            source=str(source), production_beam=str(production),
                            production_sha256=self.module.digest(production), beam='module.beam',
                            packaged_sha256=self.module.digest(release/'module.beam'))]})
        (root/'frozen/release.json').write_text(json.dumps(manifest))
        return root, root/'frozen'

    def test_package_source_production_and_whole_inventory_freshness(self):
        for mutation in [None, 'source', 'production', 'extra', 'mode']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root, frozen = self.package(directory)
                expected = self.module.digest(frozen/'release.json')
                if mutation == 'source':
                    (root/'source.ex').write_text('drift')
                elif mutation == 'production':
                    (root/'production.beam').write_bytes(b'drift')
                elif mutation == 'extra':
                    (frozen/'release/unrecorded').write_text('extra')
                elif mutation == 'mode':
                    (frozen/'release/module.beam').chmod(0o600)
                if mutation:
                    with self.assertRaises(AssertionError):
                        self.module.verify_package(frozen, root, expected)
                else:
                    result = self.module.verify_package(frozen, root, expected)
                    self.assertEqual(len(result['sources']), 1)

    def test_development_capture_and_wrong_manifest_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, frozen = self.package(directory)
            with self.assertRaises(AssertionError):
                self.module.verify_package(frozen, root, '0'*64)
            data = json.loads((frozen/'release.json').read_text())
            data['not_a_release'] = True
            (frozen/'release.json').write_text(json.dumps(data))
            with self.assertRaises(AssertionError):
                self.module.verify_package(frozen, root, self.module.digest(frozen/'release.json'))

    def test_fixture_binding_includes_tests_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'test.py').write_text('test bytes')
            (root/'fixture.exs').write_text('fixture bytes')
            self.assertEqual(set(self.module.fixture_state(root)), {'test.py', 'fixture.exs'})
            (root/'alias.py').symlink_to('test.py')
            with self.assertRaises(AssertionError):
                self.module.fixture_state(root)

    def test_capacity_drift_or_development_enforcement_cannot_pass(self):
        plan = self.module.expected_capacities()
        self.module.validate_capacities(plan)
        self.assertEqual(plan['pending_limits']['global'], 4096)
        self.assertEqual(plan['safety_limits']['peer']['egress_bytes'], 134479872)
        self.assertEqual(plan.get('name_limits'), {'per_peer': 4, 'global': 8192})
        self.assertEqual(plan.get('match_limits'), {'per_peer': 4, 'global': 8192})
        for scope, metric, value in [('peer', 'egress_bytes', 262144),
                                     ('global', 'ingress_bytes', 1048576)]:
            changed = copy.deepcopy(plan)
            changed['safety_limits'][scope][metric] = value
            with self.assertRaises(AssertionError):
                self.module.validate_capacities(changed)

    def test_actual_packaged_plan_is_semantically_stable_and_starts_no_product_app(self):
        frozen = self.module.ROOT/'test/reports/foundation/continuation-20261011-full-goal/environment/p08-packaged-current-capture/frozen8'
        xml = Path(__file__).with_name('packaged_wire_policy.xml')
        first = self.module.preview_plan(frozen, xml)
        second = self.module.preview_plan(frozen, xml)
        self.assertEqual(first['semantic'], second['semantic'])
        self.assertEqual(hashlib.sha256(first['etf']).hexdigest(), first['etf_sha256'])
        self.assertEqual(len(first['etf']), first['bytes'])
        self.assertIn('$map', first['display']['full_plan'])
        self.assertIsNone(first['semantic']['configuration']['accounts']['user_records']['messagebus']['provenance'])
        for field in ['application_started_before', 'application_started_after']:
            self.assertNotIn('gao_bus', first['display'][field])
            self.assertNotIn('ex_d_bus', first['display'][field])
        self.assertEqual(first['display']['legacy_egress_override_rejected'], True)
        expected_code = first.get('runtime_code_expected', {})
        self.assertEqual(len(expected_code), 61)
        for module in ['Elixir.GaoBus.Config', 'Elixir.GaoBus.Router', 'Elixir.ExDBus.Message']:
            self.assertIn(module, expected_code)
        for row in expected_code.values():
            self.assertRegex(row['md5'], r'^[0-9a-f]{32}$')
            self.assertTrue(row['path'].startswith(('lib/gao_bus-', 'lib/ex_d_bus-')))


if __name__ == '__main__':
    unittest.main()
