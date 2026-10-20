"""Strict immutable-source inventory and disposable copied-package installation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import packaged_qualify as implementation


class PackageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o755)
        (self.source / 'bin').mkdir(mode=0o755)
        (self.source / 'bin/launcher').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.source / 'bin/launcher').chmod(0o755)
        (self.source / 'data').write_bytes(b'frozen data\n')
        (self.source / 'data').chmod(0o644)
        (self.source / 'readonly').write_bytes(b'read only\n')
        (self.source / 'readonly').chmod(0o444)
        (self.source / 'link').symlink_to('data')
        self.expected = implementation.inventory(self.source)
        # Independently reproduce the documented builtins.path import contract.
        for name, row in self.expected.items():
            if row['type'] != 'symlink':
                (self.source / name).chmod(0o555 if row['type'] == 'directory' or row['mode'] & 0o111 else 0o444)
        self.source.chmod(0o555)
        self.base = self.root / 'guest'
        self.base.mkdir(mode=0o755)
        self.destination = self.base / 'package/release'

    def function(self, name):
        function = getattr(implementation, name, None)
        self.assertTrue(callable(function), 'missing required inventory helper: ' + name)
        return function

    def verify(self, expected=None):
        return self.function('verify_nix_inventory')(self.source, self.expected if expected is None else expected)

    def install(self, destination=None):
        with patch.object(implementation, 'BASE', self.base):
            return self.function('install_release')(self.source, self.destination if destination is None else destination, self.expected)

    def test_exact_normalized_source_is_accepted_without_mutation(self):
        before = implementation.inventory(self.source)
        self.verify()
        self.assertEqual(implementation.inventory(self.source), before)

    def test_wrong_mode_bytes_target_missing_or_extra_path_are_rejected(self):
        def changed_bytes():
            (self.source / 'data').chmod(0o644)
            (self.source / 'data').write_bytes(b'changed data\n')
            (self.source / 'data').chmod(0o444)

        mutations = [lambda: (self.source / 'data').chmod(0o644),
                     changed_bytes,
                     lambda: ((self.source / 'link').unlink(), (self.source / 'link').symlink_to('readonly')),
                     lambda: (self.source / 'data').unlink(),
                     lambda: (self.source / 'extra').write_bytes(b'unrecorded')]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                clone = self.root / ('mutation-%d' % index)
                shutil.copytree(self.source, clone, symlinks=True)
                original = self.source
                self.source = clone
                try:
                    clone.chmod(0o755)
                    mutate()
                    clone.chmod(0o555)
                    with self.assertRaises(AssertionError):
                        self.verify()
                finally:
                    self.source = original

    def test_privileged_actual_or_original_modes_are_rejected(self):
        for mode in (0o4755, 0o2755):
            with self.subTest(mode=oct(mode)):
                invalid = copy.deepcopy(self.expected)
                invalid['bin/launcher']['mode'] = mode
                with self.assertRaises(AssertionError):
                    self.verify(invalid)
                (self.source / 'bin/launcher').chmod(mode)
                try:
                    with self.assertRaises(AssertionError):
                        self.verify()
                finally:
                    (self.source / 'bin/launcher').chmod(0o555)

    def test_unsafe_manifest_paths_and_writable_original_modes_are_rejected(self):
        for name in ('../escape', '/absolute', '.', 'bin/../escape', 'bin//launcher', 'bin/./launcher', 'bad\x00path'):
            with self.subTest(name=name):
                invalid = dict(self.expected, **{name: self.expected['data']})
                with self.assertRaises(AssertionError):
                    self.verify(invalid)
        for mode in (0o666, 0o775, True):
            invalid = copy.deepcopy(self.expected)
            invalid['data']['mode'] = mode
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                self.verify(invalid)

    def test_source_root_cannot_be_symlink_or_mutable(self):
        alias = self.root / 'source-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(AssertionError):
            self.function('verify_nix_inventory')(alias, self.expected)
        for mode in (0o755, 0o4555):
            self.source.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(AssertionError):
                self.verify()
        self.source.chmod(0o555)

    def test_copy_restores_complete_original_modes_and_never_chmods_symlinks(self):
        source_before = implementation.inventory(self.source)
        chmod = Path.chmod
        seen = []

        def guarded_chmod(path, mode, *args, **kwargs):
            self.assertFalse(path.is_symlink(), 'chmod would follow a symlink')
            self.assertTrue(path.is_relative_to(self.destination), 'chmod outside copied release')
            seen.append(str(path.relative_to(self.destination)))
            return chmod(path, mode, *args, **kwargs)

        # copytree/copy2 legitimately retain symlink metadata with follow_symlinks=False;
        # restoration itself must never invoke Path.chmod on symlinks.
        with patch.object(Path, 'chmod', guarded_chmod):
            self.install()
        self.assertEqual(implementation.inventory(self.destination), self.expected)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)
        self.assertNotIn('link', seen)
        self.assertEqual(implementation.inventory(self.source), source_before)

    def test_only_fresh_fixture_owned_destination_is_allowed(self):
        for destination in (self.root / 'unowned/release', self.base / 'another/release'):
            with self.subTest(destination=destination), self.assertRaises(AssertionError):
                self.install(destination)
            self.assertFalse(destination.parent.exists())
        self.destination.parent.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(AssertionError):
            self.install()
        self.assertEqual(implementation.inventory(self.source), {name: dict(row, mode=row['mode'] if row['type'] == 'symlink' else (0o555 if row['type'] == 'directory' or row['mode'] & 0o111 else 0o444)) for name, row in self.expected.items()})

    def test_copy_bytes_or_root_replacement_cannot_pass_postcopy_verification(self):
        real_copy = shutil.copytree
        for replace_root in (False, True):
            with self.subTest(replace_root=replace_root):
                def corrupt_copy(source, destination, *args, **kwargs):
                    result = real_copy(source, destination, *args, **kwargs)
                    if Path(destination) != self.destination:
                        return result
                    if replace_root:
                        renamed = destination.with_name('replacement')
                        destination.rename(renamed)
                        destination.symlink_to(renamed, target_is_directory=True)
                    else:
                        (destination / 'data').chmod(0o644)
                        (destination / 'data').write_bytes(b'corrupted copy')
                        (destination / 'data').chmod(0o444)
                    return result

                with patch.object(implementation.shutil, 'copytree', corrupt_copy), self.assertRaises(AssertionError):
                    self.install()
                if self.destination.parent.exists():
                    for path in self.destination.parent.rglob('*'):
                        if path.is_dir() and not path.is_symlink():
                            path.chmod(0o755)
                    shutil.rmtree(self.destination.parent)

    def make_guest(self):
        frozen = self.root / 'frozen'
        capture = self.root / 'capture'
        for directory in (frozen, capture):
            directory.mkdir()
            shutil.copytree(self.source, directory / 'release', symlinks=True)
            (directory / 'release.json').write_text(json.dumps({'inventory': self.expected}))
        (capture / 'plan.json').write_bytes(b'{}\n')
        (capture / 'plan.etf').write_bytes(b'\x83term')
        (capture / 'config').mkdir()
        (capture / 'config/bus.conf').write_bytes(b'<busconfig/>\n')
        home = self.root / 'home'
        home.mkdir()
        guest = object.__new__(implementation.Guest)
        guest.frozen, guest.capture, guest.release = frozen, capture, self.destination
        guest.report = {}
        guest.manifest = dict(package=dict(manifest=dict(inventory=self.expected), manifest_sha256=implementation.digest(capture / 'release.json')),
                              fixtures={}, plan_json_sha256=implementation.digest(capture / 'plan.json'),
                              runtime_plan=dict(etf_sha256=implementation.digest(capture / 'plan.etf'), bytes=5),
                              accounts=dict(user_records={}), xml=dict(sha256=implementation.digest(capture / 'config/bus.conf')))
        return guest, home

    def test_real_guest_install_call_copies_restores_and_verifies_both_sources(self):
        guest, home = self.make_guest()
        with patch.object(implementation, 'BASE', self.base), \
             patch.object(implementation.os, 'chown') as chown, \
             patch.object(implementation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_dir=str(home))):
            guest.install()
        self.assertEqual(guest.report['inventory_before'], self.expected)
        self.assertEqual(implementation.inventory(self.destination), self.expected)
        self.assertEqual(chown.call_count, 3)
        self.assertTrue(guest.report['iex_initialization']['absent'])

    def test_real_guest_install_rejects_either_source_before_copy(self):
        guest, _ = self.make_guest()
        for directory in (guest.frozen, guest.capture):
            path = directory / 'release/data'
            path.chmod(0o644)
            try:
                with self.subTest(directory=directory), patch.object(implementation, 'BASE', self.base), self.assertRaises(AssertionError):
                    guest.install()
                self.assertFalse(self.destination.parent.exists())
            finally:
                path.chmod(0o444)

    def test_selected_actual_store_gate_cannot_succeed_without_source_environment(self):
        result = unittest.TestResult()
        case = ActualStoreInventoryTests('test_current_imported_811_entry_package_has_exact_nix_modes_and_original_content')
        with patch.dict(os.environ):
            os.environ.pop('OSBUS_P08_INVENTORY_STORE', None)
            case.run(result)
        self.assertEqual(len(result.failures), 1, 'missing required store source must fail the selected gate')
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])


class ActualStoreInventoryTests(unittest.TestCase):
    def test_current_imported_811_entry_package_has_exact_nix_modes_and_original_content(self):
        # Explicit opt-in source: missing supplied package must fail, never skip.
        source = os.environ.get('OSBUS_P08_INVENTORY_STORE')
        self.assertIsNotNone(source, 'BLOCKED_ENV: required immutable package source OSBUS_P08_INVENTORY_STORE is missing')
        root = Path(source)
        self.assertTrue(root.is_absolute() and root.is_relative_to('/nix/store'))
        manifest_bytes = (root / 'release.json').read_bytes()
        manifest = json.loads(manifest_bytes)
        verify = getattr(implementation, 'verify_nix_inventory', None)
        self.assertTrue(callable(verify), 'missing required immutable inventory verification')
        actual = implementation.inventory(root / 'release')
        self.assertEqual(len(actual), len(manifest['inventory']))
        verify(root / 'release', manifest['inventory'])
        self.assertEqual((root / 'release.json').read_bytes(), manifest_bytes)
        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), 'dde56f6cfb2986356c382e61e2aa332020692a25c3ab9a03827fdce665289e48')


if __name__ == '__main__':
    unittest.main()
