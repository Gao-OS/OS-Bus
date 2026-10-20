"""Inert execution of the actual abrupt helper; no daemon, process or signal."""
import ast
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from contract import validate_abrupt
from test_contract import witness


def actual_original_import(directory):
    """Import retained bytes only; fail immediately on process/socket activity."""
    spec = importlib.util.spec_from_file_location('uid_original_transport', directory / 'run.py')
    legacy = importlib.util.module_from_spec(spec)
    operations = [(subprocess, name) for name in ('Popen', 'run', 'call', 'check_call', 'check_output')]
    operations += [(socket, name) for name in ('socket', 'socketpair', 'create_connection')]
    operations += [(os, name) for name in dir(os)
                   if name.startswith(('exec', 'spawn', 'posix_spawn')) or
                   name in ('fork', 'forkpty', 'system', 'kill', 'killpg')]
    with ExitStack() as stack:
        guards = [stack.enter_context(patch.object(module, name,
                  side_effect=AssertionError('import attempted activity: ' + name)))
                  for module, name in operations]
        stack.enter_context(patch.object(sys, 'path', [str(directory), *sys.path]))
        stack.enter_context(patch.object(sys, 'dont_write_bytecode', True))
        actor = sys.modules.pop('actor', None)
        try:
            spec.loader.exec_module(legacy)
        finally:
            sys.modules.pop('actor', None)
            if actor is not None:
                sys.modules['actor'] = actor
            for guard in guards:
                guard.assert_not_called()
    return legacy


class OriginalImportControls(unittest.TestCase):
    def test_actual_security_import_complete_package(self):
        source = Path(__file__).parent / 'inherited/security'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'security'
            shutil.copytree(source, directory)
            before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
            legacy = actual_original_import(directory)
            workload = (directory / 'workload.json').read_bytes()
            self.assertEqual(hashlib.sha256(workload).hexdigest(),
                             '91d73a1c70885287b07642b2bf63921733d288a469c51f0d649e702edda5151a')
            self.assertEqual(legacy.WORKLOAD, json.loads(workload))
            self.assertEqual(legacy.SELECTED, json.loads(workload)['selected'])
            self.assertEqual(legacy.__name__, 'uid_original_transport')
            self.assertEqual(Path(legacy.packet.__code__.co_filename), directory / 'actor.py')
            self.assertEqual({p.relative_to(directory): p.read_bytes()
                              for p in directory.rglob('*') if p.is_file()}, before)

    def test_actual_security_import_omitted_workload(self):
        source = Path(__file__).parent / 'inherited/security'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'security'
            shutil.copytree(source, directory, ignore=shutil.ignore_patterns('workload.json'))
            before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
            with self.assertRaises(FileNotFoundError) as caught:
                actual_original_import(directory)
            self.assertEqual(caught.exception.filename, str(directory / 'workload.json'))
            self.assertEqual(caught.exception.errno, 2)
            self.assertEqual({p.relative_to(directory): p.read_bytes()
                              for p in directory.rglob('*') if p.is_file()}, before)

    def test_workload_has_original_and_inherited_package_pins(self):
        directory = Path(__file__).parent
        source = ast.parse((directory / 'run.py').read_text())
        pins, = [ast.literal_eval(node.value) for node in source.body
                 if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                 target.id == 'ORIGINAL_PINS' for target in node.targets)]
        manifest = json.loads((directory / 'INHERITED_INPUTS.json').read_text())['inputs']
        inherited = manifest['scripts/foundation/vm_security/workload.json']
        workload = directory / 'inherited/security/workload.json'
        self.assertEqual(pins['workload.json'],
                         '91d73a1c70885287b07642b2bf63921733d288a469c51f0d649e702edda5151a')
        self.assertEqual(inherited['sha256'], pins['workload.json'])
        self.assertEqual(inherited['frozen'],
                         'scripts/foundation/m1_uid_abrupt_peer/inherited/security/workload.json')
        self.assertEqual(inherited['size'], len(workload.read_bytes()))
        self.assertEqual(inherited['mode'], oct(workload.stat().st_mode & 0o777))
        self.assertEqual(hashlib.sha256(workload.read_bytes()).hexdigest(), inherited['sha256'])


def actual_abrupt(model):
    source = Path(__file__).with_name('run.py')
    tree = ast.parse(source.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    abrupt = [node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'abrupt']
    assert len(abrupt) == 1
    module = ast.fix_missing_locations(ast.Module(body=copy.deepcopy(abrupt), type_ignores=[]))
    namespace = dict(settle=model.settle, identity=model.identity, time=model.clock,
                     deadline=60, daemon=model.daemon, healthy=model.healthy,
                     remaining=lambda bound: bound - model.now, report=model.report,
                     observer=model.observer, validate_abrupt=validate_abrupt,
                     request=model.request, retire=model.retire)
    exec(compile(module, str(source), 'exec'), namespace)
    return namespace['abrupt']


class Model:
    def __init__(self):
        self.event, self.before, self.after, join = witness()
        self.actor = dict(join=join, identity=join['identity'], unique=join['unique'], active=True)
        self.observer = {'join': {'peer': '#PID<0.3.0>', 'unique': ':1.3'}}
        self.report = {'abrupt_kills': []}
        self.row = {}
        self.calls, self.now, self.samples = [], 0, 0
        self.clock = SimpleNamespace(monotonic=self.monotonic)
        self.daemon = SimpleNamespace(process=SimpleNamespace(stdin=SimpleNamespace(
            write=self.write, flush=lambda: self.calls.append('flush'))), read=self.read)

    def monotonic(self):
        self.now += 0.001
        return self.now

    def identity(self, pid, uid):
        self.calls.append(('kernel', pid, uid))
        return 'Uid: 1100 1100 1100 1100\nGid: 1100 1100 1100 1100\n'

    def settle(self, bound=None):
        self.samples += 1
        self.calls.append(('settle', bound))
        if self.samples == 1:
            return self.before
        assert self.actor['active'] is False
        assert bound is not None
        return self.after

    def write(self, value):
        self.calls.append(('write', value))

    def read(self, timeout):
        self.calls.append(('down', timeout))
        return self.event

    def healthy(self):
        self.calls.append('healthy')

    def request(self, actor, **values):
        assert actor is self.actor and values == {'op': 'wait_closed'}
        self.calls.append('wait_closed')
        return {'closed': True}

    def retire(self, actor):
        self.calls.append('natural_actor_eof')
        actor['shutdown'] = {'method': 'eof', 'returncode': 0}


class DriverControls(unittest.TestCase):
    def test_actual_helper_checks_automatic_state_before_actor_eof(self):
        model = Model()
        actual_abrupt(model)(model.actor, model.row, 'owner_down_promotes')
        write = model.calls.index(('write', b'uid_abrupt_peer :1.2\n'))
        down = next(i for i, value in enumerate(model.calls) if isinstance(value, tuple) and value[0] == 'down')
        self.assertIn('healthy', model.calls[write:down])
        settled = max(i for i, value in enumerate(model.calls) if isinstance(value, tuple) and value[0] == 'settle')
        self.assertLess(settled, model.calls.index('wait_closed'))
        self.assertLess(model.calls.index('wait_closed'), model.calls.index('natural_actor_eof'))
        self.assertEqual(model.row['abrupt_kill_labels'], ['owner_down_promotes'])
        self.assertEqual(model.report['abrupt_kills'][0]['event'], model.event)
        self.assertEqual(model.report['abrupt_kills'][0]['after'], model.after)

    def test_original_eof_marker_cannot_enter_automatic_reclamation(self):
        model = Model()
        model.event['down']['reason'] = 'normal'
        with self.assertRaises(AssertionError):
            actual_abrupt(model)(model.actor, model.row, 'owner_down_promotes')
        self.assertNotIn('natural_actor_eof', model.calls)
        self.assertTrue(model.actor['active'])
        self.assertEqual(model.report['abrupt_kills'][0]['event']['down']['reason'], 'normal')

    def test_retained_credit_fails_before_explicit_actor_cleanup(self):
        model = Model()
        model.after['uid_authorities']['names']['uid_counts']['1100'] = 2
        with self.assertRaises(AssertionError):
            actual_abrupt(model)(model.actor, model.row, 'owner_down_promotes')
        self.assertNotIn('wait_closed', model.calls)
        self.assertNotIn('natural_actor_eof', model.calls)
        self.assertIn('after', model.report['abrupt_kills'][0])


if __name__ == '__main__':
    unittest.main()
