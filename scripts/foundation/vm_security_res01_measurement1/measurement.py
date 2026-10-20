"""Bounded auxiliary timing; preserves callback values, failures and synchronous work."""
import ast
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import time

MAX_EVENTS = 100_000


class Recorder:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.events = []
        self.context = {}
        self.overflow = False
        self.provenance = {}

    @contextmanager
    def span(self, boundary, **metadata):
        start = self.clock()
        event = dict(self.context, **metadata, boundary=boundary, clock='python_guest_monotonic',
                     started=start, error=None)
        try:
            yield event
        except BaseException as error:
            event['error'] = dict(type=type(error).__name__, detail=str(error)[:256])
            raise
        finally:
            event['finished'] = self.clock()
            event['elapsed_seconds'] = event['finished'] - start
            if len(self.events) < MAX_EVENTS:
                self.events.append(event)
            else:
                self.overflow = True
                raise AssertionError('bounded measurement event inventory exhausted')

    def timed(self, boundary, callback, **metadata):
        with self.span(boundary, **metadata) as event:
            result = callback()
            if isinstance(result, bytes):
                event['bytes'] = len(result)
            return result

    @contextmanager
    def contextual(self, **metadata):
        previous = self.context
        self.context = dict(previous, **metadata)
        try:
            yield
        finally:
            self.context = previous

    def checkpoint(self, evidence):
        """Only called after the original deferral guard or after original teardown."""
        daemon = evidence / 'daemon-measurement.json'
        daemon_records = json.loads(daemon.read_text()) if daemon.exists() else None
        payload = dict(kind='res01_timing_experiment_v1', diagnostic_only=True,
            product_qualified=False, readiness='L0', event_limit=MAX_EVENTS,
            overflow=self.overflow, python_events=self.events, daemon=daemon_records,
            provenance=self.provenance,
            clock_rule='daemon-local intervals only; no cross-clock subtraction',
            overhead='timing reads and bounded in-memory records remain inside original wall-clock deadlines')
        temporary = evidence / 'measurement.json.tmp'
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
        temporary.replace(evidence / 'measurement.json')


def apply_recipe(source, changes):
    for change in changes:
        assert set(change) == {'before', 'after', 'count'}
        assert source.count(change['before']) == change['count'], ('measurement anchor drift', change['before'])
        source = source.replace(change['before'], change['after'])
    return source


def install_channel(legacy, path, recorder, recipe, expected):
    """Replace only the original read body with exact guarded timing expressions."""
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    tree = ast.parse(data)
    channel = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Channel')
    read = next(n for n in channel.body if isinstance(n, ast.FunctionDef) and n.name == 'read')
    text = '\n'.join(line[4:] for line in data.decode().splitlines()[read.lineno - 1:read.end_lineno]) + '\n'
    transformed = apply_recipe(text, recipe)
    namespace = dict(legacy.__dict__, measurement=recorder)
    exec(compile(transformed, str(path) + ':measurement-read', 'exec'), namespace)
    legacy.Channel.read = namespace['read']
    recorder.provenance['channel_read_transformed_sha256'] = hashlib.sha256(transformed.encode()).hexdigest()
