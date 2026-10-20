"""Root-only disposable-guest entry over exact corrected RES01 bytes."""
import hashlib
import json
import os
from pathlib import Path
import sys

from measurement import Recorder, apply_recipe, install_channel

HERE = Path(__file__).resolve().parent


def main(candidate, original, evidence):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security/res01'
    bindings = json.loads((HERE / 'BASE_BINDINGS1.json').read_text())
    recipe_bytes = (HERE / 'recipe1.json').read_bytes()
    recipes = json.loads(recipe_bytes)
    base = Path(os.environ['RES01_MEASUREMENT_BASE'])
    for name in ('run.py', 'launcher.exs', 'actor.py', 'cleanup.py', 'workload.json'):
        assert hashlib.sha256((base / name).read_bytes()).hexdigest() == bindings[name]['sha256']
    for name in ('actor.py', 'cleanup.py', 'workload.json'):
        assert (HERE / name).read_bytes() == (base / name).read_bytes()
    assert hashlib.sha256((original / 'run.py').read_bytes()).hexdigest() == bindings['original/run.py']['sha256']
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert hashlib.sha256((candidate / 'candidate.json').read_bytes()).hexdigest() == '372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'
    assert manifest['source_sha256'] == 'efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'
    measurement = Recorder()
    transformed = apply_recipe((base / 'run.py').read_text(), recipes['runner'])
    measurement.provenance = dict(base_bindings=bindings,
        recipe_sha256=hashlib.sha256(recipe_bytes).hexdigest(),
        runner_transformed_sha256=hashlib.sha256(transformed.encode()).hexdigest(),
        sources={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file()})
    namespace = dict(__name__='res01_measurement_base', __file__=str(HERE / 'run.py'),
        measurement=measurement, measurement_install_channel=install_channel,
        measurement_recipes=recipes, measurement_bindings=bindings)
    exec(compile(transformed, str(base / 'run.py') + ':measurement', 'exec'), namespace)
    try:
        namespace['main'](candidate, original, evidence)
    finally:
        # Base main's existing finally has already attempted actor/daemon cleanup.
        measurement.checkpoint(evidence)
    auxiliary = json.loads((evidence / 'measurement.json').read_text())
    assert auxiliary['overflow'] is False and auxiliary['daemon'] is not None
    assert auxiliary['daemon']['overflow'] is False and auxiliary['daemon']['snapshot_count'] > 0
    assert {'request', 'request_begin', 'request_read', 'receipt_append', 'receipt_persist',
        'settle', 'settle_write', 'settle_flush', 'settle_read', 'settle_validate', 'settle_state_compare',
        'channel_read', 'channel_select', 'channel_os_read', 'channel_line_log_append',
        'channel_json_parse'} <= {event['boundary'] for event in auxiliary['python_events']}
    assert {'snapshot_complete', 'original_snapshot', 'original_limits_snapshot', 'extension_limits_snapshot',
        'limits_authority_state', 'names_authority_state', 'matches_authority_state', 'peer_state',
        'json_safe_mapping', 'emit_json_encode', 'emit_stdout_write_flush'} <= {
        event['boundary'] for event in auxiliary['daemon']['events']}
    print(json.dumps(dict(result='diagnostic_timing_recorded', diagnostic_only=True,
        product_qualified=False, readiness='L0')))


if __name__ == '__main__':
    assert len(sys.argv) == 4
    main(*(Path(arg) for arg in sys.argv[1:]))
