"""Bind immutable current product bytes to the existing SEC09–12 metadata schema."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import xml.etree.ElementTree as ET

ARTIFACT_SHA = "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1"
RUNTIME_SHA = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5"
CORPUS_SHA = "992aa6dec8b021a68398757886e7173110cde28bd6c3cf54daf3a6e7b7fe88e5"
LAUNCHER_SHA = "e7836b4136a37adca89e1ef5d9ba97ebb6bb5bd4d79e22963aa0e59985d11ae6"
XML_DAEMON_SHA = "24aa74efaba361e529447d9643709d072e19e2d9d344e9883aa2361d1895d006"
XML_DAEMON_PATCHED_SHA = "d2cbdf82fa79b1eb09abf0ec1b8579a2c5c2759c361c914adc6c540059c2f564"
XML_DAEMON_CHANGES = [
    ('Application.put_env(:gao_bus, :resource_limits, GaoBus.Limits.defaults())',
     'Application.delete_env(:gao_bus, :resource_limits)'),
    ('resource_limits: GaoBus.Limits.defaults()',
     'resource_limits: elem(GaoBus.Limits.snapshot(), 1).limits')]
OLD_EMIT = 'emit = fn event -> IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(event))) end'
NEW_EMIT = 'emit = fn event -> IO.puts(["FIXTURE ", :json.encode(event)]) end'
# The ordinary emitter stays Unicode-safe. Only requested snapshots are timed;
# their full data is emitted before the small timing record is buffered.
TIMED_SNAPSHOT = '''timed_snapshot = fn ->
  began = System.monotonic_time(:nanosecond)
  event = safe_snapshot.()
  captured = System.monotonic_time(:nanosecond)
  encoded = :json.encode(event)
  encoded_at = System.monotonic_time(:nanosecond)
  IO.puts(["FIXTURE ", encoded])
  written = System.monotonic_time(:nanosecond)
  {:snapshot_timing, %{capture_ns: captured - began, encode_ns: encoded_at - captured,
    write_ns: written - encoded_at}}
end
'''
SNAPSHOT_DAEMON_CHANGES = [
    (OLD_EMIT, NEW_EMIT),
    ('Stream.repeatedly(fn -> IO.read(:stdio, :line) end)',
     TIMED_SNAPSHOT + 'Stream.repeatedly(fn -> IO.read(:stdio, :line) end)'),
    ('|> Enum.reduce_while(nil, fn\n  :eof, _ -> {:halt, nil}\n  line, _ ->\n    case String.trim(line) do',
     '|> Enum.reduce_while([], fn\n  :eof, timings -> {:halt, Enum.reverse(timings)}\n  line, timings ->\n    timing = case String.trim(line) do'),
    ('"snapshot" -> emit.(safe_snapshot.())', '"snapshot" -> timed_snapshot.()'),
    ('    {:cont, nil}\nend)',
     '''    timings = case timing do
      {:snapshot_timing, sample} -> [sample | timings]
      _ -> timings
    end
    {:cont, timings}
end)
|> Enum.with_index()
|> Enum.each(fn {sample, index} ->
  IO.puts(["FIXTURE_TIMING ", :json.encode(Map.put(sample, :snapshot_index, index))])
end)''')]
OLD_LOG_FILE = 'file: System.fetch_env!("SEC09_SEC12_LOG")'
NEW_LOG_FILE = 'file: String.to_charlist(System.fetch_env!("SEC09_SEC12_LOG"))'
OLD_BINDING = "MANIFEST_SHA='372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7';SOURCE_SHA='efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'"
BUS_PATH_ATTRIBUTE = b' send_path="/org/freedesktop/DBus"'
REQUESTED_REPLY_ATTRIBUTE = b' receive_requested_reply="true"'
OLD_DAEMON_CHANNEL = "daemon=legacy.Channel(argv,directory/'daemon.log','FIXTURE ')"
NEW_DAEMON_CHANNEL = "daemon=channel_class(legacy)(argv,directory/'daemon.log','FIXTURE ')"
# Embedded so the existing single-file Nix adapter supplies the copied helper.
DAEMON_CHANNEL_SOURCE = r'''"""Daemon-only raw file capture; actors retain their sealed pipe channel."""
import json
import os
import signal
import subprocess
import time


def channel_class(legacy):
    class DaemonChannel(legacy.Channel):
        def __init__(self, command, log, prefix=''):
            self.command, self.log, self.prefix = command, log, prefix
            self.buffer = b''
            self.phase_timings = []
            with log.open('xb', buffering=0) as output:
                self.process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=output,
                    stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
            self.reader = log.open('rb', buffering=0)

        def read(self, timeout=10):
            deadline = time.monotonic() + timeout
            began = time.monotonic_ns()
            decode_started = None
            sample = dict(event=None, decoded=False)
            try:
                while True:
                    assert time.monotonic() < deadline, ('channel deadline', self.command)
                    while b'\n' not in self.buffer:
                        assert time.monotonic() < deadline, ('channel deadline', self.command)
                        piece = os.read(self.reader.fileno(), 65536)
                        if not piece and self.process.poll() is not None:
                            # Exit can race the first EOF observation; consume final bytes.
                            piece = os.read(self.reader.fileno(), 65536)
                            assert piece, ('process exited', self.command, self.process.returncode)
                        if not piece:
                            time.sleep(min(0.001, max(deadline - time.monotonic(), 0)))
                            continue
                        self.buffer += piece
                        assert len(self.buffer) <= 4_194_304, 'fixture output line too large'
                    raw, self.buffer = self.buffer.split(b'\n', 1)
                    decode_started = time.monotonic_ns()
                    line = raw.decode() + '\n'
                    # The child already wrote these exact bytes into the evidence log.
                    if line.startswith(self.prefix):
                        value = json.loads(line[len(self.prefix):])
                        sample.update(event=value.get('event') if isinstance(value, dict) else None, decoded=True)
                        return value
                    decode_started = None
            finally:
                finished = time.monotonic_ns()
                sample.update(read_ns=(finished if decode_started is None else decode_started) - began,
                              decode_ns=None if decode_started is None else finished - decode_started,
                              total_ns=finished - began)
                self.phase_timings.append(sample)

        def stop(self, grace=5):
            method = 'eof'
            self.process.stdin.close()
            try:
                self.process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                method = 'terminate'
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    method = 'kill'
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=3)
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.reader.close()
            return dict(command=self.command, pid=self.process.pid,
                        returncode=self.process.returncode, method=method)
    return DaemonChannel
'''
OLD_NATIVE_SERIAL_COUNT = "value['native_serial_count']=bus_serial_count(value['window'])"
OLD_REQUEST_BOUNDARY = ("        with (directory/'requests.jsonl').open('a') as journal:journal.write(json.dumps(row,sort_keys=True)+'\\n')\n"
                        "        assert time.monotonic()<=limit and response['ok'] is True,response")
NEW_REQUEST_BOUNDARY = ("        try:\n"
                        "            assert time.monotonic()<=limit and response['ok'] is True,response\n"
                        "        finally:\n"
                        "            with (directory/'requests.jsonl').open('a') as journal:journal.write(json.dumps(row,sort_keys=True)+'\\n')")
OLD_BACKEND_PERSIST = "json.dumps(current,indent=2,sort_keys=True)"
NEW_BACKEND_PERSIST = "json.dumps(current,sort_keys=True,separators=(',',':'))"
OLD_REPORT_PERSIST = "json.dumps(report,indent=2,sort_keys=True)"
NEW_REPORT_PERSIST = "json.dumps(report,sort_keys=True,separators=(',',':'))"
RUN_PERSIST_CHANGES = [
    ("record['probes']=probes;current['operations'].append(record);persist()",
     "record['probes']=probes;current['operations'].append(record)"),
    ("current['cases'].append(value);persist()", "current['cases'].append(value)")]
COLLECT_PERSIST_CHANGES = [
    ("report['backends'].append(row);report['corpus_pairs']+=len(row['cases']);persist()",
     "report['backends'].append(row);report['corpus_pairs']+=len(row['cases'])"),
    ("row['gate_commands'][req]=command;persist()", "row['gate_commands'][req]=command")]
RUN_TIMING_CHANGES = [
    ('    def persist():', '    phase_timings=[]\n    def persist():'),
    ("temporary.replace(directory/'backend.json')",
     "temporary.replace(directory/'backend.json')\n"
     "        (directory/'phase-timings.json').write_text(json.dumps(dict(controller=phase_timings, "
     "daemon_reads=daemon.phase_timings if daemon is not None else []),sort_keys=True)+'\\n')"),
    ('    def settle(expected=None):',
     '''    def measure_snapshot_phase(phase, operation, value):
        began=time.monotonic_ns()
        try:
            return operation(value)
        finally:
            phase_timings.append(dict(phase=phase,snapshot_count=len(current['snapshots']),elapsed_ns=time.monotonic_ns()-began))

    def settle(expected=None):'''),
    ('external=external_fds(value)', "external=measure_snapshot_phase('external_fds',external_fds,value)"),
    ('key=state_key(value)', "key=measure_snapshot_phase('state_key',state_key,value)")]


def defer_persistence(source, changes):
    patched = source
    for before, after in changes:
        assert patched.count(before) == 1 and after not in patched.replace(before, '')
        patched = patched.replace(before, after)
    restored = patched
    for before, after in reversed(changes):
        assert restored.count(after) == 1
        restored = restored.replace(after, before)
    assert restored == source
    return patched


def patch_xml_daemon(source):
    assert hashlib.sha256(source.encode()).hexdigest() == XML_DAEMON_SHA
    patched = defer_persistence(source, XML_DAEMON_CHANGES + SNAPSHOT_DAEMON_CHANGES)
    assert hashlib.sha256(patched.encode()).hexdigest() == XML_DAEMON_PATCHED_SHA
    return patched


def patch_requested_reply_denies(source):
    matches = list(re.finditer(rb'<policy user="1102">.*?</policy>', source, re.S))
    assert len(matches) == 1
    match, = matches
    original = match.group()
    patched = original
    for kind in (b'method_return', b'error'):
        rule = b'<deny receive_type="' + kind + b'"/>'
        assert patched.count(rule) == 1
        patched = patched.replace(rule, rule[:-2] + REQUESTED_REPLY_ATTRIBUTE + b'/>')
    assert patched.replace(REQUESTED_REPLY_ATTRIBUTE, b'') == original.replace(
        REQUESTED_REPLY_ATTRIBUTE, b'')
    # Undo only the two deny attributes; existing requested-reply allows stay intact.
    restored = patched
    for kind in (b'method_return', b'error'):
        new = b'<deny receive_type="' + kind + b'"' + REQUESTED_REPLY_ATTRIBUTE + b'/>'
        restored = restored.replace(new, b'<deny receive_type="' + kind + b'"/>', 1)
    assert restored == original
    return source[:match.start()] + patched + source[match.end():]


def write_daemon_channel(copied):
    original_mode = stat.S_IMODE(copied.stat().st_mode)
    helper = copied / 'daemon_channel.py'
    try:
        copied.chmod(original_mode | stat.S_IWUSR)
        helper.write_text(DAEMON_CHANNEL_SOURCE)
        helper.chmod(0o444)
        assert helper.read_text() == DAEMON_CHANNEL_SOURCE
    finally:
        copied.chmod(original_mode)
    assert stat.S_IMODE(copied.stat().st_mode) == original_mode
    return helper, original_mode


def patch_provenance(source):
    assert source.count(XML_DAEMON_SHA) == 1 and XML_DAEMON_PATCHED_SHA not in source
    patched = source.replace(XML_DAEMON_SHA, XML_DAEMON_PATCHED_SHA)
    assert patched.replace(XML_DAEMON_PATCHED_SHA, XML_DAEMON_SHA) == source
    return patched


def patch_launcher(source):
    assert hashlib.sha256(source.encode()).hexdigest() == LAUNCHER_SHA
    assert source.count(OLD_LOG_FILE) == 1 and NEW_LOG_FILE not in source
    patched = source.replace(OLD_LOG_FILE, NEW_LOG_FILE)
    assert patched.count(XML_DAEMON_SHA) == 2 and XML_DAEMON_PATCHED_SHA not in patched
    patched = patched.replace(XML_DAEMON_SHA, XML_DAEMON_PATCHED_SHA)
    assert patched.count(NEW_LOG_FILE) == 1 and patched.count(XML_DAEMON_PATCHED_SHA) == 2
    assert patched.replace(NEW_LOG_FILE, OLD_LOG_FILE).replace(XML_DAEMON_PATCHED_SHA, XML_DAEMON_SHA) == source
    return patched


def row(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode), path
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                sha256=hashlib.sha256(data).hexdigest())


def leaves(root):
    paths = list(root.rglob("*"))
    assert not any(path.is_symlink() for path in paths), root
    return {path.relative_to(root).as_posix() for path in paths if path.is_file()}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def normalize(artifact, runtime_path, fixtures, corpus_path, output):
    assert not output.exists(), output
    assert row(artifact / "artifact.json")["sha256"] == ARTIFACT_SHA
    assert row(runtime_path)["sha256"] == RUNTIME_SHA
    assert row(corpus_path)["sha256"] == CORPUS_SHA
    product = json.loads((artifact / "artifact.json").read_text())
    runtime = json.loads(runtime_path.read_text())
    corpus = json.loads(corpus_path.read_text())
    assert product["not_a_release"] and runtime["not_a_release"]
    assert product["origin_pin"]["sha256"] == RUNTIME_SHA
    assert len(product["sources"]) == 71 and len(product["files"]) == 80
    assert leaves(artifact) == set(product["files"]) | {"artifact.json"}
    for name, expected in product["files"].items():
        assert name.startswith("lib/") and ".." not in Path(name).parts
        observed = row(artifact / name)
        assert observed["sha256"] == expected["sha256"] and observed["bytes"] == expected["bytes"]
        assert observed["mode"] == expected["mode"] & ~0o222
    assert leaves(fixtures) == set(corpus["fixture_files"])
    fixture_rows = {}
    for name in sorted(corpus["fixture_files"]):
        expected, = [pin for path, pin in corpus["files"].items()
                     if path.endswith("/source1/fixture1/" + name)]
        observed = row(fixtures / name)
        assert observed["sha256"] == expected["sha256"] and observed["bytes"] == expected["bytes"]
        assert observed["mode"] == expected["mode"] & ~0o222
        fixture_rows[name] = observed

    sources = {name: pin["sha256"] for name, pin in product["sources"].items()}
    source_sha = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()
    assert set(sources) == set(runtime["sources"])
    mappings = runtime["source_beams"]
    assert len(mappings) == 57 and sum(map(len, mappings.values())) == 61
    assert set(mappings) <= set(sources)
    assert all("lib/" + beam in product["files"] for beams in mappings.values() for beam in beams)
    manifest = dict(version=1, not_a_release=True, runtime=runtime["runtime"],
                    sources=sources, source_sha256=source_sha, source_beams=mappings,
                    files={name: pin["sha256"] for name, pin in product["files"].items()},
                    file_modes={name: pin["mode"] for name, pin in product["files"].items()})
    output.mkdir()
    candidate = output / "candidate"
    candidate.mkdir()
    shutil.copytree(artifact / "lib", candidate / "lib")
    write_json(candidate / "candidate.json", manifest)
    manifest_sha = row(candidate / "candidate.json")["sha256"]
    for name in product["files"]:
        assert row(candidate / name) == row(artifact / name), name

    copied = output / "fixtures"
    shutil.copytree(fixtures, copied)
    contract = copied / "contract.py"
    original = contract.read_text()
    assert original.count(OLD_BINDING) == 1
    replacement = f"MANIFEST_SHA='{manifest_sha}';SOURCE_SHA='{source_sha}'"
    contract.chmod(0o644)
    contract.write_text(original.replace(OLD_BINDING, replacement))
    contract.chmod(0o444)
    assert contract.read_text().replace(replacement, OLD_BINDING) == original

    # dbus-daemon requires a member rule to specify an interface or path.
    # Match only the existing bus method rules; preserve all other XML bytes.
    rules = copied / "rules.conf"
    original_xml = rules.read_bytes()
    assert BUS_PATH_ATTRIBUTE not in original_xml
    rule_counts = {"allow": 0, "deny": 0}

    def qualify_bus_method(match):
        tag = match.group()
        element = ET.fromstring(tag)
        attributes = element.attrib
        if (attributes.get("send_destination") == "org.freedesktop.DBus"
                and attributes.get("send_type") == "method_call"
                and "send_member" in attributes
                and "send_path" not in attributes and "send_interface" not in attributes):
            rule_counts[element.tag] += 1
            return tag[:-2] + BUS_PATH_ATTRIBUTE + b"/>"
        return tag

    patched_xml = re.sub(rb"<(?:allow|deny)\b[^<>]*/>", qualify_bus_method, original_xml)
    assert rule_counts == {"allow": 90, "deny": 8}
    assert patched_xml.count(BUS_PATH_ATTRIBUTE) == 98
    assert patched_xml.replace(BUS_PATH_ATTRIBUTE, b"") == original_xml
    patched_xml = patch_requested_reply_denies(patched_xml)
    rules.chmod(0o644)
    rules.write_bytes(patched_xml)
    rules.chmod(0o444)
    assert rules.read_bytes() == patched_xml

    # Native serial recovery is GaoBus-only; reference serials are per connection.
    run = copied / "run.py"
    original_run = run.read_text()
    assert original_run.count(OLD_NATIVE_SERIAL_COUNT) == 1
    run_replacement = OLD_NATIVE_SERIAL_COUNT + " if backend=='gao_bus' else 'UNSUPPORTED'"
    run_changes = [(OLD_NATIVE_SERIAL_COUNT, run_replacement),
                   (OLD_REQUEST_BOUNDARY, NEW_REQUEST_BOUNDARY),
                   (OLD_BACKEND_PERSIST, NEW_BACKEND_PERSIST)] + RUN_PERSIST_CHANGES + [
                       ('from cleanup import stop_channel',
                        'from cleanup import stop_channel\nfrom daemon_channel import channel_class'),
                       (OLD_DAEMON_CHANNEL, NEW_DAEMON_CHANNEL)] + RUN_TIMING_CHANGES
    patched_run = defer_persistence(original_run, run_changes)
    run.chmod(0o644)
    run.write_text(patched_run)
    run.chmod(0o444)
    assert run.read_text() == patched_run
    helper, copied_fixture_mode = write_daemon_channel(copied)

    collector = copied / "collect.py"
    original_collector = collector.read_text()
    collector_changes = [(OLD_REPORT_PERSIST, NEW_REPORT_PERSIST)] + COLLECT_PERSIST_CHANGES
    patched_collector = defer_persistence(original_collector, collector_changes)
    collector.chmod(0o644)
    collector.write_text(patched_collector)
    collector.chmod(0o444)
    assert collector.read_text() == patched_collector

    daemon = copied / "transformed-daemon.exs"
    original_daemon = daemon.read_text()
    patched_daemon = patch_xml_daemon(original_daemon)
    daemon.chmod(0o644)
    daemon.write_text(patched_daemon)
    daemon.chmod(0o444)
    assert daemon.read_text() == patched_daemon

    provenance = copied / "PROVENANCE_EXPECTED1.json"
    original_provenance = provenance.read_text()
    patched_provenance = patch_provenance(original_provenance)
    provenance.chmod(0o644)
    provenance.write_text(patched_provenance)
    provenance.chmod(0o444)
    assert json.loads(provenance.read_text())["transformed_sha256"] == row(daemon)["sha256"]

    launcher = copied / "launcher.exs"
    original_launcher = launcher.read_text()
    patched_launcher = patch_launcher(original_launcher)
    launcher.chmod(0o644)
    launcher.write_text(patched_launcher)
    launcher.chmod(0o444)
    assert launcher.read_text() == patched_launcher

    assert leaves(copied) == leaves(fixtures) | {'daemon_channel.py'}
    assert len(fixture_rows) == 29
    unchanged_fixtures = set(fixture_rows) - {"contract.py", "rules.conf", "run.py", "collect.py", "launcher.exs",
                                           "transformed-daemon.exs", "PROVENANCE_EXPECTED1.json"}
    assert len(unchanged_fixtures) == 22
    for name in unchanged_fixtures:
        assert row(copied / name) == fixture_rows[name], name
        assert (copied / name).read_bytes() == (fixtures / name).read_bytes(), name
    (output / "manifest-sha256").write_text(manifest_sha + "\n")
    (output / "source-sha256").write_text(source_sha + "\n")
    write_json(output / "bindings.json", dict(
        adapter_revision=10,
        artifact_store=str(artifact), artifact_sha256=ARTIFACT_SHA,
        runtime_store=str(runtime_path), runtime_sha256=RUNTIME_SHA,
        corpus_manifest_sha256=CORPUS_SHA, fixtures_store=str(fixtures),
        fixture_inputs=fixture_rows, adapter=row(Path(__file__)),
        candidate_manifest_sha256=manifest_sha, candidate_source_sha256=source_sha,
        patched_contract=row(contract), patched_xml=row(rules), patched_run=row(run), patched_collector=row(collector),
        patched_launcher=row(launcher),
        patched_xml_daemon=row(daemon), patched_provenance=row(provenance),
        added_helpers={'daemon_channel.py': row(helper)},
        copied_fixture_directory_mode_before=copied_fixture_mode,
        copied_fixture_directory_mode_after=stat.S_IMODE(copied.stat().st_mode),
        patch_provenance={
            "transformed-daemon.exs": dict(origin=str(fixtures / "transformed-daemon.exs"),
                                          before=fixture_rows["transformed-daemon.exs"], after=row(daemon),
                                          reason="XML-derived safety budgets; Unicode-safe iodata output; separate snapshot phase timings flushed at EOF",
                                          changes=[dict(original=before, replacement=after) for before, after in XML_DAEMON_CHANGES + SNAPSHOT_DAEMON_CHANGES],
                                          reversible_textual_change=True),
            "PROVENANCE_EXPECTED1.json": dict(origin=str(fixtures / "PROVENANCE_EXPECTED1.json"),
                                             before=fixture_rows["PROVENANCE_EXPECTED1.json"], after=row(provenance),
                                             original_sha256=XML_DAEMON_SHA, replacement_sha256=XML_DAEMON_PATCHED_SHA,
                                             replacement_count=1, reversible_textual_change=True),
            "launcher.exs": dict(origin=str(fixtures / "launcher.exs"),
                                 before=fixture_rows["launcher.exs"], after=row(launcher),
                                 reason="OTP27 logger_std_h file requires file:filename() charlist",
                                 original_expression=OLD_LOG_FILE, replacement_expression=NEW_LOG_FILE,
                                 replacement_count=1, original_transformed_sha256=XML_DAEMON_SHA,
                                 replacement_transformed_sha256=XML_DAEMON_PATCHED_SHA,
                                 transformed_digest_replacements=2, reversible_textual_change=True),
            "contract.py": dict(origin=str(fixtures / "contract.py"),
                                before=fixture_rows["contract.py"], after=row(contract),
                                original_assignment=OLD_BINDING, replacement_assignment=replacement,
                                reversible_textual_change=True),
            "rules.conf": dict(origin=str(fixtures / "rules.conf"),
                               before=fixture_rows["rules.conf"], after=row(rules),
                               reason="reference member-rule syntax and explicit UID1102 requested-reply denies",
                               added_attribute=BUS_PATH_ATTRIBUTE.decode(), affected_rules=98,
                               requested_reply_denies=dict(user='1102', receive_types=['method_return', 'error'],
                                                           added_attribute=REQUESTED_REPLY_ATTRIBUTE.decode(), affected_rules=2),
                               rule_counts=rule_counts, reversible_textual_change=True),
            "run.py": dict(origin=str(fixtures / "run.py"),
                           before=fixture_rows["run.py"], after=row(run),
                           reason="GaoBus-only serial recovery; response deadline precedes retained journal I/O; compact checkpoints; daemon-only direct raw file capture; separate buffered phase timings",
                           original_assignment=OLD_NATIVE_SERIAL_COUNT,
                           replacement_assignment=run_replacement,
                           changes=[dict(original=before, replacement=after) for before, after in run_changes],
                           reversible_textual_change=True),
            "collect.py": dict(origin=str(fixtures / "collect.py"),
                               before=fixture_rows["collect.py"], after=row(collector),
                               reason="compact qualification JSON at initial/final/exception boundaries; identical decoded values and atomic replacement",
                               original_expression=OLD_REPORT_PERSIST, replacement_expression=NEW_REPORT_PERSIST,
                               changes=[dict(original=before, replacement=after) for before, after in collector_changes],
                               reversible_textual_change=True)},
        fixture_files_unchanged=22, runnable_files_unchanged=80,
        product_qualified=False, not_a_release=True))


if __name__ == "__main__":
    assert len(sys.argv) == 6 and sys.dont_write_bytecode and sys.flags.optimize == 0
    normalize(*(Path(value) for value in sys.argv[1:]))
