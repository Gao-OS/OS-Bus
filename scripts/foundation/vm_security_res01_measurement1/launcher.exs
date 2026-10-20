# Root-only guarded timing overlay; the base launcher and daemon remain frozen.
unless File.read!("/etc/osbus-security-guest") == "isolated-vm\n",
  do: raise("disposable guest required")
[run_socket, _policy] = System.argv()
unless run_socket == "/run/osbus-security/res01/bus", do: raise("private measurement socket required")
base = System.fetch_env!("RES01_MEASUREMENT_BASE")
here = __DIR__
bindings = :json.decode(File.read!(Path.join(here, "BASE_BINDINGS1.json")))
recipes_bytes = File.read!(Path.join(here, "recipe1.json"))
recipes = :json.decode(recipes_bytes)
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
source = File.read!(Path.join(base, "launcher.exs"))
unless digest.(source) == bindings["launcher.exs"]["sha256"], do: raise("base launcher drift")
replace = fn source, changes ->
  Enum.reduce(changes, source, fn change, text ->
    unless length(String.split(text, change["before"])) == change["count"] + 1,
      do: raise("measurement launcher anchor drift")
    String.replace(text, change["before"], change["after"])
  end)
end
transformed = replace.(source, recipes["launcher"])
provenance = %{kind: "res01_timing_experiment_v1", diagnostic_only: true,
  base_launcher_sha256: digest.(source), instrumented_launcher_sha256: digest.(transformed),
  recipe_sha256: digest.(recipes_bytes), overlay_launcher_sha256: digest.(File.read!(__ENV__.file)),
  event_limit: 200_000, clock: "daemon_local_elapsed_ns",
  overhead: "timing reads and bounded metadata retained within unchanged deadlines"}
Process.put(:res01_measurement_origin, System.monotonic_time(:nanosecond))
Process.put(:res01_measurement_events, [])
Process.put(:res01_measurement_count, 0)
Process.put(:res01_measurement_overflow, false)
try do
  Code.eval_string(transformed,
    [measurement_replace: replace, measurement_original_recipe: recipes["original_daemon"],
     measurement_provenance: provenance], file: Path.join(base, "launcher.exs"))
after
  # Only after the original daemon loop terminates: no held-phase chatter/writes.
  records = %{kind: "res01_daemon_timing_v1", provenance: provenance,
    overflow: Process.get(:res01_measurement_overflow),
    events: Enum.reverse(Process.get(:res01_measurement_events)),
    snapshot_count: Process.get(:res01_measurement_ordinal, 0)}
  File.write!("/run/osbus-security/res01/daemon-measurement.json",
    IO.iodata_to_binary(:json.encode(records)) <> "\n")
end
