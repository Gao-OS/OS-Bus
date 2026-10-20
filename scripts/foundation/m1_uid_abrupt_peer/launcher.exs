# VM-only source preparation; transform the frozen security daemon in memory.
original = System.fetch_env!("UID_AUTHORITIES_ORIGINAL")
source = File.read!(Path.join(original, "daemon.exs"))
pin = "cba75169efa99be884ae758d64a690cc3a6e5fd28576adc5faf06260cdcd88fb"
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
unless digest.(source) == pin, do: raise("UID original daemon pin drift")

defaults = "GaoBus.Limits.defaults()"
anchor = "Stream.repeatedly(fn -> IO.read(:stdio, :line) end)"
for {text, count} <- [{defaults, 2}, {anchor, 1}] do
  unless length(String.split(source, text)) == count + 1,
    do: raise("UID source anchor/count drift: #{text}")
end

unless function_exported?(Code.ensure_loaded!(GaoBus.Limits), :peer_identity, 1),
  do: raise("UID qualification requires the final compiled identity candidate")
defaults_profile = GaoBus.Limits.defaults()
uid_limits =
  defaults_profile
  |> Map.update!(:global, &Map.merge(&1, %{connections: 6, authenticating: 3}))
  |> Map.update!(:uid, &Map.merge(&1, %{connections: 4, authenticating: 2}))
controls = %{max_names_per_uid: 2, max_matches_per_uid: 2,
  max_names_per_peer: 4, max_matches_per_peer: 4,
  max_name_entries: 16, max_match_entries: 16}
for key <- [:config_file, :inherited_listener, :lifecycle], do: Application.delete_env(:gao_bus, key)
Application.put_env(:gao_bus, :lifecycle, :embedded)
Application.put_env(:gao_bus, :inherited_listener, false)
Application.put_env(:gao_bus, :max_connections, 256)
for {key, value} <- controls, do: Application.put_env(:gao_bus, key, value)

observer = ~S'''
original_snapshot = snapshot
json_safe = fn walk, value ->
  cond do
    is_nil(value) -> :null
    is_struct(value) -> walk.(walk, Map.from_struct(value))
    is_map(value) -> Map.new(value, fn {k, v} ->
      key = if is_atom(k) or is_integer(k), do: to_string(k), else: if(is_binary(k), do: k, else: inspect(k))
      {key, walk.(walk, v)}
    end)
    is_tuple(value) -> walk.(walk, Tuple.to_list(value))
    is_list(value) -> Enum.map(value, &walk.(walk, &1))
    is_pid(value) or is_reference(value) -> inspect(value)
    is_atom(value) and value not in [true, false, nil] -> to_string(value)
    true -> value
  end
end
snapshot = fn ->
  base = original_snapshot.()
  {:ok, usage} = GaoBus.Limits.snapshot()
  accounting = :sys.get_state(GaoBus.Limits)
  names = :sys.get_state(GaoBus.NameRegistry)
  matches = :sys.get_state(GaoBus.MatchRules)
  children = for {_, pid, _, _} <- DynamicSupervisor.which_children(GaoBus.PeerSupervisor) do
    try do
      state = :sys.get_state(pid, 50)
      %{peer: inspect(pid), credentials: state.credentials, unique: state.unique_name,
        phase: state.state, auth_phase: if(state.auth, do: state.auth.phase, else: nil)}
    catch
      :exit, _ -> %{peer: inspect(pid), unavailable: true}
    end
  end
  authorities = for module <- [GaoBus.Supervisor, GaoBus.Listener, GaoBus.Router, GaoBus.Limits,
    GaoBus.NameRegistry, GaoBus.MatchRules, GaoBus.Policy, GaoBus.PeerSupervisor], into: %{},
    do: {inspect(module), inspect(Process.whereis(module))}
  extension = %{authorities: authorities, limits: usage,
    accounting: Map.take(accounting, [:peers, :retired, :reservations, :bound_handles, :reload,
      :accept_observers]), children: Enum.sort_by(children, & &1.peer),
    supervised: DynamicSupervisor.count_children(GaoBus.PeerSupervisor),
    names: %{names: Enum.sort(:ets.tab2list(names.names)), uniques: Enum.sort(:ets.tab2list(names.uniques)),
      pid_names: Enum.sort(:ets.tab2list(names.pid_names)), peers: names.peers, uid_counts: names.uid_counts,
      max_names_per_uid: names.max_names_per_uid, max_names_per_peer: names.max_names_per_peer,
      max_name_entries: names.max_name_entries, xml_limits: names.xml_limits?},
    matches: %{entries: Enum.sort(:ets.tab2list(:gao_bus_match_rules)),
      peers: matches.peers, uid_counts: matches.uid_counts,
      max_matches_per_uid: matches.max_matches_per_uid, max_matches_per_peer: matches.max_matches_per_peer,
      max_match_entries: matches.max_match_entries, xml_limits: matches.xml_limits?}}
  Map.put(base, :uid_authorities, json_safe.(json_safe, extension))
end
'''

kill_anchor = "      \"kill_peer \" <> name ->"
quit_anchor = "      \"quit\" ->"
for text <- [kill_anchor, quit_anchor] do
  unless length(String.split(source, text)) == 2,
    do: raise("UID abrupt command anchor/count drift")
end
[head, rest] = String.split(source, kill_anchor)
[_old_kill, tail] = String.split(rest, quit_anchor)
kill_command = ~S'''
      "uid_abrupt_peer " <> name ->
        began = System.monotonic_time(:millisecond)
        {:ok, peer} = GaoBus.NameRegistry.resolve(name)
        credentials = GaoBus.Peer.get_credentials(peer)
        1100 = credentials.uid
        1100 = credentials.gid
        before = snapshot.()
        reference = Process.monitor(peer)
        Process.exit(peer, :kill)

        receive do
          {:DOWN, ^reference, :process, ^peer, :killed} -> :ok
        after
          1000 -> raise "UID abrupt Peer DOWN deadline"
        end

        # No unregister/disconnect/release call: the runner checks natural DOWN
        # cleanup and credit reuse before closing the external actor's stdin.
        emit.(%{
          event: "uid_abrupt_peer_down", peer: inspect(peer), unique: name,
          credentials: credentials, operation: "Process.exit(peer, :kill)",
          down: %{peer: inspect(peer), monitor: inspect(reference), reason: "killed"},
          explicit_cleanup_calls: [], before: before,
          daemon_elapsed_ms: System.monotonic_time(:millisecond) - began
        })

'''
transformed = (head <> kill_command <> quit_anchor <> tail)
  |> String.replace(defaults, "uid_limits")
  |> String.replace(anchor, observer <> "\n" <> anchor)
IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(%{
  event: "uid_abrupt_peer_provenance", original_sha256: pin, transformed_sha256: digest.(transformed),
  transformation: "uid-two-defaults-readonly-snapshot-abrupt-command-v1", defaults_replaced: 2,
  kill_command_replacements: 1,
  snapshot_insertions: 1, profile: uid_limits, defaults_profile: defaults_profile, authorities: controls,
  lifecycle: "embedded", config_file: :null, inherited_listener: false, max_connections: 256
})))
Code.eval_string(transformed, [uid_limits: uid_limits], file: Path.join(original, "daemon.exs"))
