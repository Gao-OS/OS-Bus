# Root-only fault channel in a disposable guest; original daemon remains exact.
original = System.fetch_env!("LISTENER_TRANSFER_ORIGINAL")
source = File.read!(Path.join(original, "daemon.exs"))
pin = "cba75169efa99be884ae758d64a690cc3a6e5fd28576adc5faf06260cdcd88fb"
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
unless digest.(source) == pin, do: raise("listener transfer original daemon drift")
for key <- [:config_file, :inherited_listener, :lifecycle], do: Application.delete_env(:gao_bus, key)
Application.put_env(:gao_bus, :lifecycle, :embedded)
Application.put_env(:gao_bus, :inherited_listener, false)
Application.put_env(:gao_bus, :max_connections, 256)
unless function_exported?(Code.ensure_loaded!(GaoBus.Listener), :transfer_ownership, 2),
  do: raise("candidate lacks real listener ownership-transfer procedure")

observer = ~S'''
original_snapshot = snapshot
json_safe = fn walk, value ->
  cond do
    is_nil(value) -> :null
    is_struct(value) -> walk.(walk, Map.from_struct(value))
    is_map(value) -> Map.new(value, fn {key, item} ->
      name = if is_atom(key) or is_integer(key), do: to_string(key), else: if(is_binary(key), do: key, else: inspect(key))
      {name, walk.(walk, item)}
    end)
    is_tuple(value) -> walk.(walk, Tuple.to_list(value))
    is_list(value) -> Enum.map(value, &walk.(walk, &1))
    is_pid(value) or is_reference(value) -> inspect(value)
    is_atom(value) and value not in [true, false, nil] -> to_string(value)
    true -> value
  end
end
fd_links = fn ->
  root = "/proc/#{System.pid()}/fd"
  File.ls!(root)
  |> Enum.reduce(%{}, fn fd, rows ->
    case File.read_link(Path.join(root, fd)) do
      {:ok, link} -> Map.put(rows, fd, link)
      {:error, :enoent} -> rows
      other -> raise "native FD readback failed: #{inspect(other)}"
    end
  end)
end
inode = fn path ->
  stat = File.stat!(path)
  %{inode: stat.inode, major_device: stat.major_device, minor_device: stat.minor_device, type: stat.type}
end
snapshot = fn ->
  base = original_snapshot.()
  names = :sys.get_state(GaoBus.NameRegistry)
  authorities = for module <- [GaoBus.Supervisor, GaoBus.Listener, GaoBus.Router, GaoBus.Limits,
    GaoBus.NameRegistry, GaoBus.MatchRules, GaoBus.Policy, GaoBus.PeerSupervisor], into: %{},
    do: {inspect(module), inspect(Process.whereis(module))}
  children = for {_, peer, _, _} <- DynamicSupervisor.which_children(GaoBus.PeerSupervisor) do
    state = :sys.get_state(peer, 1000)
    %{peer: inspect(peer), phase: state.state, credentials: state.credentials, unique: state.unique_name}
  end
  extension = %{authorities: authorities,
    core_children: Enum.sort(Supervisor.which_children(GaoBus.Supervisor)),
    children: Enum.sort_by(children, & &1.peer),
    accounting: Map.take(:sys.get_state(GaoBus.Limits), [:peers, :retired, :reservations,
      :bound_handles, :reload, :accept_observers]),
    name_state: names,
    name_tables: %{names: Enum.sort(:ets.tab2list(names.names)), uniques: Enum.sort(:ets.tab2list(names.uniques)),
      pid_names: Enum.sort(:ets.tab2list(names.pid_names))},
    match_state: :sys.get_state(GaoBus.MatchRules),
    match_entries: Enum.sort(:ets.tab2list(:gao_bus_match_rules)),
    capabilities: Enum.sort(:ets.tab2list(:gao_bus_capabilities))}
  base
  |> Map.put(:authority, json_safe.(json_safe, extension))
  |> Map.put(:native_fds, fd_links.())
  |> Map.put(:incumbent, json_safe.(json_safe, inode.(socket)))
end
'''

fault_command = ~S'''
      "prepare_listener_transfer" ->
        nil = Process.get(:listener_transfer_fixture)
        path = Path.join(Path.dirname(socket), "transfer")
        false = File.exists?(path)
        before = snapshot.()
        {:ok, listener} = :socket.open(:local, :stream, :default)
        :ok = :socket.bind(listener, %{family: :local, path: path})
        :ok = File.chmod(path, 0o666)
        :ok = :socket.listen(listener)
        owned_inode = inode.(path)
        parent = self()
        {holder, holder_monitor} = spawn_monitor(fn ->
          parent_monitor = Process.monitor(parent)
          receive do
            :accept ->
              {:ok, accepted} = :socket.accept(listener, 1000)
              {:ok, <<42>>} = :socket.recv(accepted, 1, 1000)
              {:ok, credentials} = GaoBus.Unix.Credentials.read(accepted)
              send(parent, {:transfer_accepted, accepted, credentials})
              receive do
                :stop -> :ok
                {:DOWN, ^parent_monitor, :process, ^parent, _} -> :ok
              end
            :stop -> :ok
            {:DOWN, ^parent_monitor, :process, ^parent, _} -> :ok
          end
        end)
        Process.put(:listener_transfer_fixture, {listener, holder, holder_monitor, path, owned_inode, before})
        emit.(%{event: "listener_transfer_prepared", path: path, before: before})

      "listener_transfer_failure" ->
        began = System.monotonic_time(:millisecond)
        {listener, holder, holder_monitor, path, owned_inode, before} = Process.delete(:listener_transfer_fixture)
        try do
          send(holder, :accept)
          {accepted, credentials} = receive do
            {:transfer_accepted, accepted, credentials} -> {accepted, credentials}
          after
            1000 -> raise "listener transfer accepted marker deadline"
          end
          {:ok, ^holder} = :socket.getopt(accepted, {:otp, :controlling_process})
          {:ok, fd} = :socket.getopt(accepted, {:otp, :fd})
          {:ok, "socket:" <> _ = fd_before} = File.read_link("/proc/#{System.pid()}/fd/#{fd}")
          {:ok, peer} = GaoBus.PeerSupervisor.start_peer(accepted)
          reference = Process.monitor(peer)
          nil = GaoBus.Peer.get_unique_name(peer)
          nil = GaoBus.Peer.get_credentials(peer)
          %{state: :waiting_socket, native_socket: nil} = :sys.get_state(peer)
          [] = Registry.keys(GaoBus.PeerRegistry, peer)
          false = Map.has_key?(:sys.get_state(GaoBus.Router).peers, peer)
          {:ok, accounting} = GaoBus.Limits.snapshot()
          false = Map.has_key?(accounting.peers, peer)
          # Invoke the genuine compiled production branch from a non-owner.
          {:error, {:invalid, :not_owner}} = error = GaoBus.Listener.transfer_ownership(accepted, peer)
          receive do
            {:DOWN, ^reference, :process, ^peer, :shutdown} -> :ok
          after
            1000 -> raise "listener transfer Peer DOWN deadline"
          end
          {:error, :closed} = socket_after = :socket.getopt(accepted, {:otp, :controlling_process})
          {:error, :enoent} = fd_after = File.read_link("/proc/#{System.pid()}/fd/#{fd}")
          # Native accepted FD is already gone before fixture holder/listener cleanup.
          :ok = :socket.close(listener)
          send(holder, :stop)
          receive do
            {:DOWN, ^holder_monitor, :process, ^holder, :normal} -> :ok
          after
            1000 -> raise "listener transfer holder DOWN deadline"
          end
          ^owned_inode = inode.(path)
          :ok = File.rm(path)
          deadline = began + 1000
          await = fn await ->
            state = snapshot.()
            cond do
              state == before -> state
              System.monotonic_time(:millisecond) >= deadline -> raise "listener transfer exact baseline deadline"
              true -> await.(await)
            end
          end
          after_state = await.(await)
          emit.(%{event: "listener_transfer_failure", operation: "GaoBus.Listener.transfer_ownership/2",
            error: json_safe.(json_safe, error), peer: inspect(peer), caller: inspect(self()),
            holder: inspect(holder), owner_before: inspect(holder), accepted_credentials: credentials,
            marker_hex: "2a", fd: fd, fd_before: fd_before, fd_after: json_safe.(json_safe, fd_after),
            socket_after: json_safe.(json_safe, socket_after),
            incomplete: %{phase: "waiting_socket", native_socket: :null, unique: :null, credentials: :null,
              registry: [], router_member: false, accounting_member: false},
            down: %{peer: inspect(peer), monitor: inspect(reference), reason: "shutdown"},
            holder_down: %{peer: inspect(holder), monitor: inspect(holder_monitor), reason: "normal"},
            before: before, after: after_state, explicit_peer_cleanup: [], fault_path_removed: not File.exists?(path),
            daemon_elapsed_ms: System.monotonic_time(:millisecond) - began})
        after
          :socket.close(listener)
          send(holder, :stop)
          if File.exists?(path) do
            ^owned_inode = inode.(path)
            File.rm!(path)
          end
        end

'''
anchor = "Stream.repeatedly(fn -> IO.read(:stdio, :line) end)"
quit = "      \"quit\" ->"
for text <- [anchor, quit] do
  unless length(String.split(source, text)) == 2, do: raise("listener transfer source anchor drift")
end
transformed = source
  |> String.replace(anchor, observer <> "\n" <> anchor)
  |> String.replace(quit, fault_command <> quit)
IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(%{event: "listener_transfer_provenance",
  original_sha256: pin, transformed_sha256: digest.(transformed), snapshot_insertions: 1,
  fault_command_insertions: 1, transformation: "readonly-authority-and-wrong-owner-transfer-v1",
  lifecycle: "embedded", config_file: :null, inherited_listener: false, max_connections: 256})))
Code.eval_string(transformed, [], file: Path.join(original, "daemon.exs"))
