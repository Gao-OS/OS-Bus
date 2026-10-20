defmodule OSBusFoundationPackagedInspector do
  @moduledoc "Guest-only local console instrumentation loaded after normal release boot."
  @budget_ms 3000
  @metrics ~w(connections authenticating ingress_messages ingress_bytes ingress_fds egress_messages egress_bytes egress_fds frame_bytes frame_fds activation_messages activation_bytes activation_fds)a
  @peer_queue_fields ~w(buffer_bytes incoming_fds output_messages output_fds output_bytes current_output route_wait auth_continuing messages_continuing read_scheduled frame_timer pending_fd_timer mailbox)a
  @authorities [
    GaoBus.Supervisor,
    GaoBus.Ids,
    GaoBus.PeerRegistry,
    GaoBus.Limits,
    GaoBus.Policy,
    GaoBus.NameRegistry,
    GaoBus.MatchRules,
    GaoBus.Policy.Capability,
    GaoBus.Router,
    GaoBus.Activation.HelperSupervisor,
    GaoBus.Activation,
    GaoBus.PeerSupervisor,
    GaoBus.Listener
  ]

  def reply(encoded) do
    deadline = now() + @budget_ms
    identity = request_identity(encoded)
    envelope = Map.merge(%{schema: 1, pid: String.to_integer(System.pid())}, identity)

    result =
      observation(deadline, fn ->
        with {:ok, request} <- decode_request(encoded), :ok <- guard_environment(deadline) do
          value = execute(request, deadline)
          envelope = Map.merge(envelope, %{ok: true, result: display(value)})
          IO.iodata_to_binary(:json.encode(envelope))
        else
          {:error, reason} -> throw({:fixture_error, reason})
        end
      end)

    payload =
      case result do
        {:ok, bytes} ->
          bytes

        {:error, reason} ->
          envelope
          |> Map.merge(%{ok: false, error: inspect(reason, limit: 30)})
          |> :json.encode()
          |> IO.iodata_to_binary()
      end

    IO.puts("\nFIXTURE " <> payload)
    :ok
  end

  def decode_request(encoded) when is_binary(encoded) and byte_size(encoded) <= 5464 do
    with {:ok, bytes} <- Base.decode64(encoded),
         true <- byte_size(bytes) <= 4096,
         {:ok, request} <- decode_json(bytes),
         true <- valid_request?(request) do
      {:ok, request}
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_request(_), do: {:error, :invalid_request}

  defp decode_json(bytes) do
    {:ok, :json.decode(bytes)}
  rescue
    _ -> {:error, :invalid_json}
  end

  defp valid_request?(
         %{"schema" => 1, "nonce" => nonce, "request_id" => id, "operation" => operation} =
           request
       ) do
    keys =
      if operation == "kill",
        do: ~w(schema nonce request_id operation name),
        else: ~w(schema nonce request_id operation)

    valid_identity?(nonce, id) and operation in ~w(snapshot quiescent metrics kill) and
      Enum.sort(Map.keys(request)) == Enum.sort(keys) and
      (operation != "kill" or unique_name?(request["name"]))
  end

  defp valid_request?(_), do: false

  defp valid_identity?(nonce, id),
    do:
      is_binary(nonce) and byte_size(nonce) == 32 and
        Regex.match?(~r/\A[0-9a-f]{32}\z/, nonce) and is_integer(id) and id > 0

  defp unique_name?(name),
    do:
      is_binary(name) and byte_size(name) <= 255 and
        Regex.match?(~r/\A:[0-9]+\.[0-9]+\z/, name)

  defp request_identity(encoded) do
    with true <- is_binary(encoded) and byte_size(encoded) <= 5464,
         {:ok, bytes} <- Base.decode64(encoded),
         true <- byte_size(bytes) <= 4096,
         {:ok, %{"nonce" => nonce, "request_id" => id}} <- decode_json(bytes),
         true <- valid_identity?(nonce, id) do
      %{nonce: nonce, request_id: id}
    else
      _ -> %{nonce: nil, request_id: nil}
    end
  end

  def display(value) when is_map(value) do
    value = if is_struct(value), do: Map.from_struct(value), else: value
    pairs = Enum.map(value, fn {key, item} -> {display_key(key), display(item)} end)

    if length(Enum.uniq_by(pairs, &elem(&1, 0))) != length(pairs),
      do: raise(ArgumentError, "colliding display keys")

    Map.new(pairs)
  end

  def display(value) when is_list(value), do: Enum.map(value, &display/1)
  def display(value) when is_tuple(value), do: value |> Tuple.to_list() |> display()
  def display(value) when is_pid(value), do: inspect(value)
  def display(value) when value in [true, false, nil], do: value
  def display(value) when is_atom(value), do: Atom.to_string(value)
  def display(value) when is_binary(value) or is_number(value), do: value
  defp display_key(value) when is_binary(value), do: value
  defp display_key(value) when is_atom(value), do: Atom.to_string(value)
  defp display_key(value) when is_integer(value), do: Integer.to_string(value)
  defp display_key(value) when is_pid(value), do: inspect(value)

  def encode_usage(usage) when is_map(usage) do
    bytes = :erlang.term_to_binary(usage)

    %{
      encoding: "erlang-external-term/base64",
      base64: Base.encode64(bytes),
      bytes: byte_size(bytes),
      sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    }
  end

  def validate_guard(guard) do
    expected = %{
      marker: "isolated-vm\n",
      profile: :system,
      lifecycle: :release,
      node: :nonode@nohost,
      native: %{uid: 4, real_uid: 4, gid: 4, real_gid: 4},
      uids: [4, 4, 4, 4],
      gids: [4, 4, 4, 4],
      cluster: false,
      inherited: false
    }

    valid =
      is_map(guard) and
        Enum.all?(expected, fn {key, value} ->
          if key == :native,
            do: is_map(guard[key]) and Map.take(guard[key], Map.keys(value)) == value,
            else: guard[key] == value
        end) and guard[:config] == "/run/osbus-p08/config/bus.conf" and
        guard[:socket] == "/run/osbus-p08/socket/bus" and is_binary(guard[:release]) and
        Path.type(guard.release) == :absolute and
        String.starts_with?(guard.release, "/run/osbus-p08/")

    if valid, do: :ok, else: {:error, :unsafe_environment}
  end

  defp guard_environment(deadline) do
    status = File.read!("/proc/self/status")

    guard = %{
      marker: File.read!("/etc/osbus-security-guest"),
      profile: Application.get_env(:gao_bus, :profile),
      lifecycle: Application.get_env(:gao_bus, :lifecycle),
      node: node(),
      native: GaoBus.Unix.Native.identity(),
      uids: proc_ids(status, "Uid"),
      gids: proc_ids(status, "Gid"),
      config: Application.get_env(:gao_bus, :config_file),
      socket: listener_facts(deadline).socket_path,
      release: System.get_env("RELEASE_ROOT"),
      cluster: Application.get_env(:gao_bus, :cluster),
      inherited: Application.get_env(:gao_bus, :inherited_listener)
    }

    with :ok <- validate_guard(guard),
         true <- package_code?(guard.release),
         true <- List.keymember?(Application.started_applications(), :gao_bus, 0) do
      :ok
    else
      _ -> {:error, :unsafe_environment}
    end
  end

  defp proc_ids(status, key) do
    [line] =
      Regex.run(Regex.compile!("^" <> key <> ":([^\\n]+)$", "m"), status, capture: :all_but_first)

    line |> String.split() |> Enum.map(&String.to_integer/1)
  end

  defp package_code?(root) do
    Enum.all?([GaoBus.Application, GaoBus.Router, GaoBus.Peer, GaoBus.Limits], fn module ->
      path = :code.which(module)
      is_list(path) and String.starts_with?(List.to_string(path), root <> "/lib/")
    end)
  end

  def call(server, message, deadline) do
    timed(deadline, fn remaining -> GenServer.call(server, message, remaining) end)
  end

  # Raw authority states can contain native resources. Project in a disposable
  # process and observe its DOWN before returning any data to the console.
  def project_state(server, deadline, projection) do
    observation(deadline, fn ->
      timed(deadline, &:sys.get_state(server, &1)) |> require_ok() |> projection.()
    end)
  end

  def observation(deadline, operation) do
    if now() >= deadline do
      {:error, :deadline}
    else
      destination = :erlang.alias([:reply])
      tag = make_ref()

      {worker, monitor} =
        spawn_monitor(fn ->
          result =
            try do
              value = operation.()

              cond do
                now() >= deadline -> {:error, :deadline}
                safe_result?(value) -> {:ok, value}
                true -> {:error, :unsafe_observation_result}
              end
            rescue
              error -> {:error, {:inspection_error, Exception.message(error)}}
            catch
              :throw, {:fixture_error, reason} -> {:error, reason}
              :exit, reason -> {:error, {:inspection_exit, inspect(reason, limit: 30)}}
            end

          send(destination, {tag, result})
        end)

      try do
        receive do
          {^tag, result} ->
            receive do
              {:DOWN, ^monitor, :process, ^worker, :normal} ->
                if now() >= deadline, do: {:error, :deadline}, else: result

              {:DOWN, ^monitor, :process, ^worker, reason} ->
                {:error, {:observation_exit, inspect(reason, limit: 30)}}
            after
              max(deadline - now(), 0) -> stop_observer(worker, monitor)
            end

          {:DOWN, ^monitor, :process, ^worker, reason} ->
            {:error, {:observation_exit, inspect(reason, limit: 30)}}
        after
          max(deadline - now(), 0) -> stop_observer(worker, monitor)
        end
      after
        :erlang.unalias(destination)
        Process.demonitor(monitor, [:flush])
      end
    end
  end

  defp stop_observer(worker, monitor) do
    Process.exit(worker, :kill)

    # A timeout never succeeds. This separate cleanup grace bounds reaping even
    # if a dirty native operation is finishing after the inspection deadline.
    receive do
      {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :deadline}
    after
      1000 -> {:error, :observation_cleanup_deadline}
    end
  end

  defp safe_result?(value) when is_map(value),
    do: Enum.all?(value, fn {key, item} -> safe_result?(key) and safe_result?(item) end)

  defp safe_result?(value) when is_list(value), do: Enum.all?(value, &safe_result?/1)
  defp safe_result?(value) when is_tuple(value), do: value |> Tuple.to_list() |> safe_result?()

  defp safe_result?(value),
    do: is_binary(value) or is_number(value) or is_atom(value) or is_pid(value)

  defp timed(deadline, operation) do
    remaining = deadline - now()

    if remaining <= 0 do
      {:error, :deadline}
    else
      try do
        result = operation.(remaining)
        if now() >= deadline, do: {:error, :deadline}, else: {:ok, result}
      catch
        :exit, {:timeout, _} -> {:error, :deadline}
        :exit, reason -> {:error, {:authority_unavailable, reason}}
      end
    end
  end

  defp require_ok({:ok, value}), do: value
  defp require_ok({:error, reason}), do: throw({:fixture_error, reason})
  defp require_check(:ok), do: :ok
  defp require_check({:error, reason}), do: throw({:fixture_error, reason})
  defp now, do: System.monotonic_time(:millisecond)

  def validate_accounting(state) do
    if accounting_shape?(state) do
      if settled?(state), do: :ok, else: {:error, :not_quiescent}
    else
      {:error, :invalid_accounting}
    end
  end

  defp accounting_shape?(
         %{
           usage: %{
             global: global,
             uids: uids,
             peers: peers,
             reservations: reservations,
             reload_reservations: reload,
             limits: limits,
             xml: %{limits: xml_limits, queues: xml_queues, global: xml_global, uids: xml_uids}
           },
           peers: live,
           peer_queues: queues,
           authorities: authorities
         } = state
       ) do
    is_list(live) and is_map(uids) and is_map(peers) and is_map(queues) and
      is_map(authorities) and is_map(limits) and is_map(xml_limits) and is_map(xml_queues) and
      is_map(xml_global) and is_map(xml_uids) and counts?(global) and
      Enum.all?(uids, fn {uid, counts} -> is_integer(uid) and counts?(counts) end) and
      Enum.all?(peers, fn {pid, counts} -> is_pid(pid) and counts?(counts) end) and
      Enum.all?(live, fn peer ->
        is_map(peer) and is_binary(peer[:peer]) and
          is_integer(peer[:uid]) and unique_name?(peer[:name])
      end) and
      Enum.all?(queues, fn {peer, queue} ->
        is_binary(peer) and is_map(queue) and
          Enum.sort(Map.keys(queue)) == Enum.sort(@peer_queue_fields) and
          Enum.all?(queue, fn {_, value} -> is_integer(value) and value >= 0 end)
      end) and
      is_integer(reservations) and is_integer(reload) and
      Enum.all?(
        [:pending, :retired, :bound_handles, :reload, :activation],
        &is_integer(Map.get(state, &1))
      )
  end

  defp accounting_shape?(_), do: false

  defp counts?(counts),
    do:
      is_map(counts) and Enum.sort(Map.keys(counts)) == Enum.sort(@metrics) and
        Enum.all?(counts, fn {_, value} -> is_integer(value) and value >= 0 end)

  defp quiet_counts?(counts, connections),
    do:
      counts.connections == connections and
        Enum.all?(counts, fn {key, value} -> key == :connections or value == 0 end)

  defp settled?(state) do
    usage = state.usage
    expected = Enum.frequencies_by(state.peers, & &1.uid)
    peer_ids = Enum.map(state.peers, & &1.peer) |> Enum.sort()
    usage_ids = Map.keys(usage.peers) |> Enum.map(&inspect/1) |> Enum.sort()

    quiet_counts?(usage.global, length(state.peers)) and
      Enum.sort(Map.keys(usage.uids)) == Enum.sort(Map.keys(expected)) and
      Enum.all?(usage.uids, fn {uid, counts} -> quiet_counts?(counts, expected[uid]) end) and
      usage_ids == peer_ids and length(Enum.uniq(peer_ids)) == length(peer_ids) and
      Enum.all?(usage.peers, fn {_, counts} -> quiet_counts?(counts, 1) end) and
      usage.reservations == 0 and usage.reload_reservations == 0 and
      usage.xml.global == %{incomplete: 0, completed: length(state.peers)} and
      usage.xml.uids == expected and
      Enum.all?([:pending, :retired, :bound_handles, :reload, :activation], &(state[&1] == 0)) and
      Enum.sort(Map.keys(state.peer_queues)) == peer_ids and
      Enum.all?(state.peer_queues, fn {_, queue} ->
        Enum.all?(queue, fn {_, value} -> value == 0 end)
      end)
  end

  def consistent(before, after_state) do
    if before == after_state, do: :ok, else: {:error, :inconsistent_accounting}
  end

  defp authority_pids do
    Map.new(@authorities, fn module ->
      case Process.whereis(module) do
        pid when is_pid(pid) -> {module, pid}
        _ -> throw({:fixture_error, {:missing_authority, module}})
      end
    end)
  end

  def peer_records(peers),
    do:
      Map.new(peers, fn {pid, info} ->
        {pid, Map.take(info, [:unique_name, :credentials, :unix_fd])}
      end)

  defp snapshot(deadline) do
    pids = authority_pids()

    router =
      project_state(GaoBus.Router, deadline, fn state ->
        %{
          peers: peer_records(state.peers),
          pending: map_size(state.pending.entries),
          pending_limits: state.pending.limits,
          reload: if(state.reload_waiter, do: 1, else: 0),
          activation_claims: map_size(state.activation_claims),
          max_output_bytes: state.max_output_bytes
        }
      end)
      |> require_ok()

    names = name_registry_facts(deadline) |> require_ok()

    matches =
      project_state(
        GaoBus.MatchRules,
        deadline,
        &Map.take(&1, [:max_matches_per_peer, :max_match_entries, :xml_limits?])
      )
      |> require_ok()

    _ = project_state(GaoBus.Policy.Capability, deadline, fn _ -> :ok end) |> require_ok()
    policy = policy_facts(deadline)
    activation = activation_work(deadline)

    peer_queues =
      Map.new(router.peers, fn {pid, _} -> {inspect(pid), peer_facts(pid, deadline)} end)

    {:ok, usage} = call(GaoBus.Limits, :snapshot, deadline) |> require_ok()
    cleanup = cleanup_counts(deadline)
    listener = listener_facts(deadline)

    peers =
      Enum.map(router.peers, fn {pid, info} ->
        %{
          peer: inspect(pid),
          name: info.unique_name,
          uid: info.credentials.uid,
          gid: info.credentials.gid,
          groups: Map.get(info.credentials, :groups)
        }
      end)
      |> Enum.sort_by(& &1.peer)

    authorities = Map.new(pids, fn {module, pid} -> {inspect(module), inspect(pid)} end)
    pending = router.pending

    accounting =
      Map.merge(cleanup, %{
        usage: usage,
        peers: peers,
        pending: pending,
        reload: router.reload + policy.reload,
        activation: activation + router.activation_claims,
        peer_queues: peer_queues,
        authorities: authorities
      })

    queues =
      Map.new(pids, fn {module, pid} ->
        {:message_queue_len, size} = Process.info(pid, :message_queue_len)
        {inspect(module), size}
      end)

    if authority_pids() != pids, do: throw({:fixture_error, :authority_replacement})

    %{
      event: "snapshot",
      pid: String.to_integer(System.pid()),
      authorities: authorities,
      code_identity: code_identity(),
      applications:
        Enum.map(Application.started_applications(), &Atom.to_string(elem(&1, 0))) |> Enum.sort(),
      node: Atom.to_string(node()),
      peers: peers,
      usage: usage,
      usage_etf: encode_usage(usage),
      accounting: accounting,
      retired: cleanup.retired,
      bound_handles: cleanup.bound_handles,
      peer_queues: peer_queues,
      pending: pending,
      pending_limits: router.pending_limits,
      names: call(GaoBus.NameRegistry, :list_names, deadline) |> require_ok() |> Enum.sort(),
      matches: :ets.info(:gao_bus_match_rules, :size),
      capabilities: :ets.info(:gao_bus_capabilities, :size),
      matches_by_peer: table_counts(:gao_bus_match_rules),
      names_by_peer: names.names_by_peer,
      processes: :erlang.system_info(:process_count),
      ports: :erlang.system_info(:port_count),
      atoms: :erlang.system_info(:atom_count),
      memory: :erlang.memory(:total),
      queues: queues,
      configuration: policy.configuration,
      compiled_policy: policy.compiled_policy,
      policy_generation: policy.generation,
      startup_plan: %{
        profile: Application.get_env(:gao_bus, :profile),
        lifecycle: Application.get_env(:gao_bus, :lifecycle),
        native_identity: GaoBus.Unix.Native.identity(),
        safety_limits: usage.limits,
        xml_limits: Keyword.fetch!(listener.peer_options, :xml_limits),
        pending_limits: router.pending_limits,
        max_output_bytes: router.max_output_bytes,
        peer_supervisor: peer_supervisor_facts(deadline),
        names: Map.take(names, [:max_names_per_peer, :max_name_entries, :xml_limits?]),
        matches: Map.take(matches, [:max_matches_per_peer, :max_match_entries, :xml_limits?]),
        listener: listener
      }
    }
  end

  defp table_counts(table) do
    :ets.tab2list(table) |> Enum.frequencies_by(fn entry -> inspect(elem(entry, 0)) end)
  end

  def name_registry_facts(deadline) do
    project_state(GaoBus.NameRegistry, deadline, fn state ->
      state
      |> Map.take([:max_names_per_peer, :max_name_entries, :xml_limits?])
      |> Map.put(:names_by_peer, table_counts(state.pid_names))
    end)
  end

  defp code_identity,
    do: code_identity(:code.all_loaded(), System.fetch_env!("RELEASE_ROOT"))

  def code_identity(loaded, root) do
    loaded
    |> Enum.reduce(%{}, fn {module, file}, acc ->
      name = Atom.to_string(module)

      if name in ["Elixir.GaoBus", "Elixir.ExDBus"] or
           String.starts_with?(name, ["Elixir.GaoBus.", "Elixir.ExDBus."]) do
        path =
          if is_list(file),
            do: Path.relative_to(List.to_string(file), root),
            else: "nonfile:" <> to_string(file)

        Map.put(acc, name, %{
          path: path,
          md5: Base.encode16(module.module_info(:md5), case: :lower)
        })
      else
        acc
      end
    end)
  end

  defp cleanup_counts(deadline) do
    project_state(GaoBus.Limits, deadline, fn state ->
      %{retired: map_size(state.retired), bound_handles: map_size(state.bound_handles)}
    end)
    |> require_ok()
  end

  defp policy_facts(deadline) do
    reload =
      project_state(GaoBus.Policy, deadline, fn state -> if(state.reload, do: 1, else: 0) end)
      |> require_ok()

    captured = GaoBus.Policy.snapshot()
    Map.put(policy_record(captured), :reload, reload)
  end

  def policy_record({:ok, generation, %GaoBus.Policy.XML{configuration: configuration} = policy})
      when is_integer(generation) and generation > 0 and is_map(configuration) do
    %{generation: generation, configuration: configuration, compiled_policy: policy}
  end

  defp activation_work(deadline) do
    project_state(GaoBus.Activation, deadline, fn state ->
      bookkeeping = state.bookkeeping

      map_size(state.messages) + map_size(state.timers) + map_size(state.helpers) +
        :queue.len(state.effects) + MapSet.size(state.launch_notifications) +
        MapSet.size(state.deferred_systemd) +
        Enum.sum(
          Enum.map(
            [:attempts, :names, :requests, :serials, :units, :children],
            &map_size(Map.fetch!(bookkeeping, &1))
          )
        ) + if(state.drain, do: 1, else: 0)
    end)
    |> require_ok()
  end

  defp peer_supervisor_facts(deadline) do
    project_state(GaoBus.PeerSupervisor, deadline, fn state ->
      %{max_children: state.max_children, active: map_size(state.children)}
    end)
    |> require_ok()
  end

  defp listener_facts(deadline) do
    project_state(GaoBus.Listener, deadline, fn state ->
      %{
        socket_path: state.socket_path,
        peer_options: state.peer_options,
        inherited: state.identity == :inherited,
        pending_peer: if(state.pending_peer, do: 1, else: 0)
      }
    end)
    |> require_ok()
  end

  defp peer_facts(pid, deadline) do
    project_state(pid, deadline, fn state ->
      if not is_struct(state, GaoBus.Peer), do: throw({:fixture_error, :not_peer})
      queued = :queue.to_list(state.output_queue)
      outputs = if state.current_output, do: [state.current_output | queued], else: queued

      %{
        buffer_bytes: byte_size(state.buffer),
        incoming_fds: length(state.incoming_fds),
        output_messages: length(queued),
        output_fds: Enum.sum(Enum.map(outputs, &length(&1.writer.handles))),
        output_bytes:
          Enum.sum(Enum.map(outputs, &(byte_size(&1.writer.bytes) - &1.writer.offset))),
        current_output: if(state.current_output, do: 1, else: 0),
        route_wait: if(state.route_wait, do: 1, else: 0),
        auth_continuing: if(state.auth_continuing, do: 1, else: 0),
        messages_continuing: if(state.messages_continuing, do: 1, else: 0),
        read_scheduled: if(state.read_scheduled, do: 1, else: 0),
        frame_timer: if(state.frame_timer, do: 1, else: 0),
        pending_fd_timer: if(state.pending_fd_timer, do: 1, else: 0),
        mailbox: elem(Process.info(pid, :message_queue_len), 1)
      }
    end)
    |> require_ok()
  end

  defp quiescent(deadline) do
    first = snapshot(deadline)
    second = snapshot(deadline)

    if validate_accounting(first.accounting) == :ok and
         validate_accounting(second.accounting) == :ok and
         consistent(first.accounting, second.accounting) == :ok do
      second
    else
      if now() >= deadline,
        do: throw({:fixture_error, :quiescence_deadline}),
        else: quiescent(deadline)
    end
  end

  defp execute(%{"operation" => "snapshot"}, deadline), do: snapshot(deadline)
  defp execute(%{"operation" => "quiescent"}, deadline), do: quiescent(deadline)

  defp execute(%{"operation" => "metrics"}, deadline) do
    _ = quiescent(deadline)
    peers = project_state(GaoBus.Router, deadline, &Map.keys(&1.peers)) |> require_ok()
    pids = Map.values(authority_pids()) ++ peers

    Enum.each(pids, fn pid ->
      remaining = deadline - now()
      if remaining <= 0, do: throw({:fixture_error, :deadline})
      ref = make_ref()
      :erlang.garbage_collect(pid, [{:async, ref}])

      receive do
        {:garbage_collect, ^ref, true} -> :ok
        {:garbage_collect, ^ref, false} -> throw({:fixture_error, :gc_failed})
      after
        remaining -> throw({:fixture_error, :deadline})
      end
    end)

    quiescent(deadline)
  end

  defp execute(%{"operation" => "kill", "name" => name}, deadline) do
    {:ok, peer} = call(GaoBus.NameRegistry, {:resolve, name}, deadline) |> require_ok()
    peers = project_state(GaoBus.Router, deadline, &peer_records(&1.peers)) |> require_ok()
    require_check(validate_victim(name, peer, peers, Map.values(authority_pids())))
    actual = peer_identity(peer, deadline)
    if actual != %{name: name, uid: 1101}, do: throw({:fixture_error, :invalid_victim})

    :ok =
      call(
        GaoBus.Policy.Capability,
        {:grant, name, {:own, "org.foundation.Service.KillGrant"}},
        deadline
      )
      |> require_ok()

    before = snapshot(deadline)
    require_check(monitored_kill(peer, deadline))
    :ok = call(GaoBus.Router, {:unregister_peer, peer}, deadline) |> require_ok()
    :ok = call(GaoBus.Router, {:unregister_peer, peer}, deadline) |> require_ok()
    after_state = quiescent(deadline)

    if before.authorities != after_state.authorities or
         Enum.any?(after_state.peers, &(&1.peer == inspect(peer))) or
         Map.has_key?(after_state.names_by_peer, inspect(peer)) or
         Map.has_key?(after_state.matches_by_peer, inspect(peer)) or
         :ets.lookup(:gao_bus_capabilities, name) != [] or name in after_state.names,
       do: throw({:fixture_error, :incomplete_kill_cleanup})

    %{
      event: "killed",
      peer: inspect(peer),
      monitor: "DOWN:killed",
      before: before,
      snapshot: after_state
    }
  end

  def validate_victim(name, peer, peers, authorities) do
    case Map.get(peers, peer) do
      %{unique_name: ^name, credentials: %{uid: 1101}} when is_pid(peer) ->
        if unique_name?(name) and peer not in authorities,
          do: :ok,
          else: {:error, :invalid_victim}

      _ ->
        {:error, :invalid_victim}
    end
  end

  defp peer_identity(pid, deadline) do
    project_state(pid, deadline, fn state ->
      if is_struct(state, GaoBus.Peer),
        do: %{name: state.unique_name, uid: state.credentials.uid},
        else: throw({:fixture_error, :invalid_victim})
    end)
    |> require_ok()
  end

  def monitored_kill(peer, deadline) do
    remaining = deadline - now()

    if remaining <= 0 do
      {:error, :deadline}
    else
      ref = Process.monitor(peer)
      Process.exit(peer, :kill)

      result =
        receive do
          {:DOWN, ^ref, :process, ^peer, :killed} -> :ok
          {:DOWN, ^ref, :process, ^peer, _} -> {:error, :unexpected_down}
        after
          remaining -> {:error, :deadline}
        end

      Process.demonitor(ref, [:flush])
      result
    end
  end
end
