# Root-owned VM fixture channel. This is not an exported production API.
Code.require_file(Path.join(__DIR__, "state.ex"))

[socket, policy_file] = System.argv()

unless File.read!("/etc/osbus-security-guest") == "isolated-vm\n",
  do: raise("disposable guest required")

unless String.starts_with?(socket, "/run/osbus-security/"),
  do: raise("guest fixture socket required")

Application.put_env(:gao_bus, :socket_path, socket)
Application.put_env(:gao_bus, :profile, :system)
Application.put_env(:gao_bus, :cluster, false)
Application.put_env(:gao_bus, :capability_restrictions, false)
Application.put_env(:gao_bus, :auth_limits, timeout_ms: 1500, idle_timeout_ms: 500)
Application.put_env(:gao_bus, :resource_limits, GaoBus.Limits.defaults())

rules = if policy_file == "missing", do: nil, else: elem(Code.eval_file(policy_file), 0)
Application.put_env(:gao_bus, :policy_rules, rules)
{:ok, _} = Application.ensure_all_started(:gao_bus)

emit = fn event -> IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(event))) end

emit.(%{
  event: "ready",
  pid: System.pid(),
  otp: to_string(:erlang.system_info(:system_version)),
  elixir: System.version(),
  identity: GaoBus.Unix.Native.identity(),
  policy: inspect(rules, limit: :infinity),
  configuration: %{
    profile: "system",
    socket_path: socket,
    cluster: false,
    capability_restrictions: false,
    auth_limits: %{timeout_ms: 1500, idle_timeout_ms: 500},
    resource_limits: GaoBus.Limits.defaults()
  }
})

snapshot = fn ->
  router = Process.whereis(GaoBus.Router)
  peers = if router, do: :sys.get_state(router).peers, else: %{}

  rows =
    for {pid, info} <- peers do
      %{
        name: info.unique_name,
        credentials: info.credentials,
        peer: inspect(pid),
        names: GaoBus.NameRegistry.names_for(pid),
        match_rules: GaoBus.MatchRules.has_rules?(pid),
        capabilities: length(GaoBus.Policy.Capability.capabilities(info.unique_name))
      }
    end

  {:ok, usage} = GaoBus.Limits.snapshot()

  usage = %{
    global: usage.global,
    reservations: usage.reservations,
    peers: for({pid, counts} <- usage.peers, do: %{peer: inspect(pid), counts: counts}),
    uids: for({uid, counts} <- usage.uids, do: %{uid: uid, counts: counts})
  }

  queues =
    for {name, owner, unique, flags, queue} <-
          :ets.tab2list(:sys.get_state(GaoBus.NameRegistry).names) do
      %{
        name: name,
        owner: inspect(owner),
        unique: unique,
        flags: flags,
        queue:
          for(
            {pid, unique, flags} <- queue,
            do: %{peer: inspect(pid), unique: unique, flags: flags}
          )
      }
    end

  %{
    event: "snapshot",
    router: inspect(router),
    peers: rows,
    names: GaoBus.NameRegistry.list_names(),
    queues: queues,
    usage: usage,
    policy: inspect(GaoBus.Policy.snapshot(), limit: :infinity)
  }
end

await_cleanup = fn await, pid, deadline ->
  state = snapshot.()

  if Enum.any?(state.peers, &(&1.peer == inspect(pid))) or
       Enum.any?(state.usage.peers, &(&1.peer == inspect(pid))) do
    if System.monotonic_time(:millisecond) >= deadline, do: raise("peer cleanup deadline")
    await.(await, pid, deadline)
  else
    state
  end
end

Stream.repeatedly(fn -> IO.read(:stdio, :line) end)
|> Enum.reduce_while(nil, fn
  :eof, _ ->
    {:halt, nil}

  line, _ ->
    case String.trim(line) do
      "snapshot" ->
        emit.(snapshot.())

      "stop_policy" ->
        :ok = Supervisor.terminate_child(GaoBus.Supervisor, GaoBus.Policy)
        emit.(snapshot.())

      "restart_policy" ->
        {:ok, _} = Supervisor.restart_child(GaoBus.Supervisor, GaoBus.Policy)
        emit.(snapshot.())

      "deny_admission" ->
        {:ok, _} =
          GaoBus.Policy.reload(rules ++ [%{action: :connect, effect: :deny, match: %{uid: 1101}}])

        emit.(snapshot.())

      "restore_policy" ->
        {:ok, _} = GaoBus.Policy.reload(rules)
        emit.(snapshot.())

      "metrics" ->
        deadline = System.monotonic_time(:millisecond) + 2000

        await = fn await ->
          state = snapshot.()

          if state.usage.global.connections != length(state.peers) or
               state.usage.global.authenticating != 0 or state.usage.global.ingress_messages != 0 do
            if System.monotonic_time(:millisecond) >= deadline,
              do: raise("metrics quiescence deadline")

            await.(await)
          else
            state
          end
        end

        state = await.(await)
        {:ok, counts} = GaoBus.Policy.decision_counts()

        {:message_queue_len, policy_queue} =
          Process.info(Process.whereis(GaoBus.Policy), :message_queue_len)

        {:message_queue_len, router_queue} =
          Process.info(Process.whereis(GaoBus.Router), :message_queue_len)

        emit.(%{
          event: "metrics",
          snapshot: state,
          atom_count: :erlang.system_info(:atom_count),
          decision_counts: counts,
          decision_keys: map_size(counts),
          policy_queue: policy_queue,
          router_queue: router_queue
        })

      "fill_peer_supervisor" ->
        before = DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active
        limit = Application.get_env(:gao_bus, :max_connections, 256)
        {:ok, closed} = :socket.open(:local, :stream, :default)
        :ok = :socket.close(closed)

        waiting =
          for _ <- 1..(limit - before) do
            {:ok, peer} = GaoBus.PeerSupervisor.start_peer(closed)
            nil = GaoBus.Peer.get_credentials(peer)
            peer
          end

        Process.put(:fixture_waiting_peers, waiting)
        {:error, :max_children} = GaoBus.PeerSupervisor.start_peer(closed)

        emit.(%{
          event: "supervisor_full",
          before: before,
          limit: limit,
          injected: length(waiting),
          active: DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active
        })

      "clear_peer_supervisor" ->
        waiting = Process.delete(:fixture_waiting_peers)

        Enum.each(waiting, fn peer ->
          :ok = DynamicSupervisor.terminate_child(GaoBus.PeerSupervisor, peer)
        end)

        emit.(%{
          event: "supervisor_restored",
          active: DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active,
          snapshot: snapshot.()
        })

      "credential_failure" ->
        before = snapshot.()
        {:ok, closed} = :socket.open(:local, :stream, :default)
        :ok = :socket.close(closed)
        {:error, reason} = GaoBus.Unix.Credentials.read(closed)
        {:ok, peer} = GaoBus.PeerSupervisor.start_peer(closed)
        reference = Process.monitor(peer)
        nil = GaoBus.Peer.get_credentials(peer)
        send(peer, :socket_ready)

        receive do
          {:DOWN, ^reference, :process, ^peer, :normal} -> :ok
        after
          2000 -> raise "closed-credential peer did not stop"
        end

        after_state =
          await_cleanup.(await_cleanup, peer, System.monotonic_time(:millisecond) + 2000)

        emit.(%{
          event: "credential_failure",
          adapter_error: inspect(reason),
          peer: inspect(peer),
          before: before,
          after: after_state,
          credentials_before: "nil",
          termination: "normal"
        })

      "prepare_cleanup " <> name ->
        {:ok, peer} = GaoBus.NameRegistry.resolve(name)
        :ok = GaoBus.Policy.Capability.grant(name, {:own, "org.foundation.Service.Cleanup"})
        {:ok, token} = GaoBus.Limits.reserve_ingress(peer, 128)
        Process.put({:fixture_ingress, name}, token)

        emit.(%{
          event: "cleanup_prepared",
          peer: inspect(peer),
          token: inspect(token),
          snapshot: snapshot.()
        })

      "kill_peer " <> name ->
        {:ok, peer} = GaoBus.NameRegistry.resolve(name)
        before = snapshot.()
        reference = Process.monitor(peer)
        Process.exit(peer, :kill)

        receive do
          {:DOWN, ^reference, :process, ^peer, :killed} -> :ok
        after
          2000 -> raise "killed peer did not stop"
        end

        # Peer DOWN can enqueue NameAcquired/NameOwnerChanged on healthy peers.
        # Wait for their real egress retirement before checking exact credit.
        {:ok, retained} =
          GaoBusSecurityFixture.State.await(
            snapshot,
            inspect(peer),
            %{reservations: 1, ingress_messages: 1, ingress_bytes: 128, ingress_fds: 0},
            2000
          )

        1 = retained.usage.reservations
        1 = retained.usage.global.ingress_messages
        128 = retained.usage.global.ingress_bytes
        token = Process.delete({:fixture_ingress, name})
        true = is_reference(token)
        # The controller owns this synthetic queued-work credit as its consumer.
        # Source death must not reclaim it before that work has been retired.
        :ok = GaoBus.Limits.release(token)

        {:ok, after_state} =
          GaoBusSecurityFixture.State.await(
            snapshot,
            inspect(peer),
            %{reservations: 0, ingress_messages: 0, ingress_bytes: 0, ingress_fds: 0},
            2000
          )

        0 = after_state.usage.reservations
        0 = after_state.usage.global.ingress_messages
        0 = after_state.usage.global.ingress_bytes
        :ok = GaoBus.Router.unregister_peer(peer)
        :ok = GaoBus.Router.unregister_peer(peer)
        GaoBus.NameRegistry.peer_disconnected(peer)
        GaoBus.MatchRules.peer_disconnected(peer)
        GaoBus.Policy.Capability.peer_disconnected(name)
        _ = :sys.get_state(GaoBus.NameRegistry)
        _ = :sys.get_state(GaoBus.MatchRules)
        _ = :sys.get_state(GaoBus.Policy.Capability)

        emit.(%{
          event: "peer_killed",
          peer: inspect(peer),
          before: before,
          retained_ingress: retained,
          consumer_release: "ok",
          after: after_state,
          repeated_cleanup: snapshot.(),
          capabilities: length(GaoBus.Policy.Capability.capabilities(name)),
          match_rules: GaoBus.MatchRules.has_rules?(peer),
          termination: "killed"
        })

      "quit" ->
        Application.stop(:gao_bus)

      other ->
        raise "unknown fixture command #{inspect(other)}"
    end

    {:cont, nil}
end)

