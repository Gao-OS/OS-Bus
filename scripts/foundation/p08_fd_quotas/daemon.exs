Code.require_file(Enum.at(System.argv(), 1))

defmodule GaoBusFDQuotaFixture do
  @moduledoc false
  @grace 1000
  @authorities [
    GaoBus.Supervisor,
    GaoBus.Ids,
    GaoBus.NameRegistry,
    GaoBus.MatchRules,
    GaoBus.Policy,
    GaoBus.Policy.Capability,
    GaoBus.Limits,
    GaoBus.Router,
    GaoBus.Listener
  ]

  def now, do: System.monotonic_time(:millisecond)

  def emit(value) do
    encoded =
      :json.encode(value, fn
        nil, _encoder -> "null"
        other, encoder -> :json.encode_value(other, encoder)
      end)

    IO.puts("FIXTURE " <> IO.iodata_to_binary(encoded))
  end

  # One independent observer records receipt of DOWN even while main blocks on IO.
  # Only scalar identities, monitor/query refs and timestamps enter this process.
  def watcher_call(watcher, operation, deadline) do
    ref = make_ref()
    send(watcher, {:fixture_watch, self(), ref, operation})

    receive do
      {^ref, result} -> result
    after
      max(deadline - now(), 1) -> raise "monitor observer query deadline"
    end
  end

  def watcher_summary(watches, waiters, queries) do
    %{
      event: "watcher_snapshot",
      watcher: inspect(self()),
      registered: map_size(watches),
      rows:
        watches
        |> Map.values()
        |> Enum.map(& &1.row)
        |> Enum.reject(&is_nil/1)
        |> Enum.sort_by(& &1.name),
      waiting: map_size(waiters),
      queries: queries,
      max_watches: 4,
      max_queries: 32,
      clock: "BEAM monotonic receipt of DOWN"
    }
  end

  def watcher_loop(watches, waiters, queries) do
    true = elem(Process.info(self(), :message_queue_len), 1) <= 16

    receive do
      {:fixture_watch, from, query_ref, operation} ->
        queries = queries + 1
        true = queries <= 32

        case operation do
          {:register, name, pid} ->
            true = map_size(watches) < 4 and not Map.has_key?(watches, name)
            ref = Process.monitor(pid)
            registered = now()

            send(
              from,
              {query_ref,
               %{
                 event: "watch",
                 name: name,
                 peer: inspect(pid),
                 monitor_ref: inspect(ref),
                 registered_ms: registered
               }}
            )

            watcher_loop(
              Map.put(watches, name, %{pid: pid, ref: ref, registered_ms: registered, row: nil}),
              waiters,
              queries
            )

          {:await, name, deadline} ->
            watch = Map.fetch!(watches, name)

            if watch.row do
              send(from, {query_ref, watch.row})
              watcher_loop(watches, waiters, queries)
            else
              true = not Map.has_key?(waiters, name) and now() < deadline

              timer =
                Process.send_after(
                  self(),
                  {:watch_deadline, name, query_ref},
                  max(deadline - now(), 0)
                )

              watcher_loop(
                watches,
                Map.put(waiters, name, %{from: from, ref: query_ref, timer: timer}),
                queries
              )
            end

          :summary ->
            send(from, {query_ref, watcher_summary(watches, waiters, queries)})
            watcher_loop(watches, waiters, queries)

          :stop ->
            Enum.each(watches, fn {_name, watch} -> Process.demonitor(watch.ref, [:flush]) end)
            Enum.each(waiters, fn {_name, waiter} -> Process.cancel_timer(waiter.timer) end)
            send(from, {query_ref, watcher_summary(watches, waiters, queries)})
        end

      {:DOWN, ref, :process, pid, reason} ->
        received = now()

        {name, watch} =
          Enum.find(watches, fn {_name, watch} -> watch.ref == ref and watch.pid == pid end)

        true = is_nil(watch.row)

        reason =
          case reason do
            :normal -> "normal"
            :killed -> "killed"
            other -> raise "unexpected watched DOWN #{inspect(other, limit: 16)}"
          end

        row = %{
          name: name,
          peer: inspect(pid),
          monitor_ref: inspect(ref),
          reason: reason,
          registered_ms: watch.registered_ms,
          received_ms: received
        }

        watches = Map.put(watches, name, %{watch | row: row})
        {waiter, waiters} = Map.pop(waiters, name)

        if waiter do
          Process.cancel_timer(waiter.timer)
          send(waiter.from, {waiter.ref, row})
        end

        watcher_loop(watches, waiters, queries)

      {:watch_deadline, name, query_ref} ->
        case waiters[name] do
          %{ref: ^query_ref} -> raise "watched DOWN deadline #{name}"
          _ -> watcher_loop(watches, waiters, queries)
        end
    end
  end

  # Return scalars only. In particular, never retain a native_socket across kill.
  def peer(pid, info) do
    state = :sys.get_state(pid)
    output = state.current_output

    %{
      peer: inspect(pid),
      name: info.unique_name,
      credentials: Map.take(state.credentials, [:pid, :uid, :gid]),
      negotiated: state.auth.unix_fd_negotiated,
      mailbox: elem(Process.info(pid, :message_queue_len), 1),
      queue: :queue.len(state.output_queue),
      buffer_bytes: byte_size(state.buffer),
      output:
        if output do
          %{
            serial: output.message.serial,
            sender: output.message.sender,
            type: to_string(output.message.type),
            member: output.message.member,
            bytes: byte_size(output.writer.bytes),
            offset: output.writer.offset,
            deadline: output.writer.deadline,
            blocked: output.writer.blocked,
            rights_sent: output.writer.rights_sent,
            fds: length(output.writer.handles),
            sha256: Base.encode16(:crypto.hash(:sha256, output.writer.bytes), case: :lower)
          }
        end
    }
  end

  def snapshot(gc \\ false) do
    router = :sys.get_state(GaoBus.Router)
    _ = :sys.get_state(GaoBus.NameRegistry)
    _ = :sys.get_state(GaoBus.MatchRules)
    _ = :sys.get_state(GaoBus.Policy.Capability)
    {:ok, usage} = GaoBus.Limits.snapshot()

    peers =
      Enum.map(router.peers, fn {pid, info} ->
        try do
          peer(pid, info)
        catch
          :exit, reason ->
            %{peer: inspect(pid), name: info.unique_name, departed: inspect(reason)}
        end
      end)

    if gc do
      Enum.each(@authorities, &:erlang.garbage_collect(Process.whereis(&1)))
      Enum.each(Map.keys(router.peers), &:erlang.garbage_collect/1)
    end

    %{
      event: "snapshot",
      pid: System.pid(),
      now_ms: now(),
      peers: peers,
      authorities: Map.new(@authorities, &{inspect(&1), inspect(Process.whereis(&1))}),
      names: Enum.sort(GaoBus.NameRegistry.list_names()),
      matches: :ets.info(:gao_bus_match_rules, :size),
      capabilities: :ets.info(:gao_bus_capabilities, :size),
      pending: map_size(router.pending.entries),
      usage: %{
        global: usage.global,
        uids: Map.new(usage.uids, fn {uid, counts} -> {to_string(uid), counts} end),
        peers: Map.new(usage.peers, fn {pid, counts} -> {inspect(pid), counts} end),
        reservations: usage.reservations,
        limits: usage.limits,
        xml: usage.xml
      }
    }
  end

  def quiet(deadline) do
    state = snapshot()

    settled =
      state.pending == 0 and state.usage.reservations == 0 and state.peers == [] and
        map_size(state.usage.peers) == 0 and map_size(state.usage.uids) == 0 and
        Enum.all?(state.usage.global, fn {_key, value} -> value == 0 end)

    cond do
      settled -> snapshot(true)
      now() >= deadline -> raise "quiescence deadline #{inspect(state)}"
      true -> quiet(deadline)
    end
  end

  def departed(names, deadline) do
    state = snapshot()
    gone = Enum.all?(names, fn name -> not Enum.any?(state.peers, &(&1.name == name)) end)

    settled =
      gone and length(state.peers) == 3 and state.usage.global.connections == 3 and
        map_size(state.usage.peers) == 3 and state.usage.global.egress_fds == 2

    cond do
      settled -> state
      now() >= deadline -> raise "killed peer cleanup deadline #{inspect(state)}"
      true -> departed(names, deadline)
    end
  end

  def blocked(name, deadline) do
    {:ok, pid} = GaoBus.NameRegistry.resolve(name)
    row = peer(pid, %{unique_name: name})
    out = row.output

    cond do
      out && out.blocked && out.rights_sent && out.offset > 0 && out.offset < out.bytes -> row
      now() >= deadline -> raise "actual blocked writer missing #{inspect(row)}"
      true -> blocked(name, deadline)
    end
  end

  def stall(name) do
    {:ok, pid} = GaoBus.NameRegistry.resolve(name)
    :ok = :socket.setopt(:sys.get_state(pid).socket, :socket, :sndbuf, 1024)
    %{event: "stalled", name: name, peer: inspect(pid), sndbuf: 1024}
  end

  def run(socket) do
    "isolated-vm\n" = File.read!("/etc/osbus-security-guest")
    "/run/osbus-fd-quotas/bus" = socket

    limits = %{
      global: %{
        connections: 8,
        ingress_messages: 128,
        ingress_bytes: 1_048_576,
        ingress_fds: 64,
        egress_messages: 128,
        egress_bytes: 1_048_576,
        egress_fds: 3
      },
      uid: %{connections: 8, egress_messages: 128, egress_bytes: 1_048_576, egress_fds: 2},
      peer: %{
        ingress_messages: 16,
        ingress_bytes: 262_144,
        ingress_fds: 16,
        egress_messages: 16,
        egress_bytes: 262_144,
        egress_fds: 16
      }
    }

    rules =
      for uid <- [0, 1100, 1101],
          action <- [:connect, :send, :receive],
          do: %{action: action, effect: :allow, match: %{uid: uid}}

    settings = [
      socket_path: socket,
      profile: :system,
      config_file: nil,
      cluster: false,
      capability_restrictions: false,
      resource_limits: limits,
      policy_rules: rules,
      send_timeout_ms: 5000
    ]

    for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)
    {:ok, _} = Application.ensure_all_started(:gao_bus)
    collector = GaoBusFairnessCollector.start()
    _ = :crypto.hash(:sha256, "fixture-warm")
    watcher = spawn_link(fn -> watcher_loop(%{}, %{}, 0) end)
    watcher_ready = watcher_call(watcher, :summary, now() + @grace)
    :erlang.trace_pattern({GaoBus.Limits, :reserve_egress, 5}, [{:_, [], [{:return_trace}]}], [])
    :erlang.trace(Process.whereis(GaoBus.Router), true, [:send, :call, {:tracer, collector}])

    emit(%{
      event: "ready",
      pid: System.pid(),
      config_file: nil,
      profile: "system",
      resource_limits: limits,
      send_timeout_ms: 5000,
      watcher: watcher_ready
    })

    Stream.repeatedly(fn -> IO.read(:stdio, :line) end)
    |> Enum.reduce_while(%{}, fn
      :eof, _watches ->
        {:halt, %{}}

      line, watches ->
        {result, watches} =
          case String.split(String.trim(line)) do
            ["inspect"] ->
              {snapshot(), watches}

            ["metrics"] ->
              {quiet(now() + @grace), watches}

            ["departed", source, victim, deadline] ->
              {departed([source, victim], String.to_integer(deadline)), watches}

            ["stall", name] ->
              {stall(name), watches}

            ["watch", name] ->
              {:ok, pid} = GaoBus.NameRegistry.resolve(name)
              ack = watcher_call(watcher, {:register, name, pid}, now() + @grace)

              {ack,
               Map.put(watches, name, %{
                 pid: pid,
                 monitor_ref: ack.monitor_ref,
                 registered_ms: ack.registered_ms,
                 deadline: nil
               })}

            ["blocked", name] ->
              row = blocked(name, now() + @grace)
              watch = Map.fetch!(watches, name)

              {%{event: "blocked", row: row, now_ms: now()},
               Map.put(watches, name, %{watch | deadline: row.output.deadline})}

            ["kill", name, guard] ->
              watch = Map.fetch!(watches, name)
              guard_deadline = Map.fetch!(watches, guard).deadline
              true = now() < guard_deadline
              # Discard unreachable capture terms from previous scalar inspections.
              :erlang.garbage_collect()
              at = now()
              true = at < guard_deadline
              Process.exit(watch.pid, :kill)
              row = watcher_call(watcher, {:await, name, at + @grace}, at + @grace)
              "killed" = row.reason
              true = row.monitor_ref == watch.monitor_ref and row.peer == inspect(watch.pid)

              {%{
                 event: "killed",
                 name: name,
                 peer: inspect(watch.pid),
                 monitor: "DOWN:killed",
                 kill_ms: at,
                 guard_deadline: guard_deadline,
                 observed_ms: row.received_ms,
                 received_ms: row.received_ms,
                 consumed_ms: now(),
                 down: row
               }, Map.delete(watches, name)}

            ["expiry", name] ->
              watch = Map.fetch!(watches, name)

              row =
                watcher_call(
                  watcher,
                  {:await, name, watch.deadline + @grace},
                  watch.deadline + @grace
                )

              observed = row.received_ms
              "normal" = row.reason
              true = row.monitor_ref == watch.monitor_ref and row.peer == inspect(watch.pid)
              true = observed >= watch.deadline and observed <= watch.deadline + @grace

              {%{
                 event: "expired",
                 name: name,
                 peer: inspect(watch.pid),
                 monitor: "DOWN:normal",
                 deadline: watch.deadline,
                 observed_ms: observed,
                 received_ms: observed,
                 consumed_ms: now(),
                 down: row
               }, Map.delete(watches, name)}

            ["trace"] ->
              _ = :sys.get_state(GaoBus.Router)
              ref = :erlang.trace_delivered(Process.whereis(GaoBus.Router))

              receive do
                {:trace_delivered, _pid, ^ref} -> :ok
              after
                @grace -> raise "trace delivery deadline"
              end

              {GaoBusFairnessCollector.snapshot(collector), watches}

            other ->
              raise "unknown fixture command #{inspect(other)}"
          end

        emit(result)
        {:cont, watches}
    end)

    watcher_ref = Process.monitor(watcher)
    watcher_final = watcher_call(watcher, :stop, now() + @grace)

    receive do
      {:DOWN, ^watcher_ref, :process, ^watcher, :normal} -> :ok
    after
      @grace -> raise "monitor observer shutdown deadline"
    end

    emit(Map.merge(watcher_final, %{event: "watcher_stopped", monitor: "DOWN:normal"}))

    :erlang.trace(Process.whereis(GaoBus.Router), false, [:send, :call])
    :erlang.trace_pattern({GaoBus.Limits, :reserve_egress, 5}, false, [])
    ref = Process.monitor(collector)
    send(collector, :stop)

    receive do
      {:DOWN, ^ref, :process, ^collector, :normal} -> :ok
    after
      @grace -> raise "collector shutdown deadline"
    end

    emit(%{event: "collector_stopped", monitor: "DOWN:normal"})
    :ok = Application.stop(:gao_bus)
  end
end

GaoBusFDQuotaFixture.run(hd(System.argv()))
