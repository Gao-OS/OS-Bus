defmodule GaoBus.PeerVariantDepthTest do
  use ExUnit.Case, async: false

  require Logger

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @owned "org.foundation.VariantDepthObserver"
  @core [
    GaoBus.Ids,
    Router,
    NameRegistry,
    Limits,
    GaoBus.Policy,
    GaoBus.MatchRules,
    GaoBus.Policy.Capability,
    PeerSupervisor
  ]
  @process_metrics [:reductions, :memory, :total_heap_size, :stack_size, :message_queue_len]
  @memory_metrics [:total, :processes_used, :binary, :ets, :atom_used]

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    assert %{uid: uid, gid: gid, real_uid: uid, real_gid: gid} = GaoBus.Unix.Native.identity()
    assert uid in 1..0xFFFFFFFE
    assert gid in 1..0xFFFFFFFE

    directory =
      Path.join(System.tmp_dir!(), "gb-vd-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    assert %{uid: ^uid, gid: ^gid, type: :directory, mode: directory_mode} = File.stat!(directory)
    assert Bitwise.band(directory_mode, 0o7777) == 0o700

    rules =
      Enum.map(
        [:connect, :own, :send, :receive],
        &%{action: &1, effect: :allow, match: %{uid: uid}}
      )

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(Limits)
    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(Router)
    start_supervised!({PeerSupervisor, max_children: 8})
    {:ok, empty_accounting} = snapshot()
    empty_authority = authority(nil)
    # Requests populate Router's initial policy cache with the configured snapshot.
    empty_authority =
      put_in(empty_authority, [:router, :policy_snapshot], GaoBus.Policy.snapshot())

    path = Path.join(directory, "bus")
    assert byte_size(path) < 108
    start_supervised!({GaoBus.Listener, socket_path: path, socket_mode: 0o600})
    assert %{uid: ^uid, gid: ^gid, mode: socket_mode} = File.stat!(path)
    assert Bitwise.band(socket_mode, 0o7777) == 0o600

    %{
      path: path,
      identity: %{uid: uid, gid: gid},
      empty_accounting: empty_accounting,
      empty_authority: empty_authority
    }
  end

  @tag timeout: 60_000
  test "PRO-05 native dynamic depth64 returns InvalidArgs and depth65 closes only its source",
       ctx do
    %{uid: uid, gid: gid} = ctx.identity
    body64 = :binary.copy(<<1, ?v, 0>>, 63) <> <<1, ?y, 0, 42>>
    body65 = <<1, ?v, 0>> <> body64
    packet64 = frame("RequestName", 3, body64, "v")
    packet65 = frame("RequestName", 6, body65, "v")
    frame64 = hex(packet64)
    frame65 = hex(packet65)
    body64_hex = hex(body64)
    body65_hex = hex(body65)
    assert byte_size(packet64) == 337
    assert byte_size(packet65) == 340

    assert {:ok, %ExDBus.Message{signature: "v", serial: 3}, <<>>} =
             ExDBus.Message.decode_message(packet64)

    assert {:error, {:invalid_body, :container_depth_exceeded}} =
             ExDBus.Message.decode_message(packet65)

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_variant_depth_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: ["-B", actor, ctx.path, Integer.to_string(uid), Integer.to_string(gid)]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert {:os_pid, actor_pid} = Port.info(port, :os_pid)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "owned" => @owned,
             "actor_pid" => ^actor_pid,
             "uid" => ^uid,
             "gid" => ^gid,
             "auth" => auth_hex,
             "ok" => ok_hex,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "bus_id" => bus_id,
             "frame64" => ^frame64,
             "frame65" => ^frame65,
             "body64" => ^body64_hex,
             "body65" => ^body65_hex,
             "pending_fds" => 0
           } = ready = actor_reply(port)

    assert Base.decode16!(auth_hex, case: :lower) == external_auth(uid)
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = frame("Hello", 1, <<>>, nil)
    get_id = frame("GetId", 2, <<>>, nil)
    assert hello_hex == hex(hello)
    assert get_id_hex == hex(get_id)
    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
    observer_only = authority(observer)
    evidence("VARIANT_DEPTH_INPUT", ready)
    Port.command(port, "open\n")

    assert %{
             "event" => "opened",
             "source" => source_name,
             "auth" => ^auth_hex,
             "ok" => ^ok_hex,
             "pending_fds" => 0
           } = opened = actor_reply(port)

    registration_writes = [auth_hex, hex("BEGIN\r\n" <> hello <> get_id)]
    assert opened["writes"] == registration_writes
    assert source_name != observer_name
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    assert {:ok, ^source} = resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
    with_source = authority(observer)
    source_before = peer_authority(source)

    # Initialize both live and absent serialization paths before the measured baseline;
    # no boundary input is sent as instrumentation warmup.
    Logger.debug("variant-depth resource instrumentation initialized")
    Logger.flush()
    initialized = resource_sample(source, observer)
    absent = process_sample(nil)

    _ =
      :json.encode(%{
        sample: initialized,
        absent: absent,
        delta: resource_delta(initialized, initialized)
      })

    baseline = resource_sample(source, observer)
    record_resources("before64", baseline, baseline)
    Port.command(port, "depth64\n")

    assert %{
             "event" => "depth64",
             "source" => ^source_name,
             "frame" => ^frame64,
             "body" => ^body64_hex,
             "error" => error,
             "source_health" => source_health,
             "observer_health" => first_health,
             "observer_health_ms" => first_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = depth64 = actor_reply(port)

    assert_invalid_args(error, source_name)
    assert_health(source_health, source_name, source_name, bus_id, 4)
    assert_health(first_health, observer_name, observer_name, bus_id, 10)
    assert first_ms >= 0 and first_ms <= 1000

    source_probe = [
      frame("GetNameOwner", 4, wire_string(source_name), "s"),
      frame("GetId", 5, <<>>, "")
    ]

    assert depth64["writes"] == registration_writes ++ [frame64] ++ Enum.map(source_probe, &hex/1)

    await(fn -> authority(observer) == with_source and peer_authority(source) == source_before end)

    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0
    record_resources("after64_quiescent", resource_sample(source, observer), baseline)
    record_resources("before65", resource_sample(source, observer), baseline)
    Port.command(port, "depth65\n")

    assert %{
             "event" => "sent65",
             "source" => ^source_name,
             "frame" => ^frame65,
             "body" => ^body65_hex,
             "pending_fds" => 0
           } = sent65 = actor_reply(port)

    assert sent65["writes"] == depth64["writes"] ++ [frame65]
    # Actor has neither closed nor read its source socket when Peer exits normally.
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
    Port.command(port, "observe-close\n")

    assert %{
             "event" => "closed",
             "disposition" => "automatic-eof",
             "terminal_hex" => "",
             "source_socket_open" => true,
             "pending_fds" => 0
           } = closed = actor_reply(port)

    await(fn -> authority(observer) == observer_only end)
    assert {:error, :name_not_found} = resolve(source_name)
    record_resources("source_departed_restored", resource_sample(source, observer), baseline)
    Port.command(port, "settled\n")

    assert %{
             "event" => "settled",
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "health" => final_health,
             "observer_health_ms" => final_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = settled = actor_reply(port)

    assert_health(final_health, observer_name, observer_name, bus_id, 12)
    assert final_ms >= 0 and final_ms <= 1000
    await(fn -> authority(observer) == observer_only end)
    assert {:ok, ^observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    record_resources("after_observer_health", resource_sample(source, observer), baseline)

    evidence("VARIANT_DEPTH_CASE", %{
      opened: opened,
      depth64: depth64,
      sent65: sent65,
      closed: closed,
      settled: settled,
      source_down: "normal",
      source_down_bound_ms: 1500,
      authority_unchanged_after64: true,
      authority_restored_after65: true
    })

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "boundaries" => [64, 65],
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "frame64" => ^frame64,
             "frame65" => ^frame65,
             "body64" => ^body64_hex,
             "body65" => ^body65_hex,
             "error" => ^error,
             "source_health" => ^source_health,
             "observer_health" => [^first_health, ^final_health],
             "observer_health_ms" => [^first_ms, ^final_ms],
             "disposition" => "automatic-eof",
             "pending_fds" => 0
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

    await(fn ->
      {:ok, accounting} = snapshot()

      children() == [] and :sys.get_state(Router, 1500).peers == %{} and
        names() == ["org.freedesktop.DBus"] and accounting == ctx.empty_accounting and
        authority(nil) == ctx.empty_authority
    end)

    assert {:error, :name_not_found} = resolve(observer_name)
    assert {:error, :name_not_found} = resolve(@owned)
    record_resources("final_empty_cleanup", resource_sample(source, observer), baseline)
    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)

    evidence(
      "VARIANT_DEPTH_SUMMARY",
      Map.merge(result, %{
        scope: "finite local native dynamic-variant subset; endpoint observations only",
        full_pro05_qualified: false,
        native_pre_fix_red: "unobserved",
        product_qualified: false
      })
    )
  end

  # Complete fixed/header/body construction independent of the production encoder.
  defp frame(member, serial, body, signature) do
    fields = [
      {1, "o", wire_string("/org/freedesktop/DBus")},
      {2, "s", wire_string("org.freedesktop.DBus")},
      {3, "s", wire_string(member)},
      {6, "s", wire_string("org.freedesktop.DBus")}
    ]

    fields =
      if is_nil(signature),
        do: fields,
        else: fields ++ [{8, "g", <<byte_size(signature)>> <> signature <> <<0>>}]

    header =
      Enum.reduce(fields, <<>>, fn {code, type, value}, acc ->
        pad(acc, 8) <> <<code, 1>> <> type <> <<0>> <> value
      end)

    <<?l, 1, 0, 1, byte_size(body)::little-32, serial::little-32, byte_size(header)::little-32>> <>
      pad(header, 8) <> body
  end

  defp wire_string(value), do: <<byte_size(value)::little-32>> <> value <> <<0>>
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  defp pad(bytes, alignment),
    do: bytes <> :binary.copy(<<0>>, rem(alignment - rem(byte_size(bytes), alignment), alignment))

  defp external_auth(uid), do: <<0>> <> "AUTH EXTERNAL " <> hex(Integer.to_string(uid)) <> "\r\n"

  defp assert_invalid_args(row, source_name) do
    assert %{"type" => 3, "fields" => fields, "body" => body} = row
    assert fields["4"] == "org.freedesktop.DBus.Error.InvalidArgs"
    assert fields["5"] == 3
    assert fields["6"] == source_name
    assert fields["7"] == "org.freedesktop.DBus"
    assert fields["8"] == "s"
    assert body == hex(wire_string("Arguments do not match the bus method signature"))
  end

  defp assert_health(rows, destination, owner, bus_id, serial) do
    assert [
             %{"type" => 2, "fields" => first, "body" => owner_body},
             %{"type" => 2, "fields" => second, "body" => ^bus_id}
           ] = rows

    assert first["5"] == serial
    assert second["5"] == serial + 1
    assert owner_body == hex(wire_string(owner))

    for fields <- [first, second] do
      assert fields["6"] == destination
      assert fields["7"] == "org.freedesktop.DBus"
      assert fields["8"] == "s"
    end
  end

  defp registered?(peer, name, actor_pid, %{uid: uid, gid: gid}) do
    state = peer_state(peer)

    state.state == :connected and state.unique_name == name and state.auth.phase == :connected and
      state.credentials == Map.put(state.auth.credentials, :unique_name, name) and
      match?(%{uid: ^uid, gid: ^gid, pid: ^actor_pid}, state.auth.credentials) and
      state.auth.buffer == <<>> and
      state.auth.total_bytes == byte_size(external_auth(uid)) + byte_size("BEGIN\r\n") and
      state.buffer == <<>> and state.incoming_fds == [] and not state.auth.unix_fd_negotiated and
      state.frame_timer == nil and state.frame_deadline == nil and
      state.frame_timeout_ms == 5000 and state.route_wait == nil and
      state.current_output == nil and state.output_queue == {[], []}
  end

  # Never retain socket/native resource handles in snapshots.
  defp peer_state(peer), do: Map.drop(:sys.get_state(peer, 1500), [:socket, :native_socket])
  defp peer_authority(nil), do: nil

  defp peer_authority(peer) do
    Map.take(peer_state(peer), [
      :unique_name,
      :credentials,
      :auth,
      :state,
      :buffer,
      :incoming_fds,
      :frame_timer,
      :frame_deadline,
      :frame_options,
      :frame_timeout_ms,
      :pending_fd_timer,
      :pending_fd_deadline,
      :registration_timer,
      :xml_limits,
      :route_wait,
      :current_output,
      :output_queue
    ])
  end

  defp authority(observer) do
    registry = :sys.get_state(NameRegistry, 1500)
    {:ok, accounting} = snapshot()

    %{
      core: Enum.map(@core, &Process.whereis/1),
      router: Map.delete(:sys.get_state(Router, 1500), :next_serial),
      registry: registry,
      names: Enum.sort(:ets.tab2list(registry.names)),
      uniques: Enum.sort(:ets.tab2list(registry.uniques)),
      reverse_names: Enum.sort(:ets.tab2list(registry.pid_names)),
      matches: :sys.get_state(GaoBus.MatchRules, 1500),
      match_entries: Enum.sort(:ets.tab2list(:gao_bus_match_rules)),
      capabilities: Enum.sort(:ets.tab2list(:gao_bus_capabilities)),
      policy: GaoBus.Policy.snapshot(),
      observer: peer_authority(observer),
      accounting: accounting
    }
  end

  defp process_sample(nil), do: %{status: "absent", pid: nil, metrics: nil}

  defp process_sample(pid) do
    case Process.info(pid, @process_metrics) do
      nil -> %{status: "absent", pid: inspect(pid), metrics: nil}
      metrics -> %{status: "live", pid: inspect(pid), metrics: Map.new(metrics)}
    end
  end

  defp resource_sample(source, observer) do
    processes =
      Map.new(@core, fn name -> {Atom.to_string(name), process_sample(Process.whereis(name))} end)

    %{
      processes:
        Map.merge(processes, %{
          "source" => process_sample(source),
          "observer" => process_sample(observer)
        }),
      vm: %{
        reductions: elem(:erlang.statistics(:reductions), 0),
        memory: Map.take(Map.new(:erlang.memory()), @memory_metrics),
        atom_count: :erlang.system_info(:atom_count),
        process_count: :erlang.system_info(:process_count),
        port_count: :erlang.system_info(:port_count)
      }
    }
  end

  defp metric_delta(current, baseline) do
    Map.new(current, fn {key, value} -> {key, value - Map.fetch!(baseline, key)} end)
  end

  defp resource_delta(sample, baseline) do
    %{
      processes:
        Map.new(sample.processes, fn {name, current} ->
          previous = Map.fetch!(baseline.processes, name)

          metrics =
            if current.status == "live" and previous.status == "live" and
                 current.pid == previous.pid,
               do: metric_delta(current.metrics, previous.metrics),
               else: nil

          {name, %{status: current.status, metrics: metrics}}
        end),
      vm: %{
        reductions: sample.vm.reductions - baseline.vm.reductions,
        memory: metric_delta(sample.vm.memory, baseline.vm.memory),
        atom_count: sample.vm.atom_count - baseline.vm.atom_count,
        process_count: sample.vm.process_count - baseline.vm.process_count,
        port_count: sample.vm.port_count - baseline.vm.port_count
      }
    }
  end

  defp record_resources(stage, sample, baseline) do
    delta = resource_delta(sample, baseline)
    evidence("VARIANT_DEPTH_RESOURCES", %{stage: stage, sample: sample, delta: delta})
    assert sample.vm.memory.total <= 256 * 1024 * 1024
    assert delta.vm.atom_count <= 16

    for name <- @core do
      assert %{status: "live"} = Map.fetch!(sample.processes, Atom.to_string(name))
    end
  end

  defp children,
    do: Enum.map(GenServer.call(PeerSupervisor, :which_children, 1500), &elem(&1, 1))

  defp snapshot, do: GenServer.call(Limits, :snapshot, 1500)
  defp names, do: GenServer.call(NameRegistry, :list_names, 1500)
  defp resolve(name), do: GenServer.call(NameRegistry, {:resolve, name}, 1500)

  defp quiet? do
    {:ok, accounting} = snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    ready? = predicate.()
    assert System.monotonic_time(:millisecond) < deadline, "variant-depth state deadline"

    unless ready? do
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
