defmodule GaoBus.PeerCollectionTest do
  use ExUnit.Case, async: false

  require Logger

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @owned "org.foundation.CollectionObserver"
  @bus "org.freedesktop.DBus"
  @frame_bytes 1_048_576
  @payload_count @frame_bytes - 16 - 120 - 4
  @header_hex "6c01000178ff0f000300000078000000" <>
                "01016f00150000002f6f72672f667265656465736b746f702f44427573000000" <>
                "02017300140000006f72672e667265656465736b746f702e4442757300000000" <>
                "03017300050000004765744964000000" <>
                "06017300140000006f72672e667265656465736b746f702e4442757300000000" <>
                "0801670002617900"
  @core [
    GaoBus.Supervisor,
    GaoBus.Ids,
    GaoBus.PeerRegistry,
    Router,
    NameRegistry,
    Limits,
    GaoBus.Policy,
    GaoBus.MatchRules,
    GaoBus.Policy.Capability,
    PeerSupervisor,
    GaoBus.Listener
  ]
  @process_metrics [:reductions, :memory, :total_heap_size, :stack_size, :message_queue_len]
  @memory_metrics [:total, :processes_used, :binary, :ets, :atom_used]

  setup do
    # The outer headless runner owns this VM; never stop or adopt another bus.
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    {:ok, _} = Application.ensure_all_started(:crypto)
    assert %{uid: uid, gid: gid, real_uid: uid, real_gid: gid} = GaoBus.Unix.Native.identity()
    assert uid in 1..0xFFFFFFFE
    assert gid in 1..0xFFFFFFFE

    directory =
      Path.join(System.tmp_dir!(), "gb-cl-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    assert %{uid: ^uid, gid: ^gid, type: :directory, mode: directory_mode} = File.stat!(directory)
    assert Bitwise.band(directory_mode, 0o7777) == 0o700

    path = Path.join(directory, "bus")
    assert byte_size(path) < 108

    rules =
      [
        %{action: :connect, effect: :allow, match: %{uid: uid}},
        %{action: :own, effect: :allow, match: %{uid: uid, name: @owned}}
      ] ++
        Enum.map(["Hello", "GetId", "RequestName", "GetNameOwner"], fn member ->
          %{
            action: :send,
            effect: :allow,
            match: %{
              uid: uid,
              destination: @bus,
              interface: @bus,
              path: "/org/freedesktop/DBus",
              member: member,
              type: :method_call
            }
          }
        end) ++
        Enum.map([:method_return, :error], fn type ->
          %{action: :receive, effect: :allow, match: %{uid: uid, sender: @bus, type: type}}
        end) ++
        [
          %{
            action: :receive,
            effect: :allow,
            match: %{
              uid: uid,
              sender: @bus,
              interface: @bus,
              member: "NameAcquired",
              type: :signal
            }
          }
        ]

    children = [
      GaoBus.Ids,
      {Registry, keys: :unique, name: GaoBus.PeerRegistry},
      Limits,
      {GaoBus.Policy, rules: rules},
      NameRegistry,
      GaoBus.MatchRules,
      GaoBus.Policy.Capability,
      Router,
      {PeerSupervisor, max_children: 8},
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600}
    ]

    core =
      start_supervised!(%{
        id: :collection_core,
        start:
          {Supervisor, :start_link, [children, [strategy: :one_for_all, name: GaoBus.Supervisor]]}
      })

    listener = Process.whereis(GaoBus.Listener)
    {:ok, empty_accounting} = snapshot()
    assert :sys.get_state(listener, 1500).peer_options == []
    assert empty_accounting.xml.limits == nil
    assert empty_accounting.xml.queues == nil
    assert empty_accounting.limits == Limits.defaults()
    assert empty_accounting.limits.peer.frame_bytes == @frame_bytes
    assert empty_accounting.limits.peer.ingress_bytes == @frame_bytes
    assert empty_accounting.limits.uid.frame_bytes == 4 * @frame_bytes
    assert empty_accounting.limits.uid.ingress_bytes == @frame_bytes
    assert empty_accounting.limits.global.frame_bytes == 16 * @frame_bytes
    assert empty_accounting.limits.global.ingress_bytes == 4 * @frame_bytes
    empty_authority = authority(nil)
    # Requests populate Router's initial policy cache with the configured snapshot.
    empty_authority =
      put_in(empty_authority, [:router, :policy_snapshot], GaoBus.Policy.snapshot())

    assert %{uid: ^uid, gid: ^gid, type: :other, mode: socket_mode} = File.stat!(path)
    assert Bitwise.band(socket_mode, 0o7777) == 0o600

    %{
      path: path,
      identity: %{uid: uid, gid: gid},
      core: core,
      listener: listener,
      empty_accounting: empty_accounting,
      empty_authority: empty_authority
    }
  end

  @tag timeout: 60_000
  test "PRO-05 native maximum-frame byte array returns InvalidArgs without changing authority",
       ctx do
    %{uid: uid, gid: gid} = ctx.identity
    payload = :binary.copy(<<42>>, @payload_count)
    body = <<@payload_count::little-32>> <> payload
    packet = frame("GetId", 3, body, "ay")
    header = Base.decode16!(@header_hex, case: :lower)
    assert @payload_count == 1_048_436
    assert byte_size(header) == 136
    assert byte_size(body) == 1_048_440
    assert byte_size(packet) == @frame_bytes
    assert binary_part(packet, 0, 136) == header
    assert hex(binary_part(packet, 0, 16)) == "6c01000178ff0f000300000078000000"
    assert hex(binary_part(body, 0, 4)) == "74ff0f00"

    assert <<?l, 1, 0, 1, 1_048_440::little-32, 3::little-32, 120::little-32,
             _header::binary-size(120), ^body::binary>> = packet

    target = %{
      "serial" => 3,
      "signature" => "ay",
      "header_hex" => @header_hex,
      "array_length_hex" => "74ff0f00",
      "payload" => %{
        "count" => @payload_count,
        "byte" => 42,
        "bytes" => byte_size(payload),
        "sha256" => sha256(payload)
      },
      "body" => receipt(body),
      "packet" => receipt(packet)
    }

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_collection_actor.py", __DIR__)

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
             "target" => ^target,
             "pending_fds" => 0
           } = ready = actor_reply(port)

    auth = external_auth(uid)
    assert Base.decode16!(auth_hex, case: :lower) == auth
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = frame("Hello", 1, <<>>, nil)
    get_id = frame("GetId", 2, <<>>, nil)
    assert hello_hex == hex(hello)
    assert get_id_hex == hex(get_id)
    registration_writes = Enum.map([auth, "BEGIN\r\n" <> hello <> get_id], &receipt/1)
    request = wire_string(@owned)
    request_name = frame("RequestName", 3, pad(request, 4) <> <<0::little-32>>, "su")
    observer_writes = registration_writes ++ [receipt(request_name)]
    assert ready["writes"] == observer_writes
    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
    assert_native_peer(observer)
    observer_only = authority(observer)
    Port.command(port, "open\n")

    assert %{
             "event" => "opened",
             "source" => source_name,
             "auth" => ^auth_hex,
             "ok" => ^ok_hex,
             "pending_fds" => 0
           } = opened = actor_reply(port)

    assert opened["writes"] == registration_writes
    assert source_name != observer_name
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    assert {:ok, ^source} = resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
    assert_native_peer(source)
    with_source = authority(observer)
    source_before = peer_authority(source)

    evidence("COLLECTION_INPUT", %{
      ready: ready,
      native_limits: ctx.empty_accounting.limits,
      native_frame_options: peer_state(source).frame_options,
      native_xml_limits: peer_state(source).xml_limits
    })

    # Initialize live/absent instrumentation without sending a target warmup.
    Logger.debug("collection resource instrumentation initialized")
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
    record_resources("before_collection", baseline, baseline)
    Port.command(port, "collection\n")

    assert %{
             "event" => "collected",
             "source" => ^source_name,
             "target" => ^target,
             "error" => error,
             "source_health" => source_health,
             "collection_ms" => collection_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = collected = actor_reply(port)

    assert_invalid_args(error, source_name)
    assert_health(source_health, source_name, source_name, bus_id, 4)
    assert collection_ms >= 0 and collection_ms <= 3000
    source_writes = registration_writes ++ [receipt(packet)] ++ health_writes(source_name, 4)
    assert collected["writes"] == source_writes
    assert collected["observer_writes"] == observer_writes

    await(fn ->
      authority(observer) == with_source and peer_authority(source) == source_before
    end)

    assert registered?(source, source_name, actor_pid, ctx.identity)
    assert registered?(observer, observer_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0

    record_resources(
      "after_collection_source_health",
      resource_sample(source, observer),
      baseline
    )

    Port.command(port, "observe\n")

    assert %{
             "event" => "observed",
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "health" => first_health,
             "observer_health_ms" => first_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = observed = actor_reply(port)

    assert_health(first_health, observer_name, observer_name, bus_id, 10)
    assert first_ms >= 0 and first_ms <= 1000
    observer_writes = observer_writes ++ health_writes(@owned, 10)
    assert observed["writes"] == observer_writes

    await(fn ->
      authority(observer) == with_source and peer_authority(source) == source_before
    end)

    assert registered?(source, source_name, actor_pid, ctx.identity)
    assert registered?(observer, observer_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    assert Process.whereis(GaoBus.Supervisor) == ctx.core
    assert Process.whereis(GaoBus.Listener) == ctx.listener
    record_resources("after_observer_health", resource_sample(source, observer), baseline)
    Port.command(port, "close-source\n")

    assert %{
             "event" => "closed",
             "disposition" => "controller-close",
             "pending_fds" => 0
           } = closed = actor_reply(port)

    assert closed["writes"] == source_writes
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
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
    observer_writes = observer_writes ++ health_writes(@owned, 12)
    assert settled["writes"] == observer_writes
    await(fn -> authority(observer) == observer_only end)
    assert {:ok, ^observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    assert registered?(observer, observer_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    record_resources("after_final_observer_health", resource_sample(source, observer), baseline)

    evidence("COLLECTION_CASE", %{
      opened: opened,
      collected: collected,
      observed: observed,
      closed: closed,
      settled: settled,
      source_down: "normal",
      source_down_bound_ms: 1500,
      authority_unchanged_after_collection: true,
      authority_restored_after_source_close: true
    })

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "target" => ^target,
             "error" => ^error,
             "source_health" => ^source_health,
             "collection_ms" => ^collection_ms,
             "source_writes" => ^source_writes,
             "observer_writes" => ^observer_writes,
             "observer_health" => [^first_health, ^final_health],
             "observer_health_ms" => [^first_ms, ^final_ms],
             "disposition" => "controller-close",
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
    core_monitor = Process.monitor(ctx.core)
    listener_monitor = Process.monitor(ctx.listener)
    assert :ok = stop_supervised(:collection_core)
    assert_receive {:DOWN, ^core_monitor, :process, _, :shutdown}, 1500
    assert_receive {:DOWN, ^listener_monitor, :process, _, :shutdown}, 1500
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    refute File.exists?(ctx.path)

    evidence(
      "COLLECTION_SUMMARY",
      Map.merge(result, %{
        scope: "finite local native materialized collection; endpoint observations only",
        payload_round_trip: false,
        full_pro05_qualified: false,
        native_pre_fix_red: "unobserved",
        product_qualified: false
      })
    )
  end

  defp assert_native_peer(peer) do
    state = peer_state(peer)
    assert state.xml_limits == nil

    assert state.frame_options == %{
             max_bytes: @frame_bytes,
             max_fds: 16,
             pending_fd_timeout: nil,
             max_output_bytes: @frame_bytes
           }
  end

  defp sha256(bytes), do: hex(:crypto.hash(:sha256, bytes))
  defp receipt(bytes), do: %{"bytes" => byte_size(bytes), "sha256" => sha256(bytes)}

  defp health_writes(owned, serial) do
    Enum.map(
      [
        frame("GetNameOwner", serial, wire_string(owned), "s"),
        frame("GetId", serial + 1, <<>>, "")
      ],
      &receipt/1
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
    evidence("COLLECTION_RESOURCES", %{stage: stage, sample: sample, delta: delta})
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
    assert System.monotonic_time(:millisecond) < deadline, "collection state deadline"

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
