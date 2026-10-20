defmodule GaoBus.PeerMatchArgumentTest do
  use ExUnit.Case, async: false

  require Logger

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @owned "org.foundation.MatchArgumentObserver"
  @rule "type='signal',arg0path='/probe'"
  @bus "org.freedesktop.DBus"
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
      Path.join(System.tmp_dir!(), "gb-ma-#{System.pid()}-#{System.unique_integer([:positive])}")

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
        Enum.map(["Hello", "GetId", "RequestName", "GetNameOwner", "AddMatch"], fn member ->
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
        ] ++
        Enum.map([:send, :receive], fn action ->
          %{
            action: action,
            effect: :allow,
            match: %{
              uid: uid,
              path: "/probe",
              interface: "org.foundation.Probe",
              member: "Changed",
              type: :signal
            }
          }
        end)

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
        id: :match_argument_core,
        start:
          {Supervisor, :start_link, [children, [strategy: :one_for_all, name: GaoBus.Supervisor]]}
      })

    listener = Process.whereis(GaoBus.Listener)
    {:ok, empty_accounting} = snapshot()
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
  test "PRO-05 native uint32 arg0path nonmatch preserves authority after a positive string signal",
       ctx do
    %{uid: uid, gid: gid} = ctx.identity
    positive_body = wire_string("/probe")
    uint32_body = <<42::little-32>>
    positive_packet = signal_frame(3, "s", positive_body)
    uint32_packet = signal_frame(6, "u", uint32_body)
    positive_frame = hex(positive_packet)
    uint32_frame = hex(uint32_packet)
    positive_body_hex = hex(positive_body)
    uint32_body_hex = hex(uint32_body)
    assert positive_body_hex == "060000002f70726f626500"
    assert uint32_body_hex == "2a000000"
    assert byte_size(positive_packet) == 99
    assert byte_size(uint32_packet) == 92

    assert <<?l, 4, 0, 1, 11::little-32, 3::little-32, 71::little-32,
             _positive_header::binary-size(71), 0, ^positive_body::binary>> = positive_packet

    assert <<?l, 4, 0, 1, 4::little-32, 6::little-32, 71::little-32,
             _uint32_header::binary-size(71), 0, ^uint32_body::binary>> = uint32_packet

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_match_argument_actor.py", __DIR__)

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
             "rule" => @rule,
             "actor_pid" => ^actor_pid,
             "uid" => ^uid,
             "gid" => ^gid,
             "auth" => auth_hex,
             "ok" => ok_hex,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "bus_id" => bus_id,
             "positive_frame" => ^positive_frame,
             "uint32_frame" => ^uint32_frame,
             "positive_body" => ^positive_body_hex,
             "uint32_body" => ^uint32_body_hex,
             "pending_fds" => 0
           } = ready = actor_reply(port)

    assert Base.decode16!(auth_hex, case: :lower) == external_auth(uid)
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = frame("Hello", 1, <<>>, nil)
    get_id = frame("GetId", 2, <<>>, nil)
    assert hello_hex == hex(hello)
    assert get_id_hex == hex(get_id)
    registration_writes = [auth_hex, hex("BEGIN\r\n" <> hello <> get_id)]
    request = wire_string(@owned)
    request_name = frame("RequestName", 3, pad(request, 4) <> <<0::little-32>>, "su")
    add_match = frame("AddMatch", 4, wire_string(@rule), "s")
    observer_writes = registration_writes ++ Enum.map([request_name, add_match], &hex/1)
    assert ready["writes"] == observer_writes
    assert_registration(ready["control"], observer_name, bus_id)
    assert_ownership(ready["ownership"], observer_name)
    assert_empty_reply(ready["installed"], observer_name, 4)
    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
    observer_only = authority(observer)

    assert [{^observer, match_ref, installed_rule, @rule}] = observer_only.match_entries
    assert is_reference(match_ref)

    assert installed_rule == %GaoBus.MatchRules{
             type: :signal,
             eavesdrop: false,
             args: %{{:arg_path, 0} => "/probe"}
           }

    evidence("MATCH_ARGUMENT_INPUT", ready)
    Port.command(port, "open\n")

    assert %{
             "event" => "opened",
             "source" => source_name,
             "auth" => ^auth_hex,
             "ok" => ^ok_hex,
             "pending_fds" => 0
           } = opened = actor_reply(port)

    assert opened["writes"] == registration_writes
    assert_registration(opened["receipts"], source_name, bus_id)
    assert source_name != observer_name
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    assert {:ok, ^source} = resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
    with_source = authority(observer)
    source_before = peer_authority(source)
    assert with_source.match_entries == observer_only.match_entries

    # Initialize live/absent serialization before measurement without target warmup.
    Logger.debug("match-argument resource instrumentation initialized")
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
    record_resources("before_positive", baseline, baseline)
    Port.command(port, "positive\n")

    assert %{
             "event" => "positive",
             "source" => ^source_name,
             "frame" => ^positive_frame,
             "body" => ^positive_body_hex,
             "received" => received,
             "source_health" => positive_source,
             "observer_health" => positive_observer,
             "observer_health_ms" => positive_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = positive = actor_reply(port)

    assert received == %{
             "type" => 4,
             "serial" => 3,
             "fields" => %{
               "1" => "/probe",
               "2" => "org.foundation.Probe",
               "3" => "Changed",
               "7" => source_name,
               "8" => "s"
             },
             "body" => positive_body_hex
           }

    assert_health(positive_source, source_name, source_name, bus_id, 4)
    assert_health(positive_observer, observer_name, observer_name, bus_id, 10)
    assert positive_ms >= 0 and positive_ms <= 1000
    positive_writes = registration_writes ++ [positive_frame] ++ health_writes(source_name, 4)
    observer_writes = observer_writes ++ health_writes(@owned, 10)
    assert positive["writes"] == positive_writes
    assert positive["observer_writes"] == observer_writes

    await(fn -> authority(observer) == with_source and peer_authority(source) == source_before end)

    assert registered?(source, source_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0
    record_resources("after_positive_quiescent", resource_sample(source, observer), baseline)
    record_resources("before_uint32", resource_sample(source, observer), baseline)
    Port.command(port, "uint32\n")

    assert %{
             "event" => "typed-source",
             "source" => ^source_name,
             "frame" => ^uint32_frame,
             "body" => ^uint32_body_hex,
             "source_health" => typed_source,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = typed = actor_reply(port)

    assert_health(typed_source, source_name, source_name, bus_id, 7)
    assert typed["writes"] == positive_writes ++ [uint32_frame] ++ health_writes(source_name, 7)
    assert typed["observer_writes"] == observer_writes

    await(fn -> authority(observer) == with_source and peer_authority(source) == source_before end)

    assert registered?(source, source_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0
    record_resources("after_uint32_source_health", resource_sample(source, observer), baseline)
    # Source replies settle routing before authorizing exact observer reads.
    Port.command(port, "observe\n")

    assert %{
             "event" => "observed",
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "health" => typed_observer,
             "observer_health_ms" => typed_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = observed = actor_reply(port)

    assert_health(typed_observer, observer_name, observer_name, bus_id, 12)
    assert typed_ms >= 0 and typed_ms <= 1000
    observer_writes = observer_writes ++ health_writes(@owned, 12)
    assert observed["writes"] == observer_writes

    await(fn -> authority(observer) == with_source and peer_authority(source) == source_before end)

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

    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
    await(fn -> authority(observer) == observer_only end)
    assert {:error, :name_not_found} = resolve(source_name)
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

    assert_health(final_health, observer_name, observer_name, bus_id, 14)
    assert final_ms >= 0 and final_ms <= 1000
    assert settled["writes"] == observer_writes ++ health_writes(@owned, 14)
    await(fn -> authority(observer) == observer_only end)
    assert {:ok, ^observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    assert registered?(observer, observer_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0

    evidence("MATCH_ARGUMENT_CASE", %{
      opened: opened,
      positive: positive,
      typed_source: typed,
      observed: observed,
      closed: closed,
      settled: settled,
      source_down: "normal",
      source_down_bound_ms: 1500,
      authority_unchanged_after_positive: true,
      authority_unchanged_after_uint32: true,
      authority_restored_after_source_close: true
    })

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "rule" => @rule,
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "positive_frame" => ^positive_frame,
             "uint32_frame" => ^uint32_frame,
             "positive_body" => ^positive_body_hex,
             "uint32_body" => ^uint32_body_hex,
             "received" => ^received,
             "source_health" => [^positive_source, ^typed_source],
             "observer_health" => [^positive_observer, ^typed_observer, ^final_health],
             "observer_health_ms" => [^positive_ms, ^typed_ms, ^final_ms],
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
    assert :ok = stop_supervised(:match_argument_core)
    assert_receive {:DOWN, ^core_monitor, :process, _, :shutdown}, 1500
    assert_receive {:DOWN, ^listener_monitor, :process, _, :shutdown}, 1500
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    refute File.exists?(ctx.path)

    evidence(
      "MATCH_ARGUMENT_SUMMARY",
      Map.merge(result, %{
        scope: "finite local native typed match-argument subset; endpoint observations only",
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

    wire_frame(1, serial, fields, body)
  end

  defp signal_frame(serial, signature, body) do
    wire_frame(
      4,
      serial,
      [
        {1, "o", wire_string("/probe")},
        {2, "s", wire_string("org.foundation.Probe")},
        {3, "s", wire_string("Changed")},
        {8, "g", <<byte_size(signature)>> <> signature <> <<0>>}
      ],
      body
    )
  end

  defp wire_frame(type, serial, fields, body) do
    header =
      Enum.reduce(fields, <<>>, fn {code, signature, value}, acc ->
        pad(acc, 8) <> <<code, 1>> <> signature <> <<0>> <> value
      end)

    <<?l, type, 0, 1, byte_size(body)::little-32, serial::little-32,
      byte_size(header)::little-32>> <> pad(header, 8) <> body
  end

  defp health_writes(owned, serial) do
    Enum.map(
      [
        frame("GetNameOwner", serial, wire_string(owned), "s"),
        frame("GetId", serial + 1, <<>>, "")
      ],
      &hex/1
    )
  end

  defp wire_string(value), do: <<byte_size(value)::little-32>> <> value <> <<0>>
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  defp pad(bytes, alignment),
    do: bytes <> :binary.copy(<<0>>, rem(alignment - rem(byte_size(bytes), alignment), alignment))

  defp external_auth(uid), do: <<0>> <> "AUTH EXTERNAL " <> hex(Integer.to_string(uid)) <> "\r\n"

  defp assert_registration(rows, name, bus_id) do
    [hello, get_id] = Enum.filter(rows, &(&1["type"] == 2))
    [acquired] = Enum.filter(rows, &(&1["type"] == 4))
    assert length(rows) == 3
    assert_reply(hello, name, 1, "s", hex(wire_string(name)))
    assert_reply(get_id, name, 2, "s", bus_id)
    assert_acquired(acquired, name, name)
  end

  defp assert_ownership(rows, observer_name) do
    [reply] = Enum.filter(rows, &(&1["type"] == 2))
    [acquired] = Enum.filter(rows, &(&1["type"] == 4))
    assert length(rows) == 2
    assert_reply(reply, observer_name, 3, "u", hex(<<1::little-32>>))
    assert_acquired(acquired, @owned, observer_name)
  end

  defp assert_acquired(row, name, destination) do
    assert row["type"] == 4
    assert row["body"] == hex(wire_string(name))

    assert row["fields"] == %{
             "1" => "/org/freedesktop/DBus",
             "2" => @bus,
             "3" => "NameAcquired",
             "6" => destination,
             "7" => @bus,
             "8" => "s"
           }
  end

  defp assert_empty_reply(row, destination, serial) do
    assert row["type"] == 2
    assert row["body"] == ""
    assert Map.get(row["fields"], "8", "") == ""

    assert Map.delete(row["fields"], "8") == %{
             "5" => serial,
             "6" => destination,
             "7" => @bus
           }
  end

  defp assert_reply(row, destination, serial, signature, body) do
    assert %{"type" => 2, "fields" => fields, "body" => ^body} = row
    assert fields == %{"5" => serial, "6" => destination, "7" => @bus, "8" => signature}
  end

  defp assert_health(rows, destination, owner, bus_id, serial) do
    assert [first, second] = rows
    assert_reply(first, destination, serial, "s", hex(wire_string(owner)))
    assert_reply(second, destination, serial + 1, "s", bus_id)
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
    evidence("MATCH_ARGUMENT_RESOURCES", %{stage: stage, sample: sample, delta: delta})
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
    assert System.monotonic_time(:millisecond) < deadline, "match-argument state deadline"

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
