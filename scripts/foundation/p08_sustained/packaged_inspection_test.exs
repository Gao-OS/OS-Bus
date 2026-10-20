ExUnit.start()

fixture = Path.join(__DIR__, "packaged_inspection.exs")
if File.exists?(fixture), do: Code.require_file(fixture)

defmodule OSBusFoundationPackagedInspectorTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  alias OSBusFoundationPackagedInspector, as: Inspector

  test "actual NameRegistry reverse counts include unique primary queued and cleaned peers" do
    registry =
      start_supervised!({GaoBus.NameRegistry, max_names_per_peer: 13, max_name_entries: 97})

    primary = start_supervised!({Agent, fn -> :primary end}, id: :primary)
    queued = start_supervised!({Agent, fn -> :queued end}, id: :queued)
    healthy = start_supervised!({Agent, fn -> :healthy end}, id: :healthy)
    primary_key = inspect(primary)
    queued_key = inspect(queued)
    healthy_key = inspect(healthy)
    name = "org.foundation.Service.TableRepair"
    healthy_name = "org.foundation.Observer.TableRepair"

    assert :ok = GaoBus.NameRegistry.register_unique(":1.41", primary)
    assert :ok = GaoBus.NameRegistry.register_unique(":1.42", queued)
    assert :ok = GaoBus.NameRegistry.register_unique(":1.43", healthy)
    assert {:ok, 1} = GaoBus.NameRegistry.request_name(name, 0, primary, ":1.41")
    assert {:ok, 2} = GaoBus.NameRegistry.request_name(name, 0, queued, ":1.42")
    assert {:ok, 2} = GaoBus.NameRegistry.request_name(name, 0, queued, ":1.42")
    assert {:ok, 1} = GaoBus.NameRegistry.request_name(healthy_name, 0, healthy, ":1.43")
    assert {:ok, [":1.41", ":1.42"]} = GaoBus.NameRegistry.list_queued_owners(name)
    assert GaoBus.NameRegistry.names_for(queued) == [":1.42"]
    assert :ets.whereis(:gao_bus_pid_names) == :undefined

    deadline = System.monotonic_time(:millisecond) + 3000

    assert {:ok,
            %{
              names_by_peer: %{^primary_key => 2, ^queued_key => 2, ^healthy_key => 2},
              max_names_per_peer: 13,
              max_name_entries: 97,
              xml_limits?: false
            } = facts} = Inspector.name_registry_facts(deadline)

    assert Enum.sort(Map.keys(facts)) ==
             [:max_name_entries, :max_names_per_peer, :names_by_peer, :xml_limits?]

    assert map_size(facts.names_by_peer) == 3

    assert {:error, :unsafe_observation_result} =
             Inspector.project_state(registry, deadline, &Map.take(&1, [:pid_names]))

    assert {:error, :unsafe_observation_result} =
             Inspector.project_state(registry, deadline, & &1)

    GaoBus.NameRegistry.peer_disconnected(primary)
    # The synchronous call is a same-sender barrier for the disconnect cast.
    assert {:ok, [":1.42"]} = GaoBus.NameRegistry.list_queued_owners(name)
    assert {:error, :name_not_found} = GaoBus.NameRegistry.resolve(":1.41")

    assert {:ok, %{names_by_peer: %{^queued_key => 2, ^healthy_key => 2} = remaining}} =
             Inspector.name_registry_facts(deadline)

    assert map_size(remaining) == 2

    GaoBus.NameRegistry.peer_disconnected(queued)
    assert {:error, :name_not_found} = GaoBus.NameRegistry.resolve(name)
    assert {:error, :name_not_found} = GaoBus.NameRegistry.resolve(":1.42")
    assert {:ok, healthy} == GaoBus.NameRegistry.resolve(healthy_name)

    assert {:ok, %{names_by_peer: %{^healthy_key => 2} = remaining}} =
             Inspector.name_registry_facts(deadline)

    assert map_size(remaining) == 1

    GaoBus.NameRegistry.peer_disconnected(healthy)
    assert GaoBus.NameRegistry.list_names() == ["org.freedesktop.DBus"]
    assert {:ok, %{names_by_peer: empty}} = Inspector.name_registry_facts(deadline)
    assert empty == %{}
  end

  test "actual NameRegistry projection shares the absolute deadline when blocked" do
    registry = start_supervised!(GaoBus.NameRegistry)
    tasks = start_supervised!(Task.Supervisor)
    parent = self()

    {:ok, caller} =
      Task.Supervisor.start_child(tasks, fn ->
        :sys.replace_state(registry, fn state ->
          send(parent, :registry_blocked)

          receive do
            :release_registry -> state
          end
        end)
      end)

    ref = Process.monitor(caller)
    assert_receive :registry_blocked
    started = System.monotonic_time(:millisecond)
    deadline = started + 40

    try do
      assert {:error, :deadline} = Inspector.name_registry_facts(deadline)
      assert {:error, :deadline} = Inspector.name_registry_facts(deadline)
      assert System.monotonic_time(:millisecond) - started < 3000
    after
      send(registry, :release_registry)
      assert_receive {:DOWN, ^ref, :process, ^caller, :normal}
    end

    assert {:ok, %{names_by_peer: empty}} =
             Inspector.name_registry_facts(System.monotonic_time(:millisecond) + 3000)

    assert empty == %{}
  end

  test "Router peer projection excludes monitor and opaque transport state" do
    credentials = %{uid: 1101, gid: 100, groups: [100], pid: 17}

    peers = %{
      self() => %{
        unique_name: ":1.42",
        credentials: credentials,
        unix_fd: true,
        monitor_ref: make_ref(),
        private_transport: make_ref()
      }
    }

    assert Inspector.peer_records(peers) ==
             %{self() => %{unique_name: ":1.42", credentials: credentials, unix_fd: true}}
  end

  test "core code identities retain wrong paths and non-file origins instead of omitting them" do
    loaded = [
      {GaoBus.Policy, ~c"/tmp/substitute.beam"},
      {ExDBus, :preloaded},
      {GaoBus, ~c"/release/lib/gao_bus-0.1.0/ebin/Elixir.GaoBus.beam"},
      {Enum, ~c"/release/lib/elixir/ebin/Elixir.Enum.beam"}
    ]

    observed = Inspector.code_identity(loaded, "/release")

    assert Enum.sort(Map.keys(observed)) == [
             "Elixir.ExDBus",
             "Elixir.GaoBus",
             "Elixir.GaoBus.Policy"
           ]

    assert observed["Elixir.GaoBus.Policy"].path == "/tmp/substitute.beam"
    assert observed["Elixir.ExDBus"].path == "nonfile:preloaded"
    assert observed["Elixir.GaoBus"].path == "lib/gao_bus-0.1.0/ebin/Elixir.GaoBus.beam"

    assert observed["Elixir.GaoBus.Policy"].md5 ==
             Base.encode16(GaoBus.Policy.module_info(:md5), case: :lower)
  end

  test "local observation and encoding share one absolute deadline and reap their worker" do
    parent = self()
    deadline = System.monotonic_time(:millisecond) + 40

    assert {:error, :deadline} =
             Inspector.observation(deadline, fn ->
               send(parent, {:observer, self()})

               receive do
                 :finish -> :unexpected_success
               end
             end)

    assert_receive {:observer, worker}
    ref = Process.monitor(worker)
    assert_receive {:DOWN, ^ref, :process, ^worker, :noproc}

    assert {:error, :deadline} =
             Inspector.observation(deadline, fn -> flunk("expired work ran") end)

    refute_receive {_, {:ok, :unexpected_success}}, 0
  end

  test "projected state cannot return an opaque native reference to the console" do
    owner =
      start_supervised!(
        {Agent,
         fn ->
           {:ok, socket} = :socket.open(:local, :stream, :default)
           {:ok, native} = GaoBus.Unix.Resources.capture(socket)
           %{socket: socket, native: native}
         end}
      )

    assert {:error, :unsafe_observation_result} =
             Inspector.project_state(owner, System.monotonic_time(:millisecond) + 1000, & &1)
  end

  test "projected native state dies before receipt and releases the killed holder's descriptor" do
    parent = self()

    owner =
      start_supervised!(
        {Agent,
         fn ->
           {:ok, socket} = :socket.open(:local, :stream, :default)
           {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
           {:ok, native} = GaoBus.Unix.Resources.capture(socket)
           %{socket: socket, native: native, target: File.read_link!("/proc/self/fd/#{fd}")}
         end},
        restart: :temporary
      )

    target = Agent.get(owner, & &1.target)
    assert count_target(target) == 2

    assert {:ok, %{target: ^target, retained_while_observing: 1}} =
             Inspector.project_state(
               owner,
               System.monotonic_time(:millisecond) + 1000,
               fn state ->
                 send(parent, {:observer, self()})
                 assert {:ok, %{cloexec: true}} = GaoBus.Unix.Resources.info(state.native)
                 ref = Process.monitor(owner)
                 Process.exit(owner, :kill)
                 assert_receive {:DOWN, ^ref, :process, ^owner, :killed}
                 retained = count_target(state.target)
                 # Keep the positive-control reference live through the count;
                 # compiler liveness may otherwise release it before the sample.
                 assert {:ok, %{cloexec: true}} = GaoBus.Unix.Resources.info(state.native)
                 %{target: state.target, retained_while_observing: retained}
               end
             )

    assert_receive {:observer, observer}
    ref = Process.monitor(observer)
    assert_receive {:DOWN, ^ref, :process, ^observer, :noproc}
    assert count_target(target) == 0
  end

  defp count_target(target) do
    "/proc/self/fd"
    |> File.ls!()
    |> Enum.count(fn fd -> File.read_link("/proc/self/fd/" <> fd) == {:ok, target} end)
  end

  test "ordered whole policy and metadata come from the same captured tuple" do
    configuration = %{
      settings: %{type: :system},
      limits: %{"reply_timeout" => 100},
      accounts: %{memberships: %{1100 => [100], 1101 => [100]}},
      sources: [%{path: "/run/osbus-p08/config/bus.conf", sha256: "frozen"}]
    }

    policy = %GaoBus.Policy.XML{
      blocks: [
        %{
          selector: {:user, 1101},
          rules: [
            %{action: :receive, effect: :deny, attributes: %{"receive_requested_reply" => true}}
          ]
        }
      ],
      daemon_uid: 4,
      memberships: %{1100 => [100], 1101 => [100], 42 => [42]},
      needs_groups: false,
      configuration: configuration
    }

    assert %{generation: 7, configuration: ^configuration, compiled_policy: ^policy} =
             Inspector.policy_record({:ok, 7, policy})
  end

  defp request(operation \\ "snapshot") do
    %{
      "schema" => 1,
      "nonce" => String.duplicate("a", 32),
      "request_id" => 1,
      "operation" => operation
    }
  end

  defp encoded(value), do: value |> :json.encode() |> IO.iodata_to_binary() |> Base.encode64()

  defp accounting do
    counts = %{
      connections: 1,
      authenticating: 0,
      ingress_messages: 0,
      ingress_bytes: 0,
      ingress_fds: 0,
      egress_messages: 0,
      egress_bytes: 0,
      egress_fds: 0,
      frame_bytes: 0,
      frame_fds: 0,
      activation_messages: 0,
      activation_bytes: 0,
      activation_fds: 0
    }

    peer = inspect(self())

    usage = %{
      global: counts,
      uids: %{1101 => counts},
      peers: %{self() => counts},
      reservations: 0,
      reload_reservations: 0,
      limits: %{global: %{connections: 8}},
      xml: %{
        limits: %{"max_completed_connections" => 7},
        queues: %{"max_outgoing_bytes" => 262_144},
        global: %{incomplete: 0, completed: 1},
        uids: %{1101 => 1}
      }
    }

    %{
      usage: usage,
      peers: [%{peer: peer, uid: 1101, name: ":1.42"}],
      pending: 0,
      retired: 0,
      bound_handles: 0,
      reload: 0,
      activation: 0,
      peer_queues: %{
        peer => %{
          buffer_bytes: 0,
          incoming_fds: 0,
          output_messages: 0,
          output_fds: 0,
          output_bytes: 0,
          current_output: 0,
          route_wait: 0,
          auth_continuing: 0,
          messages_continuing: 0,
          read_scheduled: 0,
          frame_timer: 0,
          pending_fd_timer: 0,
          mailbox: 0
        }
      },
      authorities: %{"Router" => inspect(self())}
    }
  end

  test "the complete Limits term survives ETF and PID-safe display" do
    usage =
      accounting().usage
      |> put_in([:uids, 1101, :frame_fds], 2)
      |> put_in([:peers, self(), :egress_bytes], 123)
      |> put_in([:xml, :global, :incomplete], 3)
      |> Map.put(:reload_reservations, 1)

    envelope = Inspector.encode_usage(usage)
    assert envelope.encoding == "erlang-external-term/base64"
    bytes = Base.decode64!(envelope.base64)
    assert byte_size(bytes) == envelope.bytes
    assert envelope.sha256 == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    assert :erlang.binary_to_term(bytes, [:safe]) == usage
    display = Inspector.display(usage)
    assert display["peers"][inspect(self())]["connections"] == 1
    assert display["uids"]["1101"]["connections"] == 1
    assert display["xml"]["queues"]["max_outgoing_bytes"] == 262_144
    assert display["reload_reservations"] == 1
    assert display["peers"][inspect(self())]["egress_bytes"] == 123
    assert display["uids"]["1101"]["frame_fds"] == 2
    assert display["xml"]["global"]["incomplete"] == 3
    assert :json.decode(IO.iodata_to_binary(:json.encode(display))) == display

    assert {:error, :invalid_accounting} =
             Inspector.validate_accounting(%{
               accounting()
               | usage: %{global: usage.global, reservations: 0, peers: 1}
             })
  end

  test "every full-scope resource credit prevents quiescence" do
    state = accounting()
    assert :ok = Inspector.validate_accounting(state)

    for scope <- [:global, :uids, :peers],
        metric <- Map.keys(state.usage.global) -- [:connections] do
      mutated =
        case scope do
          :global -> put_in(state, [:usage, :global, metric], 1)
          :uids -> put_in(state, [:usage, :uids, 1101, metric], 1)
          :peers -> put_in(state, [:usage, :peers, self(), metric], 1)
        end

      assert {:error, :not_quiescent} = Inspector.validate_accounting(mutated),
             "accepted #{scope}/#{metric}"
    end
  end

  test "orphaned UID Peer XML and cleanup work fail even when global credits are zero" do
    state = accounting()

    mutations = [
      put_in(state, [:usage, :uids], %{}),
      put_in(state, [:usage, :peers], %{}),
      put_in(state, [:usage, :peers], %{inspect(self()) => state.usage.global}),
      put_in(state, [:usage, :global, :connections], 2),
      put_in(state, [:usage, :xml, :global, :completed], 2),
      put_in(state, [:usage, :xml, :global, :incomplete], 1),
      put_in(state, [:usage, :xml, :uids], %{1101 => 1, 4 => 0}),
      put_in(state, [:usage, :uids, 4], %{state.usage.global | connections: 0}),
      put_in(state, [:usage, :reservations], 1),
      put_in(state, [:usage, :reload_reservations], 1)
    ]

    for changed <- mutations,
        do: assert(match?({:error, _}, Inspector.validate_accounting(changed)))

    for key <- [:pending, :retired, :bound_handles, :reload, :activation] do
      assert {:error, :not_quiescent} = Inspector.validate_accounting(Map.put(state, key, 1))
    end

    for key <- Map.keys(state.peer_queues[inspect(self())]) do
      changed = put_in(state, [:peer_queues, inspect(self()), key], 1)
      assert {:error, :not_quiescent} = Inspector.validate_accounting(changed)
    end

    assert {:error, :invalid_accounting} =
             Inspector.validate_accounting(Map.delete(state, :peer_queues))
  end

  test "two observations must agree on complete accounting and authority identity" do
    state = accounting()
    assert :ok = Inspector.consistent(state, state)

    assert {:error, :inconsistent_accounting} =
             Inspector.consistent(
               state,
               put_in(state, [:usage, :limits, :global, :connections], 9)
             )

    assert {:error, :inconsistent_accounting} =
             Inspector.consistent(
               state,
               put_in(state, [:authorities, "Router"], "#PID<0.999.0>")
             )
  end

  test "requests bind exact schema nonce identity operation size and unique victim" do
    for operation <- ["snapshot", "quiescent", "metrics"] do
      value = request(operation)
      assert {:ok, ^value} = Inspector.decode_request(encoded(value))
    end

    kill = Map.put(request("kill"), "name", ":1.42")
    assert {:ok, ^kill} = Inspector.decode_request(encoded(kill))

    for bad <- [
          Map.put(request(), "schema", 2),
          Map.put(request(), "nonce", "A"),
          Map.put(request(), "request_id", 0),
          Map.put(request(), "operation", "eval"),
          Map.put(request(), "name", ":1.42"),
          Map.put(request(), "extra", 1),
          request("kill"),
          Map.put(kill, "name", "GaoBus.Router"),
          Map.put(kill, "name", ":1.42\";System.stop()")
        ] do
      assert {:error, :invalid_request} = Inspector.decode_request(encoded(bad))
    end

    for bad <- ["%", Base.encode64("{"), Base.encode64(String.duplicate("x", 4097))] do
      assert {:error, _} = Inspector.decode_request(bad)
    end
  end

  test "duplicate JSON keys and substituted complete queue fields reject" do
    json = IO.iodata_to_binary(:json.encode(request()))
    duplicate = "{\"schema\":2," <> String.slice(json, 1..-1//1)
    assert {:error, :invalid_request} = Inspector.decode_request(Base.encode64(duplicate))
    state = accounting()
    queue = state.peer_queues[inspect(self())] |> Map.delete(:mailbox) |> Map.put(:invented, 0)
    changed = put_in(state, [:peer_queues, inspect(self())], queue)
    assert {:error, :invalid_accounting} = Inspector.validate_accounting(changed)
  end

  test "reply emits one exact identity-bound error envelope and returns only ok" do
    invalid = request("eval")
    output = capture_io(fn -> assert :ok = Inspector.reply(encoded(invalid)) end)
    assert "\nFIXTURE " <> payload = output
    envelope = :json.decode(String.trim(payload))
    assert Enum.sort(Map.keys(envelope)) == ~w(error nonce ok pid request_id schema)
    assert envelope["schema"] == 1
    assert envelope["nonce"] == invalid["nonce"]
    assert envelope["request_id"] == 1
    assert envelope["pid"] == String.to_integer(System.pid())
    assert envelope["ok"] == false
    assert envelope["error"] == ":invalid_request"
  end

  test "guard requires actual disposable packaged system identity and no distribution" do
    guard = %{
      marker: "isolated-vm\n",
      profile: :system,
      lifecycle: :release,
      node: :nonode@nohost,
      native: %{uid: 4, real_uid: 4, gid: 4, real_gid: 4},
      uids: [4, 4, 4, 4],
      gids: [4, 4, 4, 4],
      config: "/run/osbus-p08/config/bus.conf",
      socket: "/run/osbus-p08/socket/bus",
      release: "/run/osbus-p08/release",
      cluster: false,
      inherited: false
    }

    assert :ok = Inspector.validate_guard(guard)

    for {key, value} <- [
          marker: "",
          profile: :session,
          lifecycle: :embedded,
          node: :named@host,
          uids: [0, 4, 4, 4],
          gids: [4, 0, 4, 4],
          config: "/etc/dbus-1/system.conf",
          socket: "/run/dbus/system_bus_socket",
          release: nil,
          cluster: true,
          inherited: true
        ] do
      assert {:error, :unsafe_environment} = Inspector.validate_guard(Map.put(guard, key, value))
    end

    assert {:error, :unsafe_environment} =
             Inspector.validate_guard(put_in(guard, [:native, :real_uid], 0))
  end

  test "a victim must be the actual registered UID1101 Peer and never an authority" do
    peer = self()
    peers = %{peer => %{unique_name: ":1.42", credentials: %{uid: 1101}}}
    assert :ok = Inspector.validate_victim(":1.42", peer, peers, [])
    assert {:error, :invalid_victim} = Inspector.validate_victim(":1.43", peer, peers, [])

    assert {:error, :invalid_victim} =
             Inspector.validate_victim(
               ":1.42",
               peer,
               put_in(peers, [peer, :credentials, :uid], 1100),
               []
             )

    assert {:error, :invalid_victim} = Inspector.validate_victim(":1.42", peer, peers, [peer])
    assert {:error, :invalid_victim} = Inspector.validate_victim(":1.42", peer, %{}, [])
  end

  test "state calls share an absolute deadline without leaking a blocked task" do
    pid = start_supervised!({Agent, fn -> 1 end})
    owner = self()
    tasks = start_supervised!(Task.Supervisor)

    {:ok, caller} =
      Task.Supervisor.start_child(tasks, fn ->
        Agent.get(pid, fn _ ->
          send(owner, :blocked)

          receive do
            :finish -> :ok
          end
        end)
      end)

    caller_ref = Process.monitor(caller)
    assert_receive :blocked
    deadline = System.monotonic_time(:millisecond) + 40
    assert {:error, :deadline} = Inspector.call(pid, :snapshot, deadline)
    assert {:error, :deadline} = Inspector.call(pid, :snapshot, deadline)
    ref = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^ref, :process, ^pid, :killed}
    assert_receive {:DOWN, ^caller_ref, :process, ^caller, _}
  end

  test "monitored kill requires exact killed DOWN" do
    pid = start_supervised!({Agent, fn -> 1 end}, restart: :temporary)
    assert :ok = Inspector.monitored_kill(pid, System.monotonic_time(:millisecond) + 100)

    assert {:error, :unexpected_down} =
             Inspector.monitored_kill(
               pid,
               System.monotonic_time(:millisecond) + 100
             )
  end
end
