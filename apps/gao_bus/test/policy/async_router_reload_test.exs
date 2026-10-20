defmodule GaoBus.Policy.AsyncRouterReloadTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Config, Limits, NameRegistry, Policy, Router}
  alias GaoBus.Unix.Resources

  @moduletag :tmp_dir
  @bus "org.freedesktop.DBus"
  @first "org.test.AsyncFirst"
  @second "org.test.AsyncSecond"

  setup %{tmp_dir: directory} = tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    previous = Application.fetch_env(:gao_bus, :capability_restrictions)
    Application.put_env(:gao_bus, :capability_restrictions, false)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:gao_bus, :capability_restrictions, value)
        :error -> Application.delete_env(:gao_bus, :capability_restrictions)
      end
    end)

    File.chmod!(directory, 0o700)

    socket_directory =
      Path.join(System.tmp_dir!(), "gb-ar-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(socket_directory)
    File.chmod!(socket_directory, 0o700)
    on_exit(fn -> File.rm_rf!(socket_directory) end)
    services = Path.join(directory, "services")
    File.mkdir!(services)
    %{uid: uid, gid: gid} = GaoBus.Unix.Native.identity()
    gate = make_ref()

    accounts = %{
      users: %{"fixture" => uid},
      groups: %{"fixture" => gid},
      memberships: %{uid => [gid]},
      user_records: %{
        "fixture" => %{name: "fixture", uid: uid, gid: gid, groups: [gid], provenance: nil}
      }
    }

    context = %{
      path: Path.join(socket_directory, "bus"),
      config: Path.join(directory, "bus.conf"),
      services: services,
      gate: gate,
      uid: uid,
      config_options: [daemon_uid: uid, accounts: accounts]
    }

    write_configuration(context, @first, Map.get(tags, :deny_reload, false))
    assert {:ok, config} = Config.load(context.config, context.config_options)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(Limits)
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)

    start_supervised!(
      {Policy,
       rules: config,
       config_file: context.config,
       config_options: context.config_options,
       publication: :router,
       reload_prepare_barrier: {self(), gate}}
    )

    start_supervised!(GaoBus.Policy.Capability)
    router = start_supervised!(Router)
    start_supervised!(GaoBus.PeerSupervisor)
    start_supervised!({GaoBus.Listener, socket_path: context.path})
    {caller, name} = registered(context)
    {observer, _} = registered(context)
    Map.merge(context, %{caller: caller, name: name, observer: observer, router: router})
  end

  test "preparation leaves another real peer healthy and the old whole generation visible", ctx do
    original = Policy.snapshot()
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 10)
    worker = prepared(ctx)

    send_call(ctx.observer, "Ping", 20, interface: "org.freedesktop.DBus.Peer")
    assert %Message{type: :method_return, serial: health_serial} = reply(ctx.observer, 20)
    assert Process.whereis(Router) == ctx.router
    assert Policy.snapshot() == original
    assert list(ctx.observer, 21) == [@first]
    assert {:ok, usage} = Limits.snapshot()
    assert usage.global.ingress_messages == 0
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == [worker]
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)

    release(ctx, worker)
    assert %Message{type: :method_return, serial: serial, fds: []} = reply(ctx.caller, 10)
    assert serial > health_serial
    assert {:ok, 2, _} = Policy.snapshot()
    assert list(ctx.observer, 22) == [@second]
  end

  test "NO_REPLY reload holds the same connection's Ping until publication", ctx do
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 30, flags: 1)
    worker = prepared(ctx)
    send_call(ctx.caller, "Ping", 31, interface: "org.freedesktop.DBus.Peer")
    assert list(ctx.observer, 32) == [@first]
    assert {:ok, peer} = NameRegistry.resolve(ctx.name)
    assert is_reference(:sys.get_state(peer).route_wait)
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)

    release(ctx, worker)
    assert %Message{type: :method_return, reply_serial: 31} = next_message(ctx.caller)
    assert list(ctx.caller, 33) == [@second]
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)
    assert {:ok, 2, _} = Policy.snapshot()
  end

  test "the completion reply uses admission receive policy and current Router serial", ctx do
    write_configuration(ctx, @second, false, true)
    send_call(ctx.caller, "ReloadConfig", 40)
    worker = prepared(ctx)
    send_call(ctx.observer, "GetId", 41)
    assert %Message{type: :method_return, serial: previous_serial} = reply(ctx.observer, 41)
    release(ctx, worker)

    assert %Message{type: :method_return, serial: serial, destination: destination} =
             reply(ctx.caller, 40)

    assert serial > previous_serial
    assert destination == ctx.name
    assert {:ok, 2, _} = current = Policy.snapshot()

    assert {:deny, :policy_denied} =
             Policy.authorize(current, :receive, %{
               credentials: %{uid: ctx.uid},
               sender_names: [@bus],
               destination_names: [ctx.name],
               requested_reply: true,
               message: %Message{type: :method_return}
             })
  end

  test "busy callers cannot enqueue more workers or replace the admitted waiter", ctx do
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 50)
    worker = prepared(ctx)

    for serial <- 51..62 do
      send_call(ctx.observer, "ReloadConfig", serial)

      assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.LimitsExceeded"} =
               reply(ctx.observer, serial)
    end

    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == [worker]
    assert {:ok, 1, _} = Policy.snapshot()
    refute_receive {:reload_prepared_barrier, _, _}, 0
    release(ctx, worker)
    assert %Message{type: :method_return} = reply(ctx.caller, 50)
    assert {:ok, 2, _} = Policy.snapshot()
  end

  test "caller exit drops its reply but the admitted reload still commits", ctx do
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 70)
    worker = prepared(ctx)
    assert {:ok, peer} = NameRegistry.resolve(ctx.name)
    monitor = Process.monitor(peer)
    :ok = :gen_tcp.close(ctx.caller)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}, 1500
    _ = :sys.get_state(ctx.router)
    {replacement, _} = registered(ctx)
    release(ctx, worker)
    assert {:ok, 2, _} = Policy.snapshot()
    assert list(ctx.observer, 71) == [@second]
    send_call(replacement, "Ping", 72, interface: "org.freedesktop.DBus.Peer")
    assert %Message{type: :method_return, reply_serial: 72} = next_message(replacement)
    assert {:error, :timeout} = :gen_tcp.recv(replacement, 0, 0)
  end

  test "synchronous API completion commits through Router without a wire waiter", ctx do
    write_configuration(ctx, @second)
    parent = self()
    start_supervised!({Task, fn -> send(parent, {:sync_reload_result, Policy.reload_file()}) end})
    worker = prepared(ctx)
    assert list(ctx.observer, 80) == [@first]
    refute_receive {:sync_reload_result, _}, 0
    release(ctx, worker)
    assert_receive {:sync_reload_result, {:ok, 2}}, 1500
    assert list(ctx.observer, 81) == [@second]
  end

  @tag deny_reload: true
  test "denied and malformed controls never start preparation", ctx do
    original = Policy.snapshot()
    send_call(ctx.caller, "ReloadConfig", 90)

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.caller, 90)

    send_call(ctx.observer, "ReloadConfig", 91, signature: "s", body: ["invalid"])

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.observer, 91)

    assert Policy.snapshot() == original
    refute_receive {:reload_prepared_barrier, _, _}, 0
  end

  test "authorized malformed control fails before preparation", ctx do
    original = Policy.snapshot()
    send_call(ctx.caller, "ReloadConfig", 95, signature: "s", body: ["invalid"])

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.InvalidArgs"} =
             reply(ctx.caller, 95)

    assert Policy.snapshot() == original
    refute_receive {:reload_prepared_barrier, _, _}, 0
  end

  test "wrong Policy PID, epoch, and job completions leave the admitted reload waiting", ctx do
    original = Policy.snapshot()
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 100)
    worker = prepared(ctx)
    waiter = :sys.get_state(ctx.router).reload_waiter
    {policy, epoch, job} = waiter.handle
    assert is_reference(waiter.route_ack)
    refute policy == self()
    send_call(ctx.caller, "Ping", 101, interface: "org.freedesktop.DBus.Peer")

    for {{policy_pid, completion_epoch, completion_job}, serial} <- [
          {{self(), epoch, job}, 110},
          {{policy, make_ref(), job}, 111},
          {{policy, epoch, make_ref()}, 112}
        ] do
      send(
        ctx.router,
        {:policy_reload_finished, policy_pid, completion_epoch, completion_job, {:ok, 999}}
      )

      assert_pending_reload(ctx, waiter, worker, original, [@first], serial)
    end

    release(ctx, worker)
    assert %Message{type: :method_return, reply_serial: 100} = reply(ctx.caller, 100)
    assert %Message{type: :method_return, reply_serial: 101} = reply(ctx.caller, 101)
    assert {:ok, 2, _} = Policy.snapshot()
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot()
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == []
    assert :sys.get_state(ctx.router).reload_waiter == nil
    assert_route_released(waiter.peer)
    assert list(ctx.observer, 113) == [@second]
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)
  end

  test "a retired completion cannot consume a later reload's waiter or acknowledgement", ctx do
    write_configuration(ctx, @second)
    send_call(ctx.caller, "ReloadConfig", 200)
    first_worker = prepared(ctx)
    first_waiter = :sys.get_state(ctx.router).reload_waiter
    {policy, epoch, retired_job} = first_waiter.handle
    release(ctx, first_worker)
    assert %Message{type: :method_return, reply_serial: 200} = reply(ctx.caller, 200)
    assert {:ok, 2, _} = original = Policy.snapshot()
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot()
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == []
    assert :sys.get_state(ctx.router).reload_waiter == nil
    assert_route_released(first_waiter.peer)

    write_configuration(ctx, @first)
    send_call(ctx.caller, "ReloadConfig", 210)
    worker = prepared(ctx)
    waiter = :sys.get_state(ctx.router).reload_waiter
    assert {^policy, ^epoch, job} = waiter.handle
    refute job == retired_job
    assert is_reference(waiter.route_ack)
    send_call(ctx.caller, "Ping", 211, interface: "org.freedesktop.DBus.Peer")
    send(ctx.router, {:policy_reload_finished, policy, epoch, retired_job, {:ok, 2}})

    assert_pending_reload(ctx, waiter, worker, original, [@second], 220)

    release(ctx, worker)
    assert %Message{type: :method_return, reply_serial: 210} = reply(ctx.caller, 210)
    assert %Message{type: :method_return, reply_serial: 211} = reply(ctx.caller, 211)
    assert {:ok, 3, _} = Policy.snapshot()
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot()
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == []
    assert :sys.get_state(ctx.router).reload_waiter == nil
    assert_route_released(waiter.peer)
    assert list(ctx.observer, 221) == [@first]
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)
  end

  test "FD-bearing reload retires its input while preparation holds the same peer's Ping", ctx do
    original = Policy.snapshot()
    write_configuration(ctx, @second)
    port = reload_fd_actor(ctx.path)
    assert ["ready", actor_pid, name, frame_hex] = reload_fd_event(port)
    assert {:os_pid, os_pid} = Port.info(port, :os_pid)
    assert actor_pid == Integer.to_string(os_pid)
    frame = Base.decode16!(frame_hex, case: :lower)

    assert {:ok,
            %Message{
              type: :method_call,
              serial: 300,
              member: "ReloadConfig",
              signature: "",
              body: [],
              unix_fds: 1
            }, <<>>} = Message.decode_message(frame)

    assert {:ok, peer} = NameRegistry.resolve(name)
    <<prefix::binary-size(16), _rest::binary>> = frame
    assert Port.command(port, "prefix\n")
    assert ["prefix", prefix_hex] = reload_fd_event(port)
    assert Base.decode16!(prefix_hex, case: :lower) == prefix

    {partial, _usage} =
      await_reload_fd_state(peer, fn state, usage ->
        state.buffer == prefix and match?([_handle], state.incoming_fds) and
          usage.peers[peer].frame_bytes == 16 and usage.peers[peer].frame_fds == 1 and
          usage.global.frame_fds == 1 and usage.uids[ctx.uid].frame_fds == 1
      end)

    assert partial.state == :connected
    assert partial.credentials.uid == ctx.uid
    assert partial.auth.unix_fd_negotiated
    assert [handle] = partial.incoming_fds
    assert Resources.info(handle) == {:ok, %{cloexec: true}}
    assert Port.command(port, "finish\n")
    assert ["queued"] = reload_fd_event(port)
    worker = prepared(ctx)

    # This mailbox barrier follows route_owned/5's explicit close and credit release.
    waiter = :sys.get_state(ctx.router).reload_waiter

    assert %{
             peer: ^peer,
             request: %{serial: 300, flags: 0, sender: ^name},
             policy_snapshot: ^original
           } = waiter

    assert is_reference(waiter.route_ack)

    {pending, usage} =
      await_reload_fd_state(peer, fn state, usage ->
        Resources.info(handle) == {:error, :closed} and state.incoming_fds == [] and
          state.route_wait == waiter.route_ack and
          Enum.all?([usage.peers[peer], usage.uids[ctx.uid], usage.global], fn counts ->
            counts.frame_fds == 0 and counts.ingress_fds == 0
          end)
      end)

    assert pending.buffer == <<>>
    assert usage.reload_reservations == 1
    assert usage.global.ingress_messages == 0
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == [worker]
    assert Policy.snapshot() == original
    send_call(ctx.observer, "Ping", 400, interface: "org.freedesktop.DBus.Peer")
    assert %Message{type: :method_return, fds: []} = reply(ctx.observer, 400)
    assert list(ctx.observer, 401) == [@first]
    assert :sys.get_state(ctx.router).reload_waiter == waiter
    assert :sys.get_state(peer).route_wait == waiter.route_ack
    assert Policy.snapshot() == original
    assert Process.whereis(Router) == ctx.router
    assert Port.command(port, "probe\n")
    assert ["retired", "no_early_bytes", "broken_pipe"] = reload_fd_event(port)

    release(ctx, worker)
    assert Port.command(port, "replies\n")
    assert ["reload_reply", reload_serial, ^name, "0"] = reload_fd_event(port)
    assert ["ping_reply", ping_serial, ^name, "0"] = reload_fd_event(port)
    assert String.to_integer(ping_serial) > String.to_integer(reload_serial)
    assert ["complete"] = reload_fd_event(port)
    assert {:ok, 2, _} = Policy.snapshot()
    assert list(ctx.observer, 402) == [@second]
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot()
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == []
    assert :sys.get_state(ctx.router).reload_waiter == nil
    assert_route_released(peer)
    assert Resources.info(handle) == {:error, :closed}
    assert {:ok, ^peer} = NameRegistry.resolve(name)
    assert Port.command(port, "stop\n")
    assert ["stopped"] = reload_fd_event(port)
    assert_receive {^port, {:exit_status, 0}}, 3000
    IO.puts("P09_RELOAD_FD_ACTOR pid=#{actor_pid} exit_status=0")
  end

  defp reload_fd_actor(path) do
    executable =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    fixture = Path.expand("../fixtures/async_reload_fd_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 16_384},
        args: [fixture, path],
        env: [{~c"PYTHONDONTWRITEBYTECODE", ~c"1"}]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    port
  end

  defp reload_fd_event(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    String.split(line)
  end

  defp await_reload_fd_state(
         peer,
         predicate,
         deadline \\ System.monotonic_time(:millisecond) + 1500
       ) do
    state = :sys.get_state(peer, reload_fd_remaining(deadline))
    assert {:ok, usage} = GenServer.call(Limits, :snapshot, reload_fd_remaining(deadline))

    if predicate.(state, usage) do
      {state, usage}
    else
      await_reload_fd_state(peer, predicate, deadline)
    end
  end

  defp reload_fd_remaining(deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "reload descriptor transition did not complete within 1500ms"
    remaining
  end

  defp assert_pending_reload(ctx, waiter, worker, original, names, serial) do
    assert :sys.get_state(ctx.router).reload_waiter == waiter
    assert Policy.snapshot() == original
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    assert Task.Supervisor.children(GaoBus.Policy.ReloadSupervisor) == [worker]
    assert :sys.get_state(waiter.peer).route_wait == waiter.route_ack
    assert list(ctx.observer, serial) == names
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller, 0, 0)
  end

  defp assert_route_released(peer) do
    assert_route_released(peer, System.monotonic_time(:millisecond) + 1500)
  end

  defp assert_route_released(peer, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "peer route acknowledgement did not retire within 1500ms"

    case :sys.get_state(peer, remaining).route_wait do
      nil -> :ok
      _token -> assert_route_released(peer, deadline)
    end
  end

  defp prepared(%{gate: gate}) do
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 1500
    worker
  end

  defp release(%{gate: gate}, worker) do
    monitor = Process.monitor(worker)
    send(worker, {:release_reload, gate})
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 1500
    _ = :sys.get_state(Policy)
    _ = :sys.get_state(Router)
  end

  defp write_configuration(ctx, name, deny_reload \\ false, deny_receive \\ false) do
    for file <- File.ls!(ctx.services), do: File.rm!(Path.join(ctx.services, file))

    File.write!(
      Path.join(ctx.services, name <> ".service"),
      "[D-BUS Service]\nName=#{name}\nExec=/bin/false\nUser=fixture\n"
    )

    denial =
      if deny_reload,
        do:
          "<deny send_destination=\"#{@bus}\" send_interface=\"#{@bus}\" send_member=\"ReloadConfig\"/>",
        else: ""

    receive_denial =
      if deny_receive,
        do: "<deny receive_type=\"method_return\" receive_requested_reply=\"true\"/>",
        else: ""

    File.write!(ctx.config, """
    <busconfig><type>system</type><servicedir>#{ctx.services}</servicedir>
    <policy context="default"><allow user="#{ctx.uid}"/>
    <allow send_destination="#{@bus}"/><allow receive_sender="#{@bus}"/>
    #{denial}#{receive_denial}</policy></busconfig>
    """)
  end

  defp registered(ctx) do
    {:ok, socket} = :gen_tcp.connect({:local, ctx.path}, 0, [:binary, active: false], 1000)
    on_exit(fn -> :gen_tcp.close(socket) end)

    :ok =
      :gen_tcp.send(
        socket,
        <<0>> <> "AUTH EXTERNAL " <> Base.encode16(to_string(ctx.uid)) <> "\r\n"
      )

    assert {:ok, "OK " <> _} = :gen_tcp.recv(socket, 0, 1500)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    send_call(socket, "Hello", 1)
    assert %Message{type: :method_return, body: [name]} = reply(socket, 1)
    send_call(socket, "GetId", 2)
    assert %Message{type: :method_return} = reply(socket, 2)
    {socket, name}
  end

  defp send_call(socket, member, serial, options \\ []) do
    message =
      Message.method_call("/org/freedesktop/DBus", Keyword.get(options, :interface, @bus), member,
        destination: @bus,
        serial: serial,
        flags: Keyword.get(options, :flags, 0),
        signature: Keyword.get(options, :signature, ""),
        body: Keyword.get(options, :body, [])
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(message))
  end

  defp list(socket, serial) do
    send_call(socket, "ListActivatableNames", serial)
    assert %Message{type: :method_return, body: [names]} = reply(socket, serial)
    names
  end

  defp reply(socket, serial) do
    case next_message(socket) do
      %Message{type: :signal} -> reply(socket, serial)
      %Message{reply_serial: ^serial} = message -> message
      message -> flunk("unexpected reply while awaiting #{serial}: #{inspect(message)}")
    end
  end

  defp next_message(socket) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    assert {:ok, tail} = :gen_tcp.recv(socket, header + rem(8 - rem(header, 8), 8) + body, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    message
  end
end
