defmodule GaoBus.PeerControlTruncationTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, Router}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-ctrunc-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    uid = GaoBus.Unix.Native.identity().uid

    settings = [
      socket_path: Path.join(directory, "bus"),
      profile: :system,
      cluster: false,
      policy_rules:
        Enum.map(
          [:connect, :own, :send, :receive],
          &%{action: &1, effect: :allow, match: %{uid: uid}}
        )
    ]

    previous = Enum.map(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(settings, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, setting} -> Application.put_env(:gao_bus, key, setting)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    start_supervised!(%{id: :truncation_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    assert {:ok, observer} =
             :gen_tcp.connect(
               {:local, settings[:socket_path]},
               0,
               [:binary, active: false, packet: :line],
               1000
             )

    on_exit(fn -> :gen_tcp.close(observer) end)
    identity = Base.encode16(Integer.to_string(uid))
    :ok = :gen_tcp.send(observer, <<0>> <> "AUTH EXTERNAL #{identity}\r\n")
    assert {:ok, "OK " <> _} = :gen_tcp.recv(observer, 0, 1000)
    :ok = :inet.setopts(observer, packet: :raw)
    :ok = :gen_tcp.send(observer, "BEGIN\r\n")
    assert %Message{body: [name]} = query(observer, "Hello", 1)
    assert {:ok, observer_peer} = NameRegistry.resolve(name)
    owned = "org.foundation.TruncationObserver"
    assert %Message{body: [1]} = query(observer, "RequestName", 2, "su", [owned, 0])
    assert %Message{body: [id]} = query(observer, "GetId", 3)

    %{
      path: settings[:socket_path],
      observer: observer,
      observer_peer: observer_peer,
      name: name,
      owned: owned,
      id: id
    }
  end

  for mode <- ~w(excess credentials pending) do
    @mode mode
    test "FD-04 registered-Peer real ancillary truncation: #{mode}", ctx do
      executable =
        System.find_executable("python3") || flunk("required independent actor missing")

      actor = Path.expand("fixtures/peer_control_truncation_actor.py", __DIR__)

      port =
        Port.open({:spawn_executable, executable}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          {:line, 16_384},
          args: [actor, ctx.path, @mode, System.pid()],
          env: [{~c"PYTHONDONTWRITEBYTECODE", ~c"1"}]
        ])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)
      assert %{"event" => "warm", "target" => target} = actor_reply(port)
      assert {:ok, target_peer} = NameRegistry.resolve(target)
      await(fn -> quiet?() end)
      before = authority()
      Port.command(port, "snapshot\n")
      assert %{"event" => "baseline", "fds" => baseline_fds} = actor_reply(port)
      Port.command(port, "register\n")
      assert %{"event" => "registered", "source" => source, "owned" => owned} = actor_reply(port)
      assert {:ok, offender} = NameRegistry.resolve(source)
      assert {:ok, ^offender} = NameRegistry.resolve(owned)
      assert %{state: :connected, frame_options: %{max_fds: 16}} = :sys.get_state(offender)
      assert GaoBus.MatchRules.has_rules?(offender)
      monitor = Process.monitor(offender)

      if @mode == "excess" do
        Port.command(port, "positive\n")
        assert %{"event" => "positive", "delivered" => 16, "reclaimed" => 16} = actor_reply(port)
      end

      if @mode == "pending" do
        Port.command(port, "fragment\n")
        assert %{"event" => "fragment", "pipe" => pipe} = actor_reply(port)
        assert "pipe:[" <> _ = pipe

        await(fn ->
          state = :sys.get_state(offender)
          {:ok, accounting} = Limits.snapshot()

          byte_size(state.buffer) == 8 and length(state.incoming_fds) == 1 and
            accounting.peers[offender].frame_fds == 1
        end)

        Port.command(port, "retained\n")
        assert %{"event" => "retained", "fds" => retained_fds} = actor_reply(port)
        assert Enum.count(retained_fds, fn {_fd, identity} -> identity == pipe end) == 1
      end

      if @mode in ["credentials", "pending"] do
        # A real accepted socket option, after EXTERNAL/negotiation/Hello.
        # Credentials and rights exceed the captured rights-only control buffer.
        socket = :sys.get_state(offender).socket
        assert :ok = :socket.setopt_native(socket, {:socket, 16}, <<1::native-32>>)
      end

      router = Process.whereis(Router)
      assert 1 = :erlang.trace(router, true, [:receive])

      on_exit(fn ->
        if Process.whereis(Router) == router, do: :erlang.trace(router, false, [:receive])
      end)

      Port.command(port, "truncate\n")
      assert_receive {:DOWN, ^monitor, :process, ^offender, :normal}, 1500

      assert %{"event" => "closed", "reclaimed" => reclaimed, "terminal" => terminal} =
               actor_reply(port)

      assert terminal in ["eof", "econnreset"]

      assert reclaimed ==
               if(@mode == "excess", do: 33, else: if(@mode == "pending", do: 18, else: 16))

      await(fn -> authority() == before end)
      refute GaoBus.MatchRules.has_rules?(offender)
      assert {:error, :name_not_found} = NameRegistry.resolve(source)
      assert {:error, :name_not_found} = NameRegistry.resolve(owned)
      assert {:ok, ^target_peer} = NameRegistry.resolve(target)
      assert {:ok, observer_peer} = NameRegistry.resolve(ctx.name)
      assert observer_peer == ctx.observer_peer
      assert {:ok, ^observer_peer} = NameRegistry.resolve(ctx.owned)
      assert %Message{body: [id]} = query(ctx.observer, "GetId", 4)
      assert id == ctx.id
      await(fn -> authority() == before end)
      delivered = :erlang.trace_delivered(router)
      assert_receive {:trace_delivered, ^router, ^delivered}, 1000

      refute_receive {:trace, ^router, :receive,
                      {:owned_route, _message, ^offender, _token, _bytes, :frame}},
                     0

      assert 1 = :erlang.trace(router, false, [:receive])
      Port.command(port, "final\n")
      assert %{"event" => "final", "fds" => final_fds} = actor_reply(port)
      assert final_fds == baseline_fds
      Port.command(port, "stop\n")
      assert %{"event" => "result", "result" => "PASS", "scenario" => @mode} = actor_reply(port)
      assert_receive {^port, {:exit_status, 0}}, 1500

      IO.puts(
        "FD04_EVIDENCE " <>
          Jason.encode!(%{
            scenario: @mode,
            max_fds: 16,
            reclaimed: reclaimed,
            terminal: terminal,
            baseline_fds: baseline_fds,
            final_fds: final_fds,
            core: Enum.map(before.core, &inspect/1),
            names: before.names,
            global: before.accounting.global,
            reservations: before.accounting.reservations,
            observer_name: ctx.name,
            observer_owned: ctx.owned,
            bus_id: ctx.id,
            no_authority_dispatch: true
          })
      )
    end
  end

  defp authority do
    {:ok, accounting} = Limits.snapshot()

    %{
      core: Enum.map([Router, NameRegistry, Limits, GaoBus.Policy], &Process.whereis/1),
      peers: :sys.get_state(Router).peers,
      names: Enum.sort(NameRegistry.list_names()),
      accounting: accounting
    }
  end

  defp quiet? do
    {:ok, accounting} = Limits.snapshot()

    accounting.reservations == 0 and accounting.global.frame_fds == 0 and
      accounting.global.frame_bytes == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "registered-Peer cleanup deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    Jason.decode!(line)
  end

  defp query(socket, member, serial, signature \\ "", body \\ []) do
    request =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial,
        signature: signature,
        body: body
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(request))
    reply(socket, serial, System.monotonic_time(:millisecond) + 1000)
  end

  defp reply(socket, serial, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    assert remaining > 0
    assert {:ok, header} = :gen_tcp.recv(socket, 16, remaining)
    <<?l, _::binary-size(3), bytes::little-32, _::little-32, fields::little-32>> = header

    assert {:ok, rest} =
             :gen_tcp.recv(socket, fields + rem(8 - rem(fields, 8), 8) + bytes, remaining)

    assert {:ok, message, <<>>} = Message.decode_message(header <> rest)
    if message.reply_serial == serial, do: message, else: reply(socket, serial, deadline)
  end
end
