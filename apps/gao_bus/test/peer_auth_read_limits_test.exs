defmodule GaoBus.PeerAuthReadLimitsTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @line_limit 64
  @auth_limit 160

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    handshake =
      <<0>> <>
        "AUTH EXTERNAL " <>
        Base.encode16(Integer.to_string(uid), case: :lower) <>
        "\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n"

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-auth-limits-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)

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
    path = Path.join(directory, "bus")

    start_supervised!(
      {GaoBus.Listener,
       socket_path: path,
       socket_mode: 0o600,
       peer_options: [
         auth_limits: [
           max_line_bytes: @line_limit,
           max_auth_bytes: @auth_limit,
           max_lines_per_turn: 1
         ]
       ]}
    )

    %{path: path, handshake: handshake}
  end

  for mode <- [
        "line_complete_n",
        "line_complete_n_plus_one",
        "line_incomplete_n_plus_one",
        "cumulative_n",
        "cumulative_n_plus_one"
      ] do
    @mode mode
    test "real Peer auth byte limit: #{mode}", ctx do
      plan = plan(@mode, ctx.handshake)

      python =
        System.find_executable("python3") || flunk("required independent Python actor missing")

      fixture = Path.expand("fixtures/peer_auth_read_limits_actor.py", __DIR__)

      port =
        Port.open({:spawn_executable, python}, [
          :binary,
          :exit_status,
          {:line, 65_536},
          args: ["-B", fixture, ctx.path, @mode, System.pid()]
        ])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)

      assert %{
               "event" => "ready",
               "mode" => @mode,
               "target" => target_name,
               "healthy" => healthy_name,
               "owned" => owned,
               "handshake" => handshake_hex,
               "steps" => step_hexes,
               "finish" => finish_hex
             } = actor_reply(port)

      assert Base.decode16!(handshake_hex, case: :lower) == ctx.handshake
      assert Enum.map(step_hexes, &Base.decode16!(&1, case: :lower)) == plan.steps
      assert Base.decode16!(finish_hex, case: :lower) == plan.finish
      assert {:ok, target} = NameRegistry.resolve(target_name)
      assert {:ok, healthy} = NameRegistry.resolve(healthy_name)
      assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      await(fn -> quiet?() end)
      before = authority()
      Port.command(port, "baseline\n")
      assert %{"event" => "baseline", "fds" => baseline_fds} = actor_reply(port)
      Port.command(port, "next\n")
      assert %{"event" => "opened"} = actor_reply(port)
      await(fn -> length(children()) == 3 end)
      [source] = children() -- [target, healthy]
      monitor = Process.monitor(source)

      for {{chunk, expected}, index} <- Enum.with_index(Enum.zip(plan.steps, plan.states)) do
        Port.command(port, "step\n")

        assert %{"event" => "step", "index" => ^index, "bytes" => sent_hex, "healthy" => true} =
                 actor_reply(port)

        assert Base.decode16!(sent_hex, case: :lower) == chunk
        await(fn -> auth_state?(source, expected) end)
        assert GaoBus.Peer.get_unique_name(source) == nil
        assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      end

      Port.command(port, "finish\n")

      if @mode == "line_complete_n" do
        assert %{"event" => "line_accepted", "reply" => "REJECTED EXTERNAL\r\n"} =
                 actor_reply(port)

        await(fn -> auth_state?(source, {:auth, 65, <<>>, false}) end)
        assert GaoBus.Peer.get_unique_name(source) == nil
        Port.command(port, "register\n")
      end

      if plan.accepted do
        assert %{"event" => "registered", "source" => source_name, "binary_lf" => true} =
                 actor_reply(port)

        assert {:ok, ^source} = NameRegistry.resolve(source_name)
        state = :sys.get_state(source)
        assert state.auth.phase == :connected
        assert state.auth.total_bytes == plan.total
        assert state.auth.buffer == <<>>
        assert state.auth.unix_fd_negotiated
        Port.command(port, "close\n")
        assert %{"event" => "done", "accepted" => true} = actor_reply(port)
      else
        assert %{"event" => "done", "accepted" => false, "terminal" => terminal} =
                 actor_reply(port)

        assert terminal in ["eof", "econnreset"]
      end

      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, 1500
      await(fn -> authority() == before end)
      Port.command(port, "settled\n")

      assert %{"event" => "settled", "healthy" => true, "fds" => ^baseline_fds} =
               actor_reply(port)

      await(fn -> authority() == before end)
      assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      monitors = Enum.map([target, healthy], &{&1, Process.monitor(&1)})
      Port.command(port, "stop\n")
      assert %{"event" => "result", "mode" => @mode, "result" => "PASS"} = actor_reply(port)
      assert_receive {^port, {:exit_status, 0}}, 3000

      for {peer, ref} <- monitors,
          do: assert_receive({:DOWN, ^ref, :process, ^peer, :normal}, 1500)

      await(fn -> children() == [] and :sys.get_state(Router).peers == %{} and quiet?() end)
      assert NameRegistry.list_names() == ["org.freedesktop.DBus"]
      assert {:ok, %{global: %{connections: 0}, reservations: 0}} = Limits.snapshot()
    end
  end

  defp plan("line_complete_n", handshake) do
    body = binary_part(error_line(@line_limit), 0, @line_limit - 2)

    %{
      steps: [<<0>> <> body],
      states: [{:auth, 1, body, false}],
      finish: "\r\n",
      accepted: true,
      total: @line_limit + byte_size(handshake)
    }
  end

  defp plan("line_complete_n_plus_one", _handshake) do
    body = binary_part(error_line(@line_limit + 1), 0, @line_limit - 1)

    %{
      steps: [<<0>> <> body, "\r"],
      states: [{:auth, 1, body, false}, {:auth, 1, body <> "\r", false}],
      finish: "\n",
      accepted: false
    }
  end

  defp plan("line_incomplete_n_plus_one", _handshake) do
    body = binary_part(error_line(@line_limit + 2), 0, @line_limit)

    %{
      steps: [<<0>> <> body],
      states: [{:auth, 1, body, false}],
      finish: "x",
      accepted: false
    }
  end

  defp plan(mode, handshake) when mode in ["cumulative_n", "cumulative_n_plus_one"] do
    total = if mode == "cumulative_n", do: @auth_limit, else: @auth_limit + 1
    filler = total - byte_size(handshake)

    full =
      <<0>> <>
        error_line(@line_limit) <>
        error_line(filler - @line_limit) <>
        binary_part(handshake, 1, byte_size(handshake) - 1)

    assert byte_size(full) == total

    %{
      steps: [binary_part(full, 0, total - 2), "\r"],
      states: [
        {:authenticated, total - 7, "BEGIN", true},
        {:authenticated, total - 7, "BEGIN\r", true}
      ],
      finish: "\n",
      accepted: mode == "cumulative_n",
      total: total
    }
  end

  defp error_line(size) do
    assert size >= 8
    "ERROR " <> String.duplicate("x", size - 8) <> "\r\n"
  end

  defp auth_state?(source, {phase, total, buffer, negotiated}) do
    state = :sys.get_state(source)

    state.auth != nil and state.auth.phase == phase and state.auth.total_bytes == total and
      state.auth.buffer == buffer and state.auth.unix_fd_negotiated == negotiated
  end

  defp children, do: Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))

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
      assert System.monotonic_time(:millisecond) < deadline, "Peer auth-limit state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end
end
