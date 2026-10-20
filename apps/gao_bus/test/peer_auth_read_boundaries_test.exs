defmodule GaoBus.PeerAuthReadBoundariesTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}
  alias GaoBus.Unix.Resources

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    auth =
      <<0>> <> "AUTH EXTERNAL " <> Base.encode16(Integer.to_string(uid), case: :lower) <> "\r\n"

    handshake = auth <> "NEGOTIATE_UNIX_FD\r\nBEGIN\r\n"

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-auth-read-#{System.pid()}-#{System.unique_integer([:positive])}"
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
       peer_options: [auth_limits: [max_auth_bytes: byte_size(handshake), max_lines_per_turn: 1]]}
    )

    %{path: path, auth: auth, handshake: handshake}
  end

  for mode <- ~w(splits auth_rights first_frame) do
    @mode mode
    test "real Peer auth read boundary: #{mode}", ctx do
      python =
        System.find_executable("python3") || flunk("required independent Python actor missing")

      fixture = Path.expand("fixtures/peer_auth_read_boundaries_actor.py", __DIR__)

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
               "target" => target_name,
               "healthy" => healthy_name,
               "owned" => owned,
               "handshake" => hex,
               "cuts" => cuts,
               "mode" => @mode
             } = actor_reply(port)

      assert Base.decode16!(hex, case: :lower) == ctx.handshake
      assert cuts == cuts(@mode, ctx)
      assert {:ok, target} = NameRegistry.resolve(target_name)
      assert {:ok, healthy} = NameRegistry.resolve(healthy_name)
      assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      await(fn -> quiet?() end)
      before = authority()
      Port.command(port, "baseline\n")
      assert %{"event" => "baseline", "fds" => baseline_fds} = actor_reply(port)

      for {cut, index} <- Enum.with_index(cuts) do
        Port.command(port, "next\n")
        prefix = binary_part(ctx.handshake, 0, cut)

        assert %{"event" => "opened", "index" => ^index, "cut" => ^cut, "prefix" => prefix_hex} =
                 actor_reply(port)

        assert Base.decode16!(prefix_hex, case: :lower) == prefix
        await(fn -> length(children()) == 3 end)
        [source] = children() -- [target, healthy]
        monitor = Process.monitor(source)
        Port.command(port, "prefix\n")
        assert %{"event" => "partial", "fds" => partial_fds} = actor_reply(port)
        await(fn -> prefix_processed?(:sys.get_state(source), prefix, ctx) end)
        assert GaoBus.Peer.get_unique_name(source) == nil
        Port.command(port, "finish\n")

        handles =
          if @mode == "first_frame" do
            assert %{
                     "event" => "first_frame",
                     "prefix" => frame_hex,
                     "frame" => full_hex,
                     "pipe" => pipe
                   } = actor_reply(port)

            frame_prefix = Base.decode16!(frame_hex, case: :lower)
            full = Base.decode16!(full_hex, case: :lower)
            assert byte_size(frame_prefix) == 16

            assert {:ok, %Message{member: "Hello", signature: "", body: [], unix_fds: 1}, <<>>} =
                     Message.decode_message(full)

            await(fn ->
              state = :sys.get_state(source)
              {:ok, accounting} = Limits.snapshot()

              state.state == :awaiting_hello and state.buffer == frame_prefix and
                length(state.incoming_fds) == 1 and accounting.peers[source].frame_fds == 1 and
                accounting.peers[source].frame_bytes == 16
            end)

            assert [handle] = retained = :sys.get_state(source).incoming_fds
            assert {:ok, %{cloexec: true}} = Resources.info(handle)
            Port.command(port, "retained\n")

            assert %{"event" => "retained", "fds" => retained_fds, "pipe" => ^pipe} =
                     actor_reply(port)

            assert map_size(retained_fds) == map_size(partial_fds) + 1
            assert Enum.count(retained_fds, fn {_fd, identity} -> identity == pipe end) == 1
            Port.command(port, "complete\n")
            retained
          else
            []
          end

        if @mode != "auth_rights" do
          assert %{
                   "event" => "registered",
                   "source" => source_name,
                   "binary_lf" => true,
                   "usable_fd" => usable
                 } = actor_reply(port)

          assert usable == (@mode == "first_frame")
          assert {:ok, ^source} = NameRegistry.resolve(source_name)
          state = :sys.get_state(source)
          assert state.auth.total_bytes == byte_size(ctx.handshake)
          assert state.auth.buffer == <<>>
          Port.command(port, "close\n")
        end

        assert %{"event" => "done", "index" => ^index, "rights" => reclaimed} =
                 done = actor_reply(port)

        assert reclaimed ==
                 if(@mode == "auth_rights",
                   do: 1,
                   else: if(@mode == "first_frame", do: 2, else: 0)
                 )

        if @mode == "auth_rights", do: assert(done["terminal"] in ["eof", "econnreset"])
        assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, 1500
        await(fn -> authority() == before end)
        for handle <- handles, do: assert(Resources.info(handle) == {:error, :closed})
        Port.command(port, "settled\n")

        assert %{
                 "event" => "settled",
                 "index" => ^index,
                 "healthy" => true,
                 "reclaimed" => ^reclaimed,
                 "fds" => ^baseline_fds
               } = actor_reply(port)

        await(fn -> authority() == before end)
        assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      end

      monitors = Enum.map([target, healthy], &{&1, Process.monitor(&1)})
      Port.command(port, "stop\n")
      count = length(cuts)

      assert %{"event" => "result", "mode" => @mode, "cases" => ^count, "result" => "PASS"} =
               actor_reply(port)

      assert_receive {^port, {:exit_status, 0}}, 3000

      for {peer, ref} <- monitors,
          do: assert_receive({:DOWN, ^ref, :process, ^peer, :normal}, 1500)

      await(fn -> children() == [] and :sys.get_state(Router).peers == %{} and quiet?() end)
      assert NameRegistry.list_names() == ["org.freedesktop.DBus"]
      assert {:ok, %{global: %{connections: 0}, reservations: 0}} = Limits.snapshot()
    end
  end

  defp cuts("splits", ctx),
    do: [
      0,
      1,
      2,
      byte_size(ctx.auth),
      byte_size(ctx.handshake) - 2,
      byte_size(ctx.handshake) - 1,
      byte_size(ctx.handshake)
    ]

  defp cuts("auth_rights", ctx),
    do: [
      0,
      1,
      byte_size(ctx.auth) - 2,
      byte_size(ctx.auth) - 1,
      byte_size(ctx.handshake) - 2,
      byte_size(ctx.handshake) - 1
    ]

  defp cuts("first_frame", ctx), do: [byte_size(ctx.handshake) - 7]

  defp prefix_processed?(%{auth: nil}, _prefix, _ctx), do: false

  defp prefix_processed?(state, prefix, ctx) do
    cut = byte_size(prefix)

    cond do
      cut == 0 ->
        state.auth.phase == :initial

      cut < byte_size(ctx.auth) ->
        state.auth.phase == :auth and state.auth.buffer == binary_part(prefix, 1, cut - 1)

      cut == byte_size(ctx.handshake) ->
        state.state == :awaiting_hello

      true ->
        rest =
          if cut == byte_size(ctx.auth),
            do: <<>>,
            else:
              binary_part(
                prefix,
                byte_size(ctx.handshake) - 7,
                cut - byte_size(ctx.handshake) + 7
              )

        negotiated = cut >= byte_size(ctx.handshake) - 7

        state.auth.phase == :authenticated and state.auth.buffer == rest and
          state.auth.unix_fd_negotiated == negotiated
    end
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
      assert System.monotonic_time(:millisecond) < deadline, "Peer auth-boundary state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end
end
