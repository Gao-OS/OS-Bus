defmodule GaoBus.PeerFdSplitBoundariesTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, Router}
  alias GaoBus.Unix.Resources

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-fd02-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    uid = GaoBus.Unix.Native.identity().uid

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
    start_supervised!({GaoBus.PeerSupervisor, max_children: 8})
    path = Path.join(directory, "bus")

    start_supervised!(
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600, peer_options: [auth_limits: []]}
    )

    %{path: path}
  end

  @tag timeout: 60_000
  test "FD-02 every internal frame split retains and delivers its own usable descriptor bundle",
       ctx do
    executable =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    fixture = Path.expand("fixtures/peer_fd_split_boundaries_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 16_384},
        args: [fixture, ctx.path, System.pid()],
        env: [{~c"PYTHONDONTWRITEBYTECODE", ~c"1"}]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "source" => source_name,
             "target" => target_name,
             "healthy" => healthy_name,
             "owned" => owned,
             "frame" => hex,
             "frame_bytes" => size,
             "splits" => splits,
             "modes" => modes
           } = ready = actor_reply(port)

    IO.puts("FD02_INPUT " <> Jason.encode!(ready))

    assert size < 256
    assert splits == Enum.to_list(1..(size - 1))
    assert modes == ["rights_with_prefix", "rights_at_split"]
    frame = Base.decode16!(hex, case: :lower)
    assert byte_size(frame) == size

    assert {:ok, %Message{signature: "hh", body: [1, 0], unix_fds: 2}, <<>>} =
             Message.decode_message(frame)

    assert {:ok, source} = NameRegistry.resolve(source_name)
    assert {:ok, target} = NameRegistry.resolve(target_name)
    assert {:ok, healthy} = NameRegistry.resolve(healthy_name)
    assert {:ok, ^healthy} = NameRegistry.resolve(owned)
    peers = [source, target, healthy]
    monitors = Enum.map(peers, &{&1, Process.monitor(&1)})
    await(fn -> quiet?() end)
    before = authority()
    Port.command(port, "baseline\n")
    assert %{"event" => "baseline", "fds" => baseline_fds} = actor_reply(port)

    for mode <- modes, split <- splits do
      Port.command(port, "next\n")

      assert %{
               "event" => "partial",
               "mode" => ^mode,
               "split" => ^split,
               "prefix" => prefix_hex,
               "identities" => identities
             } = actor_reply(port)

      prefix = Base.decode16!(prefix_hex, case: :lower)
      assert byte_size(prefix) == split
      assert {:error, :insufficient_data} = Message.decode_message(prefix)

      await(fn ->
        state = :sys.get_state(source)
        {:ok, accounting} = Limits.snapshot()

        state.buffer == prefix and length(state.incoming_fds) == 2 and
          accounting.peers[source].frame_fds == 2 and
          accounting.peers[source].frame_bytes == split
      end)

      pending = :sys.get_state(source)
      assert pending.state == :connected
      assert [first_handle, second_handle] = pending.incoming_fds
      handles = [first_handle, second_handle]
      for handle <- handles, do: assert(Resources.info(handle) == {:ok, %{cloexec: true}})
      assert :sys.get_state(target).current_output == nil
      Port.command(port, "retained\n")
      assert %{"event" => "retained", "fds" => retained_fds} = actor_reply(port)
      assert map_size(retained_fds) == map_size(baseline_fds) + 2
      assert [first_identity, second_identity] = identities
      refute first_identity == second_identity

      for identity <- identities,
          do: assert(Enum.count(retained_fds, fn {_fd, value} -> value == identity end) == 1)

      Port.command(port, "finish\n")

      assert %{
               "event" => "delivered",
               "mode" => ^mode,
               "split" => ^split,
               "receipts" => [first, second, tail],
               "reclaimed" => 4,
               "healthy" => true
             } = actor_reply(port)

      assert first["identities"] == identities
      assert [_, _] = second["identities"]
      assert tail["identities"] == []
      assert tail["payloads"] == []
      await(fn -> authority() == before end)
      assert :sys.get_state(source).incoming_fds == []
      assert :sys.get_state(source).buffer == <<>>
      for handle <- handles, do: assert(Resources.info(handle) == {:error, :closed})
      assert {:ok, ^source} = NameRegistry.resolve(source_name)
      assert {:ok, ^target} = NameRegistry.resolve(target_name)
      assert {:ok, ^healthy} = NameRegistry.resolve(healthy_name)
      assert {:ok, ^healthy} = NameRegistry.resolve(owned)
      Port.command(port, "snapshot\n")

      assert %{"event" => "quiescent", "mode" => ^mode, "split" => ^split, "fds" => ^baseline_fds} =
               actor_reply(port)

      IO.puts(
        "FD02_SPLIT_EVIDENCE " <>
          Jason.encode!(%{
            mode: mode,
            split: split,
            frame_bytes: size,
            retained: identities,
            delivered: [first, second, tail],
            reclaimed: 4,
            authority_unchanged: true,
            daemon_fds_restored: true
          })
      )
    end

    cases = 2 * (size - 1)
    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => ^cases,
             "fd_frames" => fd_frames,
             "usable_resources" => resources,
             "non_fd_tails" => ^cases,
             "negative_controls" => 3,
             "baseline_fds" => ^baseline_fds,
             "final_fds" => ^baseline_fds
           } = result = actor_reply(port)

    assert fd_frames == 2 * cases
    assert resources == 4 * cases
    assert_receive {^port, {:exit_status, 0}}, 3000

    for {peer, monitor} <- monitors,
        do: assert_receive({:DOWN, ^monitor, :process, ^peer, :normal}, 1500)

    await(fn ->
      {:ok, accounting} = Limits.snapshot()

      accounting.global.connections == 0 and accounting.reservations == 0 and
        :sys.get_state(Router).peers == %{} and
        NameRegistry.list_names() == ["org.freedesktop.DBus"]
    end)

    IO.puts("FD02_SUMMARY " <> Jason.encode!(result))
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
    {:ok, state} = Limits.snapshot()

    state.reservations == 0 and state.global.frame_fds == 0 and state.global.frame_bytes == 0 and
      state.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "FD-02 state transition deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    Jason.decode!(line)
  end
end
