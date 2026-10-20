defmodule GaoBus.EgressOwnershipTest do
  use ExUnit.Case, async: false

  alias GaoBus.Limits
  alias GaoBus.Unix.{Native, Resources}

  @moduletag :tmp_dir

  setup context do
    directory = Path.join(System.tmp_dir!(), "gb-egress-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "socket")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)
    source = Path.expand("fixtures/resource_actor.py", __DIR__)
    mode = Map.get(context, :actor_mode, "discard")
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")

    actor =
      Port.open(
        {:spawn_executable, executable},
        [:binary, :exit_status, args: [source, path, mode]]
      )

    {:ok, socket} = :socket.accept(listener, 5000)
    assert {:ok, _} = :socket.recv(socket, 1, [:peek], 5000)
    assert {:ok, "resources", [_, _, _] = originals} = Resources.recv(socket, 1024)
    limits = start_supervised!({Limits, name: nil})

    on_exit(fn ->
      Resources.close(originals)
      :socket.close(socket)
      :socket.close(listener)
      if Port.info(actor), do: Port.close(actor)
      File.rm_rf!(directory)
    end)

    %{limits: limits, originals: originals, socket: socket, actor: actor}
  end

  test "target death before binding leaves copies with caller and retired credit", ctx do
    peer = recipient(ctx.limits)
    assert {:ok, token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, copies} = Resources.duplicate(ctx.originals)
    kill_and_await(ctx.limits, peer)
    assert {:error, :unknown_reservation} = Limits.bind_egress(token, copies, ctx.limits)
    assert_open(copies)
    assert :ok = Resources.close(copies)
    assert_closed(copies)
    assert %{egress_fds: 0, egress_messages: 0} = snapshot(ctx.limits).global
    finish_actor(ctx)
  end

  test "target death after binding closes handles still retained by caller", ctx do
    peer = recipient(ctx.limits)
    assert {:ok, token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, copies} = Resources.duplicate(ctx.originals)
    assert :ok = Limits.bind_egress(token, copies, ctx.limits)
    kill_and_await(ctx.limits, peer)
    assert_closed(copies)
    assert_open(ctx.originals)
    assert %{egress_fds: 0, egress_messages: 0} = snapshot(ctx.limits).global
    assert {:error, :unknown_reservation} = Limits.release(token, ctx.limits)
    finish_actor(ctx)
  end

  @tag actor_mode: "roundtrip"
  test "release closes one delivery while another transfers actual fanout resources", ctx do
    peer = recipient(ctx.limits)
    assert {:ok, first_token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, second_token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, first} = Resources.duplicate(ctx.originals)
    assert {:ok, second} = Resources.duplicate(ctx.originals)
    assert :ok = Limits.bind_egress(first_token, first, ctx.limits)
    assert :ok = Limits.bind_egress(second_token, second, ctx.limits)
    assert :ok = Resources.close(ctx.originals)
    assert :ok = Limits.release(first_token, ctx.limits)
    assert_closed(first)
    assert_open(second)
    assert %{egress_fds: 3, egress_messages: 1} = snapshot(ctx.limits).global
    assert {:ok, 8} = Resources.send(ctx.socket, "returned", second)
    assert :ok = Limits.release(second_token, ctx.limits)
    assert_closed(second)
    finish_actor(ctx, false)
  end

  test "a token can bind exactly once without taking rejected caller copies", ctx do
    peer = recipient(ctx.limits)
    assert {:ok, token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, copies} = Resources.duplicate(ctx.originals)
    assert {:ok, rejected} = Resources.duplicate(ctx.originals)
    assert :ok = Limits.bind_egress(token, copies, ctx.limits)
    before = snapshot(ctx.limits)
    assert {:error, :already_bound} = Limits.bind_egress(token, rejected, ctx.limits)
    assert snapshot(ctx.limits) == before
    assert_open(rejected)
    assert :ok = Resources.close(rejected)
    assert :ok = Limits.release(token, ctx.limits)
    assert_closed(copies)
    finish_actor(ctx)
  end

  test "invalid binding never mutates accounting or shares delivery handles", ctx do
    peer = recipient(ctx.limits)
    assert {:ok, token} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, other} = Limits.reserve_egress(peer, 8, 3, ctx.limits)
    assert {:ok, ingress} = Limits.reserve_ingress(peer, 8, ctx.limits)
    assert {:ok, copies} = Resources.duplicate(ctx.originals)
    before = snapshot(ctx.limits)
    assert {:error, :invalid_handles} = Limits.bind_egress(token, [], ctx.limits)
    assert {:error, :invalid_handles} = Limits.bind_egress(token, [1, 2, 3], ctx.limits)
    assert {:error, :not_egress_reservation} = Limits.bind_egress(ingress, copies, ctx.limits)
    assert snapshot(ctx.limits) == before
    assert :ok = Limits.bind_egress(token, copies, ctx.limits)
    assert {:error, :shared_handles} = Limits.bind_egress(other, copies, ctx.limits)
    assert_open(copies)
    assert :ok = Limits.release(token, ctx.limits)
    assert :ok = Limits.release(other, ctx.limits)
    assert :ok = Limits.release(ingress, ctx.limits)
    finish_actor(ctx)
  end

  defp recipient(limits) do
    peer = start_supervised!({Task, fn -> receive do: (:stop -> :ok) end}, id: make_ref())
    assert :ok = Limits.acquire(peer, Native.identity(), limits)
    peer
  end

  defp kill_and_await(limits, peer) do
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}, 5000
    await_removed(limits, peer, System.monotonic_time(:millisecond) + 1500)
  end

  defp await_removed(limits, peer, deadline) do
    if Map.has_key?(snapshot(limits).peers, peer) do
      assert System.monotonic_time(:millisecond) < deadline
      await_removed(limits, peer, deadline)
    end
  end

  defp snapshot(limits) do
    assert {:ok, snapshot} = Limits.snapshot(limits)
    snapshot
  end

  defp assert_open(handles) do
    for handle <- handles, do: assert(Resources.info(handle) == {:ok, %{cloexec: true}})
  end

  defp assert_closed(handles) do
    for handle <- handles, do: assert(Resources.info(handle) == {:error, :closed})
  end

  defp finish_actor(ctx, acknowledge \\ true) do
    if acknowledge, do: assert(:ok = :socket.send(ctx.socket, "!"))
    Port.command(ctx.actor, "q")
    assert_receive {actor, {:data, "RESOURCE_ACTOR_OK\n"}}, 5000
    assert actor == ctx.actor
    assert_receive {^actor, {:exit_status, 0}}, 5000
  end
end
