defmodule GaoBus.RouterWorkAccountingTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message
  alias GaoBus.Limits

  setup do
    %{limits: start_supervised!({Limits, name: nil})}
  end

  test "mailbox handoff holds ingress after source exit until authority completion", ctx do
    source = owner()
    admit(ctx, source)
    assert {:ok, token} = Limits.enqueue_route(message(), source, 128, :route, self(), ctx.limits)
    assert_receive {:owned_route, _, ^source, ^token, 128, :route}
    monitor = Process.monitor(source)
    Process.exit(source, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^source, :killed}

    await(ctx, fn state -> not Map.has_key?(state.peers, source) end)
    held = snapshot(ctx)
    assert held.global.connections == 0
    assert held.global.authenticating == 0
    assert held.global.ingress_messages == 1
    assert held.global.ingress_bytes == 128
    assert held.reservations == 1
    assert held.uids[1000].ingress_messages == 1
    assert held.uids[1000].ingress_bytes == 128

    assert :ok = Limits.release(token, ctx.limits)
    finished = snapshot(ctx)
    assert finished.global.ingress_messages == 0
    assert finished.global.ingress_bytes == 0
    assert finished.reservations == 0
    assert finished.uids == %{}
    assert {:error, :unknown_reservation} = Limits.release(token, ctx.limits)
    assert snapshot(ctx) == finished
  end

  test "authority DOWN reclaims enqueued ingress and internal work", ctx do
    authority = owner()
    admit(ctx, self())

    assert {:ok, _token} =
             Limits.enqueue_route(message(), self(), 128, :route, authority, ctx.limits)

    assert {:ok, _control} =
             Limits.enqueue_control(authority, {:notification, "value"}, ctx.limits)

    monitor = Process.monitor(authority)
    send(authority, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^authority, :normal}
    await(ctx, fn state -> state.global.ingress_messages == 0 and state.control.count == 0 end)
    assert snapshot(ctx).control.bytes == 0
  end

  test "control count is reserved before mailbox enqueue and release is exactly once", ctx do
    tokens =
      for _ <- 1..512 do
        assert {:ok, token} = Limits.reserve_control(self(), 1, ctx.limits)
        token
      end

    assert snapshot(ctx).control == %{count: 512, bytes: 512}
    assert {:error, :control_capacity} = Limits.enqueue_control(self(), :extra, ctx.limits)
    refute_receive {:control_work, _, :extra}, 0
    token = hd(tokens)
    assert :ok = Limits.release_control(token, ctx.limits)
    assert {:error, :unknown_control_reservation} = Limits.release_control(token, ctx.limits)
    for token <- tl(tokens), do: assert(:ok == Limits.release_control(token, ctx.limits))
    assert snapshot(ctx).control == %{count: 0, bytes: 0}
  end

  test "control bytes are bounded independently of its count", ctx do
    assert {:ok, token} = Limits.reserve_control(self(), 4_194_304, ctx.limits)
    assert {:error, :control_capacity} = Limits.reserve_control(self(), 1, ctx.limits)
    assert snapshot(ctx).control == %{count: 1, bytes: 4_194_304}
    assert :ok = Limits.release_control(token, ctx.limits)
  end

  test "a dead authority receives no handoff and no charge", ctx do
    authority = owner()
    monitor = Process.monitor(authority)
    send(authority, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^authority, :normal}
    admit(ctx, self())
    before = snapshot(ctx)

    assert {:error, :route_unavailable} =
             Limits.enqueue_route(message(), self(), 128, :route, authority, ctx.limits)

    assert {:error, :control_owner_unavailable} =
             Limits.enqueue_control(authority, :work, ctx.limits)

    assert snapshot(ctx) == before
  end

  test "terminal producer DOWN reclaims capacity before enqueue", ctx do
    parent = self()
    limits = ctx.limits

    producer =
      start_supervised!(
        {Task,
         fn ->
           send(parent, {:terminal_reserved, Limits.reserve_terminal(parent, 1024, limits)})

           receive do
             :stop -> :ok
           end
         end},
        id: make_ref()
      )

    assert_receive {:terminal_reserved, {:ok, _token}}
    assert snapshot(ctx).control == %{count: 1, bytes: 1024}
    monitor = Process.monitor(producer)
    send(producer, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^producer, :normal}
    await(ctx, &(&1.control.count == 0))
    assert snapshot(ctx).control.bytes == 0
  end

  test "terminal handoff survives producer DOWN until its authority consumes it", ctx do
    parent = self()
    limits = ctx.limits

    producer =
      start_supervised!(
        {Task,
         fn ->
           {:ok, token} = Limits.reserve_terminal(parent, 1024, limits)
           :ok = Limits.enqueue_terminal(token, :terminal, limits)
         end},
        id: make_ref()
      )

    monitor = Process.monitor(producer)
    assert_receive {:control_work, token, :terminal}
    assert_receive {:DOWN, ^monitor, :process, ^producer, _reason}
    assert snapshot(ctx).control == %{count: 1, bytes: 1024}
    assert :ok = Limits.release_control(token, ctx.limits)
    assert snapshot(ctx).control == %{count: 0, bytes: 0}
  end

  test "terminal cancel retires only work that has not moved to the authority", ctx do
    assert {:ok, cancelled} = Limits.reserve_terminal(self(), 1024, ctx.limits)
    assert :ok = Limits.cancel_terminal(cancelled, ctx.limits)
    assert snapshot(ctx).control.count == 0
    assert {:ok, queued} = Limits.reserve_terminal(self(), 1024, ctx.limits)
    assert :ok = Limits.enqueue_terminal(queued, :terminal, ctx.limits)
    assert :ok = Limits.cancel_terminal(queued, ctx.limits)
    assert_receive {:control_work, ^queued, :terminal}
    assert snapshot(ctx).control.count == 1
    assert :ok = Limits.release_control(queued, ctx.limits)
    assert snapshot(ctx).control.count == 0
  end

  test "authority DOWN reclaims reserved and enqueued terminal capacity", ctx do
    authority = owner()
    assert {:ok, _reserved} = Limits.reserve_terminal(authority, 1024, ctx.limits)
    assert {:ok, queued} = Limits.reserve_terminal(authority, 1024, ctx.limits)
    assert :ok = Limits.enqueue_terminal(queued, :terminal, ctx.limits)
    monitor = Process.monitor(authority)
    send(authority, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^authority, :normal}
    await(ctx, &(&1.control.count == 0))
    assert snapshot(ctx).control.bytes == 0
  end

  test "oversized terminal payload cannot exceed its admitted byte credit", ctx do
    assert {:ok, token} = Limits.reserve_terminal(self(), 1, ctx.limits)

    assert {:error, :terminal_envelope_too_large} =
             Limits.enqueue_terminal(token, "oversized", ctx.limits)

    refute_receive {:control_work, ^token, _}, 0
    assert snapshot(ctx).control == %{count: 1, bytes: 1}
    assert :ok = Limits.cancel_terminal(token, ctx.limits)
    assert snapshot(ctx).control.count == 0
  end

  defp admit(ctx, peer),
    do: assert(:ok == Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 123}, ctx.limits))

  defp message,
    do: Message.signal("/example", "org.example.Events", "Broadcast", serial: 1)

  defp owner do
    start_supervised!(
      {Task,
       fn ->
         receive do
           :stop -> :ok
         end
       end},
      id: make_ref()
    )
  end

  defp snapshot(ctx) do
    assert {:ok, state} = Limits.snapshot(ctx.limits)
    state
  end

  defp await(ctx, predicate, remaining \\ 1000)
  defp await(_ctx, _predicate, 0), do: flunk("accounting cleanup did not settle")

  defp await(ctx, predicate, remaining) do
    if predicate.(snapshot(ctx)), do: :ok, else: await(ctx, predicate, remaining - 1)
  end
end
