defmodule GaoBus.TransportLimitsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  defp accounting(overrides \\ %{}) do
    start_supervised!({Limits, name: nil, limits: overrides}, id: make_ref())
  end

  defp owner do
    start_supervised!({Task, fn -> receive do: (:stop -> :ok) end}, id: make_ref())
  end

  defp acquire(limits, uid \\ 1000) do
    peer = owner()
    assert :ok = Limits.acquire(peer, %{uid: uid, gid: 1000, pid: 123}, limits)
    peer
  end

  defp stats(limits) do
    assert {:ok, stats} = Limits.snapshot(limits)
    stats
  end

  defp await_removed(limits, peer, deadline) do
    if Map.has_key?(stats(limits).peers, peer) do
      assert System.monotonic_time(:millisecond) < deadline
      await_removed(limits, peer, deadline)
    end
  end

  for scope <- [:peer, :uid, :global],
      metric <- [
        :ingress_fds,
        :egress_messages,
        :egress_bytes,
        :egress_fds,
        :frame_bytes,
        :frame_fds
      ] do
    test "#{scope} #{metric} enforces N and N+1 transactionally" do
      scope = unquote(scope)
      metric = unquote(metric)
      limits = accounting(%{scope => %{metric => 2}})
      first = acquire(limits)

      second =
        if scope == :peer,
          do: first,
          else: acquire(limits, if(scope == :global, do: 2000, else: 1000))

      {reserve, at_boundary, over_boundary} =
        case metric do
          :ingress_fds -> {&Limits.reserve_ingress_fds/4, {1, 2}, {1, 1}}
          :egress_messages -> {&Limits.reserve_egress/4, {1, 0}, {1, 0}}
          :egress_bytes -> {&Limits.reserve_egress/4, {2, 0}, {1, 0}}
          :egress_fds -> {&Limits.reserve_egress/4, {1, 2}, {1, 1}}
          :frame_bytes -> {&Limits.set_frame/4, {2, 0}, {if(scope == :peer, do: 3, else: 1), 0}}
          :frame_fds -> {&Limits.set_frame/4, {1, 2}, {1, if(scope == :peer, do: 3, else: 1)}}
        end

      {bytes, fds} = at_boundary
      if metric == :egress_messages, do: assert({:ok, _} = reserve.(first, bytes, fds, limits))
      assert reserve.(first, bytes, fds, limits) |> successful?()
      before = stats(limits)
      {bytes, fds} = over_boundary
      assert {:error, {:limit_exceeded, ^scope, ^metric}} = reserve.(second, bytes, fds, limits)
      assert stats(limits) == before
    end
  end

  defp successful?(:ok), do: true
  defp successful?({:ok, token}), do: is_reference(token)

  test "absolute frame reservations shrink and promotion preserves buffered remainder" do
    limits = accounting(%{peer: %{frame_bytes: 10, frame_fds: 2}})
    peer = acquire(limits)
    assert :ok = Limits.set_frame(peer, 10, 2, limits)
    assert :ok = Limits.set_frame(peer, 8, 2, limits)
    assert %{frame_bytes: 8, frame_fds: 2} = stats(limits).global
    assert {:ok, first} = Limits.promote_frame(peer, 5, 1, limits)

    assert %{frame_bytes: 3, frame_fds: 1, ingress_bytes: 5, ingress_fds: 1, ingress_messages: 1} =
             stats(limits).global

    assert {:ok, second} = Limits.promote_frame(peer, 3, 1, limits)

    assert %{frame_bytes: 0, frame_fds: 0, ingress_bytes: 8, ingress_fds: 2, ingress_messages: 2} =
             stats(limits).global

    assert :ok = Limits.release(first, limits)
    assert :ok = Limits.release(second, limits)
  end

  test "failed promotion neither loses buffered credits nor creates a token" do
    limits = accounting(%{peer: %{ingress_messages: 1}})
    peer = acquire(limits)
    assert :ok = Limits.set_frame(peer, 10, 2, limits)
    assert {:ok, token} = Limits.reserve_ingress_fds(peer, 1, 0, limits)
    before = stats(limits)

    assert {:error, {:limit_exceeded, :peer, :ingress_messages}} =
             Limits.promote_frame(peer, 5, 1, limits)

    assert stats(limits) == before
    assert :ok = Limits.release(token, limits)
    assert {:ok, promoted} = Limits.promote_frame(peer, 5, 1, limits)
    assert :ok = Limits.release(promoted, limits)
  end

  test "invalid transport inputs and over-promotion never mutate accounting" do
    limits = accounting()
    peer = acquire(limits)
    assert :ok = Limits.set_frame(peer, 8, 1, limits)
    before = stats(limits)

    for {bytes, fds} <- [{-1, 0}, {1, -1}, {1.5, 0}, {1, :infinity}, {nil, nil}] do
      assert {:error, _} = Limits.set_frame(peer, bytes, fds, limits)
      assert {:error, _} = Limits.promote_frame(peer, bytes, fds, limits)
      assert {:error, _} = Limits.reserve_ingress_fds(peer, bytes, fds, limits)
      assert {:error, _} = Limits.reserve_egress(peer, bytes, fds, limits)
      assert stats(limits) == before
    end

    for {bytes, fds} <- [{9, 1}, {8, 2}, {0, 0}] do
      assert {:error, _} = Limits.promote_frame(peer, bytes, fds, limits)
      assert stats(limits) == before
    end

    assert :ok = Limits.set_frame(peer, 0, 0, limits)
    assert %{frame_bytes: 0, frame_fds: 0} = stats(limits).global
    assert {:error, :unknown_peer} = Limits.set_frame(owner(), 1, 0, limits)
  end

  test "source DOWN retains ingress FD and byte capacity at its UID and globally" do
    for scope <- [:uid, :global], {metric, ceiling} <- [ingress_bytes: 8, ingress_fds: 2] do
      limits = accounting(%{scope => %{metric => ceiling}})
      source = acquire(limits)
      assert :ok = Limits.set_frame(source, 8, 2, limits)
      assert {:ok, token} = Limits.promote_frame(source, 8, 2, limits)
      monitor = Process.monitor(source)
      Process.exit(source, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^source, :killed}
      await_removed(limits, source, System.monotonic_time(:millisecond) + 1000)

      assert %{
               connections: 0,
               authenticating: 0,
               frame_bytes: 0,
               frame_fds: 0,
               ingress_bytes: 8,
               ingress_fds: 2
             } = stats(limits).global

      assert %{1000 => %{connections: 0, ingress_bytes: 8, ingress_fds: 2}} = stats(limits).uids
      replacement = acquire(limits, if(scope == :global, do: 2000, else: 1000))

      assert {:error, {:limit_exceeded, ^scope, ^metric}} =
               Limits.reserve_ingress_fds(replacement, 1, 1, limits)

      assert :ok = Limits.release(token, limits)
      assert {:error, :unknown_reservation} = Limits.release(token, limits)
      assert {:ok, next} = Limits.reserve_ingress_fds(replacement, 8, 2, limits)
      assert :ok = Limits.release(next, limits)
      assert :ok = Limits.release_peer(replacement, limits)
      assert stats(limits).uids == %{}
    end
  end

  test "recipient DOWN releases egress and frame credits but leaves queued ingress" do
    limits = accounting()
    recipient = acquire(limits)
    assert :ok = Limits.set_frame(recipient, 4, 2, limits)
    assert {:ok, outgoing} = Limits.reserve_egress(recipient, 10, 3, limits)
    assert {:ok, incoming} = Limits.reserve_ingress_fds(recipient, 5, 1, limits)
    monitor = Process.monitor(recipient)
    Process.exit(recipient, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^recipient, :killed}
    await_removed(limits, recipient, System.monotonic_time(:millisecond) + 1000)

    assert %{
             connections: 0,
             authenticating: 0,
             frame_bytes: 0,
             frame_fds: 0,
             egress_messages: 0,
             egress_bytes: 0,
             egress_fds: 0,
             ingress_messages: 1,
             ingress_bytes: 5,
             ingress_fds: 1
           } = stats(limits).global

    assert {:error, :unknown_reservation} = Limits.release(outgoing, limits)
    assert {:error, :unknown_peer} = Limits.release_peer(recipient, limits)
    assert :ok = Limits.release(incoming, limits)
    assert stats(limits).uids == %{}
    assert stats(limits).reservations == 0
  end

  test "released live peer cannot reacquire to bypass its outstanding work credits" do
    limits = accounting()
    source = acquire(limits)
    assert {:ok, token} = Limits.reserve_ingress(source, 5, limits)
    assert :ok = Limits.release_peer(source, limits)

    assert {:error, :already_acquired} =
             Limits.acquire(source, %{uid: 2000, gid: 1000, pid: 123}, limits)

    assert :ok = Limits.release(token, limits)
    assert :ok = Limits.acquire(source, %{uid: 2000, gid: 1000, pid: 123}, limits)
    refute Map.has_key?(stats(limits).uids, 1000)
  end

  test "concurrent writers reserve shared egress capacity before enqueue" do
    limits = accounting(%{global: %{egress_messages: 3, egress_bytes: 30, egress_fds: 3}})
    recipient = acquire(limits)
    tasks = start_supervised!(Task.Supervisor)
    parent = self()

    writers =
      for _ <- 1..12 do
        Task.Supervisor.async_nolink(tasks, fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> Limits.reserve_egress(recipient, 10, 1, limits)
          end
        end)
      end

    for task <- writers, do: assert_receive({:ready, pid} when pid == task.pid)
    for task <- writers, do: send(task.pid, :go)
    results = Enum.map(writers, &Task.await/1)
    tokens = for {:ok, token} <- results, do: token
    assert length(tokens) == 3

    assert Enum.count(results, &(&1 == {:error, {:limit_exceeded, :global, :egress_messages}})) ==
             9

    assert %{egress_messages: 3, egress_bytes: 30, egress_fds: 3} = stats(limits).global
    for token <- tokens, do: assert(:ok == Limits.release(token, limits))
    assert %{egress_messages: 0, egress_bytes: 0, egress_fds: 0} = stats(limits).global
  end

  test "explicit recipient cleanup releases egress exactly once" do
    limits = accounting()
    recipient = acquire(limits)
    assert {:ok, token} = Limits.reserve_egress(recipient, 8, 2, limits)
    assert :ok = Limits.set_frame(recipient, 3, 1, limits)
    assert :ok = Limits.release_peer(recipient, limits)
    assert {:error, :unknown_reservation} = Limits.release(token, limits)
    assert {:error, :unknown_peer} = Limits.release_peer(recipient, limits)
    assert stats(limits).uids == %{}
    assert stats(limits).reservations == 0
  end

  test "unavailable accounting fails closed for every transport operation" do
    unavailable = owner()
    monitor = Process.monitor(unavailable)
    Process.exit(unavailable, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^unavailable, :killed}

    for result <- [
          Limits.reserve_ingress_fds(self(), 1, 0, unavailable),
          Limits.reserve_egress(self(), 1, 0, unavailable),
          Limits.set_frame(self(), 1, 0, unavailable),
          Limits.promote_frame(self(), 1, 0, unavailable)
        ] do
      assert result == {:error, :accounting_unavailable}
    end
  end
end
