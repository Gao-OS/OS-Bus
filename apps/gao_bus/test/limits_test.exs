defmodule GaoBus.LimitsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  defp accounting(overrides \\ %{}) do
    start_supervised!({Limits, name: nil, limits: overrides})
  end

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

  defp credentials(uid \\ 1000), do: %{uid: uid, gid: 1000, pid: 123}

  defp stats(accounting) do
    assert {:ok, stats} = Limits.snapshot(accounting)
    stats
  end

  test "defaults are finite and unknown/unbounded configurations fail closed" do
    assert %{global: global, uid: uid, peer: peer} = Limits.defaults()

    for scope <- [global, uid, peer], {_metric, ceiling} <- scope do
      assert is_integer(ceiling) and ceiling > 0
    end

    for invalid <- [
          nil,
          [],
          %{unknown: %{}},
          %{global: %{unknown: 1}},
          %{global: %{connections: 0}},
          %{uid: %{authenticating: :infinity}},
          %{peer: %{ingress_bytes: -1}},
          %{peer: %{ingress_messages: 1.5}}
        ] do
      assert {:error, {:invalid_limits, _}} = Limits.start_link(name: nil, limits: invalid)
    end
  end

  test "acquiring admission claims connection and authentication slots exactly once" do
    limits = accounting()
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:error, :already_acquired} = Limits.acquire(peer, credentials(2000), limits)
    assert %{connections: 1, authenticating: 1} = stats(limits).global
    assert %{1000 => %{connections: 1, authenticating: 1}} = stats(limits).uids
    refute Map.has_key?(stats(limits).uids, 2000)

    assert :ok = Limits.auth_completed(peer, limits)
    assert {:error, :already_authenticated} = Limits.auth_completed(peer, limits)
    assert %{connections: 1, authenticating: 0} = stats(limits).global
  end

  test "invalid or absent trusted credentials never allocate slots" do
    limits = accounting()
    peer = owner()

    for invalid <- [
          nil,
          %{},
          %{uid: 0},
          %{uid: -1, gid: 0, pid: 1},
          %{uid: 0, gid: 0xFFFFFFFF, pid: 1},
          %{uid: 0xFFFFFFFF, gid: 0, pid: 1},
          %{uid: 0, gid: 0, pid: 0},
          %{uid: "0", gid: 0, pid: 1}
        ] do
      assert {:error, :invalid_credentials} = Limits.acquire(peer, invalid, limits)
    end

    assert {:error, :invalid_peer} = Limits.acquire(:not_a_pid, credentials(), limits)
    assert %{connections: 0, authenticating: 0} = stats(limits).global
    assert stats(limits).peers == %{}
    assert stats(limits).uids == %{}
  end

  test "dead owners cannot claim admission capacity" do
    limits = accounting()
    peer = owner()
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
    assert {:error, :invalid_peer} = Limits.acquire(peer, credentials(), limits)
    assert stats(limits).peers == %{}
  end

  test "per-UID connection ceiling leaves other UIDs independent" do
    limits = accounting(%{uid: %{connections: 1}})
    first = owner()
    second = owner()
    other_uid = owner()
    assert :ok = Limits.acquire(first, credentials(), limits)

    assert {:error, {:limit_exceeded, :uid, :connections}} =
             Limits.acquire(second, credentials(), limits)

    assert :ok = Limits.acquire(other_uid, credentials(2000), limits)
    assert %{connections: 2} = stats(limits).global
  end

  test "global connection ceiling spans independent UIDs" do
    limits = accounting(%{global: %{connections: 1}})
    assert :ok = Limits.acquire(owner(), credentials(), limits)

    assert {:error, {:limit_exceeded, :global, :connections}} =
             Limits.acquire(owner(), credentials(2000), limits)

    assert %{connections: 1} = stats(limits).global
  end

  test "per-UID authentication slots recover after completion" do
    limits = accounting(%{uid: %{authenticating: 1}})
    first = owner()
    second = owner()
    assert :ok = Limits.acquire(first, credentials(), limits)

    assert {:error, {:limit_exceeded, :uid, :authenticating}} =
             Limits.acquire(second, credentials(), limits)

    assert :ok = Limits.auth_completed(first, limits)
    assert :ok = Limits.acquire(second, credentials(), limits)
    assert %{connections: 2, authenticating: 1} = stats(limits).global
  end

  test "global authentication slots recover independently of connection slots" do
    limits = accounting(%{global: %{authenticating: 1}})
    first = owner()
    second = owner()
    assert :ok = Limits.acquire(first, credentials(), limits)

    assert {:error, {:limit_exceeded, :global, :authenticating}} =
             Limits.acquire(second, credentials(2000), limits)

    assert :ok = Limits.auth_completed(first, limits)
    assert :ok = Limits.acquire(second, credentials(2000), limits)
  end

  test "ingress reservations reject unknown peers and invalid byte counts" do
    limits = accounting()
    peer = owner()
    assert {:error, :unknown_peer} = Limits.reserve_ingress(peer, 1, limits)
    assert {:error, :unknown_peer} = Limits.auth_completed(peer, limits)
    assert {:error, :unknown_peer} = Limits.release_peer(peer, limits)
    assert :ok = Limits.acquire(peer, credentials(), limits)

    for invalid <- [0, -1, 1.5, :infinity, nil] do
      assert {:error, :invalid_ingress_bytes} = Limits.reserve_ingress(peer, invalid, limits)
    end

    assert stats(limits).reservations == 0
  end

  test "per-peer count is enforced at N and N+1 with no partial allocation" do
    limits = accounting(%{peer: %{ingress_messages: 1}})
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:ok, token} = Limits.reserve_ingress(peer, 10, limits)
    before = stats(limits)

    assert {:error, {:limit_exceeded, :peer, :ingress_messages}} =
             Limits.reserve_ingress(peer, 10, limits)

    assert stats(limits) == before
    assert :ok = Limits.release(token, limits)
    assert {:ok, _token} = Limits.reserve_ingress(peer, 10, limits)
  end

  test "per-peer byte ceiling includes all outstanding messages" do
    limits = accounting(%{peer: %{ingress_bytes: 10}})
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:ok, first} = Limits.reserve_ingress(peer, 6, limits)
    assert {:ok, second} = Limits.reserve_ingress(peer, 4, limits)

    assert {:error, {:limit_exceeded, :peer, :ingress_bytes}} =
             Limits.reserve_ingress(peer, 1, limits)

    assert :ok = Limits.release(first, limits)
    assert :ok = Limits.release(second, limits)
    assert %{ingress_messages: 0, ingress_bytes: 0} = stats(limits).global
  end

  test "UID ingress ceilings share usage across peers without taxing another UID" do
    limits = accounting(%{uid: %{ingress_messages: 1, ingress_bytes: 10}})
    first = owner()
    second = owner()
    independent = owner()
    assert :ok = Limits.acquire(first, credentials(), limits)
    assert :ok = Limits.acquire(second, credentials(), limits)
    assert :ok = Limits.acquire(independent, credentials(2000), limits)
    assert {:ok, token} = Limits.reserve_ingress(first, 10, limits)

    assert {:error, {:limit_exceeded, :uid, :ingress_messages}} =
             Limits.reserve_ingress(second, 1, limits)

    assert {:ok, _} = Limits.reserve_ingress(independent, 10, limits)
    assert :ok = Limits.release(token, limits)
    assert {:ok, _} = Limits.reserve_ingress(second, 10, limits)
  end

  test "UID byte ceiling is independent from its message ceiling" do
    limits = accounting(%{uid: %{ingress_bytes: 10}})
    first = owner()
    second = owner()
    assert :ok = Limits.acquire(first, credentials(), limits)
    assert :ok = Limits.acquire(second, credentials(), limits)
    assert {:ok, _} = Limits.reserve_ingress(first, 6, limits)

    assert {:error, {:limit_exceeded, :uid, :ingress_bytes}} =
             Limits.reserve_ingress(second, 5, limits)

    assert %{ingress_messages: 1, ingress_bytes: 6} = stats(limits).uids[1000]
  end

  test "global ingress count and bytes span independent UIDs" do
    for {metric, ceiling, size, rejected_size} <- [
          {:ingress_messages, 1, 5, 1},
          {:ingress_bytes, 10, 6, 5}
        ] do
      limits =
        start_supervised!({Limits, name: nil, limits: %{global: %{metric => ceiling}}},
          id: make_ref()
        )

      first = owner()
      second = owner()
      assert :ok = Limits.acquire(first, credentials(), limits)
      assert :ok = Limits.acquire(second, credentials(2000), limits)
      assert {:ok, _} = Limits.reserve_ingress(first, size, limits)

      assert {:error, {:limit_exceeded, :global, ^metric}} =
               Limits.reserve_ingress(second, rejected_size, limits)
    end
  end

  test "release is exactly once and unknown tokens cannot underflow accounting" do
    limits = accounting()
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:ok, token} = Limits.reserve_ingress(peer, 10, limits)
    assert is_reference(token)
    assert :ok = Limits.release(token, limits)
    before = stats(limits)
    assert {:error, :unknown_reservation} = Limits.release(token, limits)
    assert {:error, :unknown_reservation} = Limits.release(make_ref(), limits)
    assert stats(limits) == before
  end

  test "explicit cleanup keeps queued work charged until its handler releases it" do
    limits = accounting()
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:ok, first} = Limits.reserve_ingress(peer, 10, limits)
    assert {:ok, second} = Limits.reserve_ingress(peer, 20, limits)
    assert :ok = Limits.release_peer(peer, limits)
    assert {:error, :unknown_peer} = Limits.release_peer(peer, limits)

    assert %{connections: 0, authenticating: 0, ingress_messages: 2, ingress_bytes: 30} =
             stats(limits).global

    assert %{1000 => %{connections: 0, ingress_messages: 2}} = stats(limits).uids
    assert :ok = Limits.release(first, limits)
    assert :ok = Limits.release(second, limits)

    assert %{connections: 0, authenticating: 0, ingress_messages: 0, ingress_bytes: 0} =
             stats(limits).global

    assert stats(limits).peers == %{}
    assert stats(limits).uids == %{}
    assert stats(limits).reservations == 0
  end

  test "owner kill restores admission but cannot bypass queued ingress capacity" do
    limits = accounting(%{global: %{connections: 1, authenticating: 1, ingress_messages: 1}})
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    assert {:ok, token} = Limits.reserve_ingress(peer, 10, limits)
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
    await_empty(limits, System.monotonic_time(:millisecond) + 1000)
    replacement = owner()
    assert :ok = Limits.acquire(replacement, credentials(), limits)
    # The dead source's message still occupies Router's mailbox. Reconnecting
    # must not turn source death into unlimited queued work.
    assert {:error, {:limit_exceeded, :global, :ingress_messages}} =
             Limits.reserve_ingress(replacement, 10, limits)

    assert :ok = Limits.release(token, limits)
    assert {:ok, _} = Limits.reserve_ingress(replacement, 10, limits)
  end

  test "concurrent ingress reservations cannot exceed the shared ceiling" do
    limits = accounting(%{global: %{ingress_messages: 3, ingress_bytes: 30}})
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(), limits)
    tasks = start_supervised!(Task.Supervisor)
    parent = self()

    actors =
      for _ <- 1..12 do
        Task.Supervisor.async_nolink(tasks, fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> Limits.reserve_ingress(peer, 10, limits)
          end
        end)
      end

    for task <- actors, do: assert_receive({:ready, pid} when pid == task.pid)
    for task <- actors, do: send(task.pid, :go)
    results = Enum.map(actors, &Task.await/1)
    tokens = for {:ok, token} <- results, do: token
    assert length(tokens) == 3

    assert Enum.count(results, &(&1 == {:error, {:limit_exceeded, :global, :ingress_messages}})) ==
             9

    assert %{ingress_messages: 3, ingress_bytes: 30} = stats(limits).global
    for token <- tokens, do: assert(:ok == Limits.release(token, limits))
    assert %{ingress_messages: 0, ingress_bytes: 0} = stats(limits).global
  end

  test "concurrent admissions claim connection and authentication slots atomically" do
    limits = accounting(%{global: %{connections: 3, authenticating: 3}})
    tasks = start_supervised!(Task.Supervisor)
    parent = self()

    actors =
      for _ <- 1..12 do
        Task.Supervisor.async_nolink(tasks, fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> :ok
          end

          send(parent, {:admitted, self(), Limits.acquire(self(), credentials(), limits)})

          receive do
            :stop -> :ok
          end
        end)
      end

    for task <- actors, do: assert_receive({:ready, pid} when pid == task.pid)
    for task <- actors, do: send(task.pid, :go)

    results =
      for task <- actors do
        pid = task.pid
        assert_receive {:admitted, ^pid, result}
        result
      end

    assert Enum.count(results, &(&1 == :ok)) == 3
    assert Enum.count(results, &(&1 == {:error, {:limit_exceeded, :global, :connections}})) == 9
    assert %{connections: 3, authenticating: 3} = stats(limits).global
    for task <- actors, do: send(task.pid, :stop)
    for task <- actors, do: assert(:ok == Task.await(task))
    await_empty(limits, System.monotonic_time(:millisecond) + 1000)
  end

  test "unavailable accounting never grants admission or ingress" do
    unavailable = owner()
    monitor = Process.monitor(unavailable)
    Process.exit(unavailable, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^unavailable, :killed}

    for result <- [
          Limits.acquire(self(), credentials(), unavailable),
          Limits.auth_completed(self(), unavailable),
          Limits.reserve_ingress(self(), 1, unavailable),
          Limits.release(make_ref(), unavailable),
          Limits.release_peer(self(), unavailable),
          Limits.snapshot(unavailable)
        ] do
      assert {:error, :accounting_unavailable} = result
    end
  end

  defp await_empty(limits, deadline) do
    case stats(limits).global do
      %{connections: 0} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline
        await_empty(limits, deadline)
    end
  end
end
