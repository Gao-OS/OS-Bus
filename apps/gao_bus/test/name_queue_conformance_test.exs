defmodule GaoBus.NameQueueConformanceTest do
  use ExUnit.Case, async: false
  alias GaoBus.NameRegistry

  setup do
    Application.stop(:gao_bus)
    start_supervised!(GaoBus.Limits)
    start_supervised!({NameRegistry, max_names_per_peer: 2, max_name_entries: 4})

    peers =
      for n <- 1..4 do
        pid = start_supervised!(%{id: {:peer, n}, start: {Agent, :start_link, [fn -> :peer end]}})
        :ok = GaoBus.Limits.acquire(pid, %{uid: 1000, gid: 1000, pid: 123})
        :ok = GaoBus.Limits.auth_completed(pid)
        name = ":1.#{n}"
        :ok = NameRegistry.register_unique(name, pid)
        {pid, name}
      end

    %{peers: peers, name: "org.foundation.Queue"}
  end

  test "owner repeat updates flags and replacement requeues it ahead of waiters", ctx do
    [a, b, c, d] = ctx.peers
    assert {:ok, 1} = request(ctx, a, 0)
    assert {:ok, 4} = request(ctx, a, 1)
    assert {:ok, 2} = request(ctx, b, 0)
    assert {:ok, 2} = request(ctx, c, 0)
    assert {:ok, 1} = request(ctx, d, 2)
    assert queue(ctx) == names([d, a, b, c])
  end

  test "queued repeats update flags without duplicate entries or extra quota", ctx do
    [a, b, c, d] = ctx.peers
    assert {:ok, 1} = request(ctx, a, 1)
    for peer <- [b, c, d], do: assert({:ok, 2} = request(ctx, peer, 0))
    assert {:ok, 2} = request(ctx, b, 1)
    assert queue(ctx) == names([a, b, c, d])
    assert {:ok, 3} = request(ctx, b, 4)
    assert queue(ctx) == names([a, c, d])
    assert {:ok, 1} = request(ctx, c, 2)
    assert queue(ctx) == names([c, a, d])
  end

  test "replacement drops old DO_NOT_QUEUE owner and never keeps new owner twice", ctx do
    [a, b, c, _] = ctx.peers
    assert {:ok, 1} = request(ctx, a, 5)
    assert {:ok, 2} = request(ctx, b, 0)
    assert {:ok, 2} = request(ctx, c, 0)
    assert {:ok, 1} = request(ctx, c, 2)
    assert queue(ctx) == names([c, b])
    refute ctx.name in NameRegistry.names_for(elem(a, 0))
    assert {:ok, 1} = NameRegistry.release_name(ctx.name, elem(c, 0))
    assert queue(ctx) == names([b])
  end

  test "SEM-01 queued REPLACE_EXISTING cannot jump a non-replaceable primary owner", ctx do
    [a, b, c, d] = ctx.peers
    assert {:ok, 1} = request(ctx, a, 1)
    for peer <- [b, c], do: assert({:ok, 2} = request(ctx, peer, 0))
    assert {:ok, 1} = request(ctx, d, 2)
    assert {:ok, 2} = request(ctx, b, 2)
    assert queue(ctx) == names([d, a, b, c])
    assert {:ok, 1} = NameRegistry.release_name(ctx.name, elem(d, 0))
    assert queue(ctx) == names([a, b, c])
    assert {:ok, elem(a, 1)} == NameRegistry.get_name_owner(ctx.name)
  end

  test "queued release and disconnect are idempotent and cannot resurrect an owner", ctx do
    [a, b, c, _] = ctx.peers
    assert {:ok, 1} = request(ctx, a, 0)
    assert {:ok, 2} = request(ctx, b, 0)
    assert {:ok, 2} = request(ctx, c, 0)
    assert {:ok, 1} = NameRegistry.release_name(ctx.name, elem(b, 0))
    assert {:ok, 3} = NameRegistry.release_name(ctx.name, elem(b, 0))
    NameRegistry.peer_disconnected(elem(b, 0))
    NameRegistry.peer_disconnected(elem(a, 0))
    assert queue(ctx) == names([c])
    NameRegistry.peer_disconnected(elem(a, 0))
    assert queue(ctx) == names([c])
    assert {:ok, 1} = NameRegistry.release_name(ctx.name, elem(c, 0))

    assert {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"} =
             NameRegistry.list_queued_owners(ctx.name)
  end

  test "bus self and unique names are queryable but cannot be requested", ctx do
    [a | _] = ctx.peers
    assert {:ok, "org.freedesktop.DBus"} = NameRegistry.get_name_owner("org.freedesktop.DBus")

    assert {:ok, ["org.freedesktop.DBus"]} =
             NameRegistry.list_queued_owners("org.freedesktop.DBus")

    assert {:ok, [elem(a, 1)]} == NameRegistry.list_queued_owners(elem(a, 1))

    for name <- [
          "org.freedesktop.DBus",
          ":1.1",
          "bad",
          "org..bad",
          "org.1bad",
          "",
          "org." <> String.duplicate("a", 252)
        ] do
      assert {:error, _} = NameRegistry.request_name(name, 0, elem(a, 0), elem(a, 1))
    end

    assert {:bus, _} = NameRegistry.resolve("org.freedesktop.DBus")
    assert {:ok, elem(a, 0)} == NameRegistry.resolve(elem(a, 1))
  end

  defp request(ctx, {pid, unique}, flags),
    do: NameRegistry.request_name(ctx.name, flags, pid, unique)

  defp queue(ctx) do
    assert {:ok, queue} = NameRegistry.list_queued_owners(ctx.name)
    queue
  end

  defp names(peers), do: Enum.map(peers, &elem(&1, 1))
end
