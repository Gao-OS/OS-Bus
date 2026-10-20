defmodule GaoBus.ActivationLimitsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  test "activation safety defaults independently bound every scope" do
    for scope <- [:peer, :uid, :global],
        metric <- [:activation_messages, :activation_bytes, :activation_fds] do
      assert is_integer(Limits.defaults()[scope][metric])
      assert Limits.defaults()[scope][metric] > 0
    end
  end

  test "zero XML pending starts admits no waiter without charging native credit" do
    limits =
      start_supervised!({Limits, name: nil, xml_limits: %{"max_pending_service_starts" => 0}})

    {peer, ingress, identity} = source(limits)
    before = snapshot(limits)

    assert {:error, {:xml_limit_exceeded, "max_pending_service_starts"}} =
             reserve(limits, ingress, identity)

    assert snapshot(limits) == before
    assert :ok = Limits.release(ingress, limits)
    assert :ok = Limits.release_peer(peer, limits)
  end

  for scope <- [:peer, :uid, :global], metric <- [:activation_messages, :activation_bytes] do
    test "#{scope} #{metric} refuses the next waiter atomically" do
      scope = unquote(scope)
      metric = unquote(metric)
      ceiling = if metric == :activation_messages, do: 1, else: 8
      limits = start_supervised!({Limits, name: nil, limits: %{scope => %{metric => ceiling}}})
      {first, ingress, identity} = source(limits)
      assert {:ok, lease} = reserve(limits, ingress, identity)

      peer = if scope == :peer, do: first, else: owner()

      if peer != first,
        do:
          assert(
            :ok =
              Limits.acquire(
                peer,
                credentials(if(scope == :global, do: 2000, else: 1000)),
                limits
              )
          )

      assert {:ok, other_ingress} = Limits.reserve_ingress(peer, 8, limits)
      other_identity = identity(peer)
      before = snapshot(limits)

      assert {:error, {:limit_exceeded, ^scope, ^metric}} =
               reserve(limits, other_ingress, other_identity)

      assert snapshot(limits) == before
      assert :ok = release(limits, lease, identity.request_key)
      assert {:ok, next} = reserve(limits, other_ingress, other_identity)
      assert :ok = release(limits, next, other_identity.request_key)
      assert :ok = Limits.release(ingress, limits)
      assert :ok = Limits.release(other_ingress, limits)
      assert snapshot(limits).global.activation_messages == 0
    end
  end

  test "XML entry ceiling counts multiple waiters from one destination" do
    limits =
      start_supervised!({Limits, name: nil, xml_limits: %{"max_pending_service_starts" => 1}})

    {peer, ingress, identity} = source(limits)
    assert {:ok, lease} = reserve(limits, ingress, identity)
    assert {:ok, second_ingress} = Limits.reserve_ingress(peer, 8, limits)
    before = snapshot(limits)

    assert {:error, {:xml_limit_exceeded, "max_pending_service_starts"}} =
             reserve(limits, second_ingress, identity(peer))

    assert snapshot(limits) == before
    assert :ok = release(limits, lease, identity.request_key)
  end

  test "source identity is checked even without XML queue configuration" do
    limits = start_supervised!({Limits, name: nil})
    {_peer, ingress, identity} = source(limits)
    other = owner()
    assert :ok = Limits.acquire(other, credentials(2000), limits)
    before = snapshot(limits)

    assert {:error, :invalid_activation_source} =
             reserve(limits, ingress, %{identity | caller: other})

    assert {:error, :invalid_activation_source} = reserve(limits, make_ref(), identity)
    assert snapshot(limits) == before
    assert :ok = Limits.release(ingress, limits)
    assert {:error, :invalid_activation_source} = reserve(limits, ingress, identity)
  end

  test "a complete message cannot lease less credit than its causal ingress" do
    limits = start_supervised!({Limits, name: nil})
    {_peer, ingress, identity} = source(limits)
    before = snapshot(limits)

    assert {:error, :invalid_activation_source} =
             api(:reserve_activation, [ingress, identity, 1, [], self(), limits])

    assert snapshot(limits) == before
  end

  test "payload UID cannot move a reservation away from its acquired UID" do
    limits = start_supervised!({Limits, name: nil})
    {_peer, ingress, identity} = source(limits)
    assert {:ok, lease} = reserve(limits, ingress, Map.put(identity, :uid, 0))
    assert snapshot(limits).uids[1000].activation_messages == 1
    refute Map.has_key?(snapshot(limits).uids, 0)
    assert :ok = release(limits, lease, identity.request_key)
  end

  test "duplicate request cannot create another lease or retire the first" do
    limits = start_supervised!({Limits, name: nil})
    {_peer, ingress, identity} = source(limits)
    assert {:ok, lease} = reserve(limits, ingress, identity)
    before = snapshot(limits)
    assert {:error, :duplicate_activation_request} = reserve(limits, ingress, identity)
    assert {:error, :activation_not_owner} = release(limits, lease, {make_ref(), make_ref()})
    assert {:error, :activation_requires_owner} = Limits.release(lease, limits)
    assert snapshot(limits) == before
    assert {:ok, []} = claim(limits, lease, identity.request_key)
    assert {:error, :activation_already_claimed} = claim(limits, lease, identity.request_key)
    assert :ok = release(limits, lease, identity.request_key)
    assert {:error, :unknown_activation_lease} = release(limits, lease, identity.request_key)
  end

  test "caller death retains queued body and UID credits until coordinator drain" do
    limits = start_supervised!({Limits, name: nil, limits: %{uid: %{activation_messages: 1}}})
    {peer, ingress, identity} = source(limits)
    assert {:ok, lease} = reserve(limits, ingress, identity)
    assert :ok = Limits.release(ingress, limits)
    assert :ok = Limits.release_peer(peer, limits)
    assert snapshot(limits).global.activation_messages == 1
    assert snapshot(limits).global.activation_bytes == 8
    assert snapshot(limits).global.ingress_messages == 1
    assert {:error, :activation_cancelled} = claim(limits, lease, identity.request_key)
    {_next_peer, next_ingress, next_identity} = source(limits)

    assert {:error, {:limit_exceeded, :uid, :activation_messages}} =
             reserve(limits, next_ingress, next_identity)

    assert :ok = release(limits, lease, identity.request_key)
    assert snapshot(limits).global.activation_messages == 0
    assert snapshot(limits).global.ingress_messages == 1
    assert :ok = Limits.release(next_ingress, limits)
  end

  test "dead coordinator and expired metadata cannot admit queued work" do
    limits = start_supervised!({Limits, name: nil})
    {_peer, ingress, identity} = source(limits)
    coordinator = owner()
    ref = Process.monitor(coordinator)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^ref, :process, ^coordinator, :killed}
    before = snapshot(limits)
    assert {:error, :invalid_activation_owner} = reserve(limits, ingress, identity, coordinator)

    assert {:error, :activation_expired} =
             reserve(limits, ingress, %{identity | deadline: System.monotonic_time(:millisecond)})

    assert snapshot(limits) == before
  end

  defp source(limits) do
    peer = owner()
    assert :ok = Limits.acquire(peer, credentials(1000), limits)
    assert {:ok, ingress} = Limits.reserve_ingress(peer, 8, limits)
    {peer, ingress, identity(peer)}
  end

  defp identity(peer),
    do: %{
      caller: peer,
      caller_incarnation: {make_ref(), ":1.1"},
      request_key: {make_ref(), make_ref()},
      deadline: System.monotonic_time(:millisecond) + 5000
    }

  defp credentials(uid), do: %{uid: uid, gid: 1000, pid: 123}
  defp owner, do: start_supervised!({Task, fn -> receive do: (:stop -> :ok) end}, id: make_ref())

  defp snapshot(limits) do
    assert {:ok, result} = Limits.snapshot(limits)
    result
  end

  defp reserve(limits, ingress, identity, coordinator \\ self()),
    do: api(:reserve_activation, [ingress, identity, 8, [], coordinator, limits])

  defp claim(limits, lease, request), do: api(:claim_activation, [lease, request, limits])
  defp release(limits, lease, request), do: api(:release_activation, [lease, request, limits])

  defp api(function, args) do
    assert function_exported?(Limits, function, length(args)),
           "missing activation lease API #{function}"

    apply(Limits, function, args)
  end
end
