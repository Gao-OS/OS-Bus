defmodule GaoBus.ActivationObservationTest do
  use ExUnit.Case, async: true

  alias GaoBus.Activation.State

  @name "org.example.Observed"
  @other "org.example.Other"
  @definition %{key: :helper_v1, backend: :helper, unit: nil}
  @lost {:observation_lost, :worker_down}

  test "a proven unlaunched reservation is released without claiming name readiness" do
    waiting = waiter(1)
    {state, key} = issued(State.new(:epoch, max_live_children: 1), waiting)
    assert {:ok, state, :ok, []} = result(state, key, :not_launched)
    assert state.children == %{}
    assert state.names[@name] == key
    assert state.attempts[key].waiters[waiting.request].request == waiting.request
    refute state.attempts[key].owned
    assert state.attempts[key].backend_done
  end

  test "lost helper observation drains leases but keeps the name and global child charge" do
    waiter = waiter(1)
    {state, key} = issued(State.new(:epoch, max_live_children: 1), waiter)

    assert {:ok, state, :ok, effects} = result(state, key, {:error, @lost})
    assert effects == terminal(key, waiter, @lost) ++ [{:cancel_deadline, key}]
    assert state.children[key].phase == :uncertain
    assert state.children[key].name == @name
    assert state.children[key].definition == @definition
    assert state.children[key].token == key
    assert state.attempts[key].waiters == %{}
    refute state.attempts[key].backend_done
    assert state.names[@name] == key
    assert state.requests == %{}
    assert state.serials == %{}

    assert {:error, :attempt_unresolved, ^state} = admit(state, waiter(2))
    {state, other} = admitted(state, waiter(2, @other))
    assert {:error, :limits_exceeded, ^state} = commit(state, other)
    assert {:ok, ^state, :ignored, []} = result(state, key, {:error, @lost})
  end

  test "deadline reload and caller loss cannot reclaim an unobserved external child" do
    waiter = waiter(1)
    {state, key} = issued(State.new(:epoch, service_start_timeout: 10), waiter)
    assert {:ok, state, :ok, _effects} = result(state, key, {:error, @lost})
    child = state.children[key]

    assert {:ok, state, :ok, []} = State.transition(state, {:expire, key}, 50_000)
    assert {:ok, state, :ok, []} = State.transition(state, {:caller_down, :caller}, 50_000)
    changed = %{@definition | key: :helper_v2}

    assert {:ok, state, :ok, []} =
             State.transition(state, {:reload, 2, %{@name => changed}}, 50_000)

    assert state.children[key] == child
    assert state.names[@name] == key
    incoming = %{waiter(2) | generation: 2, definition: changed.key}

    assert {:error, :definition_changed, ^state} =
             State.transition(state, {:admit, incoming, make_ref(), changed}, 50_000)
  end

  test "verified ownership retires the name barrier but does not prove child termination" do
    {state, key} = issued(State.new(:epoch, max_live_children: 1), waiter(1))
    assert {:ok, state, :ok, _effects} = result(state, key, {:error, @lost})
    assert {:ok, state, :ok, []} = result(state, key, :owned)
    refute Map.has_key?(state.attempts, key)
    refute Map.has_key?(state.names, @name)
    assert state.children[key].phase == :uncertain
    {state, replacement} = admitted(state, waiter(2))
    assert {:error, :limits_exceeded, ^state} = commit(state, replacement)
    assert {:ok, ^state, :ignored, []} = result(state, key, {:error, @lost})
    assert {:ok, ^state, :ignored, []} = result(state, {:old_epoch, elem(key, 1)}, {:exited, 0})

    for late <- [{:exited, 0}, {:exited, 137}, {:signaled, 9}, {:error, :late_error}] do
      assert {:ok, ^state, :ignored, []} = result(state, key, late)
    end
  end

  test "ownership before observer loss preserves the retired child's slot under name churn" do
    first = waiter(1)
    {state, key} = issued(State.new(:epoch, max_live_children: 1), first)

    assert {:ok, state, :ok, [{:resolve_waiter, ^key, request}]} =
             State.transition(state, {:name_available, @name}, 100)

    assert request == first.request

    assert {:ok, state, :ok, _effects} =
             State.transition(state, {:finish_waiter, key, request, :delivered}, 100)

    refute Map.has_key?(state.attempts, key)
    assert {:ok, state, :ok, []} = result(state, key, {:error, @lost})
    assert state.children[key].phase == :uncertain
    {state, replacement} = admitted(state, waiter(2))
    assert {:error, :limits_exceeded, ^state} = commit(state, replacement)
  end

  test "a loss notification without a reserved child cannot erase an unissued waiter" do
    {state, key} = admitted(State.new(:epoch, []), waiter(1))
    assert {:ok, ^state, :ignored, []} = result(state, key, {:error, @lost})
    assert {:ok, ^state, :ignored, []} = result(state, {:epoch, make_ref()}, {:error, @lost})
  end

  test "uncertain observation keeps a resolving waiter charged until each exact Router outcome" do
    for completion <- [:delivered, :retry, {:terminal, @lost}] do
      waiting = waiter(1)

      {state, key} =
        issued(State.new(:epoch, max_live_children: 1, max_pending_service_starts: 1), waiting)

      assert {:ok, state, :ok, [{:resolve_waiter, ^key, request}]} =
               State.transition(state, {:name_available, @name}, 100)

      assert request == waiting.request
      assert {:ok, state, :ok, [{:cancel_deadline, ^key}]} = result(state, key, {:error, @lost})
      assert state.attempts[key].waiters[request].pending_terminal == @lost
      assert state.requests[request] == key
      assert state.serials[waiting.serial] == request
      assert state.children[key].phase == :uncertain

      assert {:error, :limits_exceeded, ^state} = admit(state, waiter(2, @other))

      assert {:ok, state, :ok, effects} =
               State.transition(state, {:finish_waiter, key, request, completion}, 100)

      assert effects ==
               if(completion == :delivered,
                 do: [{:release_lease, request, waiting.lease}],
                 else: terminal(key, waiting, @lost)
               )

      assert state.requests == %{}
      assert state.serials == %{}
      assert state.children[key].phase == :uncertain

      assert {:ok, ^state, :ignored, []} =
               State.transition(state, {:finish_waiter, key, request, completion}, 101)

      if completion == :delivered do
        refute Map.has_key?(state.names, @name)
      else
        assert state.names[@name] == key
      end
    end
  end

  test "an observed actual signal is terminal and frees exactly the original slot" do
    waiter = waiter(1)
    {state, key} = issued(State.new(:epoch, max_live_children: 1), waiter)
    assert {:ok, state, :ok, effects} = result(state, key, {:signaled, 9})
    assert effects == terminal(key, waiter, {:backend_signaled, 9}) ++ [{:cancel_deadline, key}]
    assert state.children == %{}
    assert {:ok, ^state, :ignored, []} = result(state, key, {:signaled, 9})
    {state, replacement} = issued(state, waiter(2))
    assert replacement != key
    assert {:ok, ^state, :ignored, []} = result(state, key, {:exited, 0})
    assert state.children[replacement].phase == :reserved
  end

  defp result(state, key, value),
    do: State.transition(state, {:backend_result, key, value}, 100)

  defp commit(state, key), do: State.transition(state, {:commit_issue, key, 1}, 100)

  defp admit(state, waiter),
    do: State.transition(state, {:admit, waiter, make_ref(), @definition}, 100)

  defp admitted(state, waiter) do
    assert {:ok, state, {:admitted, key}, _effects} = admit(state, waiter)
    {state, key}
  end

  defp issued(state, waiter) do
    {state, key} = admitted(state, waiter)
    assert {:ok, state, :issued, [{:launch, ^key, @definition}]} = commit(state, key)
    {state, key}
  end

  defp terminal(key, waiter, reason),
    do: [
      {:terminal_waiter, key, waiter.request, reason},
      {:release_lease, waiter.request, waiter.lease}
    ]

  defp waiter(serial, name \\ @name),
    do: %{
      caller: self(),
      caller_incarnation: :caller,
      request: {:epoch, make_ref()},
      serial: {:epoch, :caller, serial},
      kind: :automatic,
      message_type: :method_call,
      flags: 0,
      destination: name,
      generation: 1,
      definition: @definition.key,
      deadline: 100_000,
      lease: make_ref()
    }
end
