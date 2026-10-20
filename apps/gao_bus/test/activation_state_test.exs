defmodule GaoBus.Activation.StateTest do
  use ExUnit.Case, async: true

  @name "org.example.Activated"
  @other_name "org.example.Other"

  defp new(options \\ []) do
    apply(GaoBus.Activation.State, :new, [:epoch, options])
  end

  defp transition(state, event, now \\ 100) do
    apply(GaoBus.Activation.State, :transition, [state, event, now])
  end

  defp definition(overrides \\ %{}) do
    Map.merge(%{key: {:source_hash, "v1"}, backend: :helper, unit: nil}, overrides)
  end

  defp waiter(serial, overrides \\ %{}) do
    Map.merge(
      %{
        caller: self(),
        caller_incarnation: :caller,
        request: {:epoch, make_ref()},
        serial: {:epoch, :caller, serial},
        kind: :automatic,
        message_type: :method_call,
        flags: 0,
        destination: @name,
        generation: 1,
        definition: definition().key,
        deadline: 100_000,
        lease: make_ref()
      },
      overrides
    )
  end

  defp admit!(state, waiter, selected \\ definition(), now \\ 100) do
    assert {:ok, next, {:admitted, key}, effects} =
             transition(state, {:admit, waiter, make_ref(), selected}, now)

    {next, key, effects}
  end

  defp commit!(state, key, now \\ 100) do
    assert {:ok, next, :issued, [{:launch, ^key, selected}]} =
             transition(state, {:commit_issue, key, 1}, now)

    {next, selected}
  end

  defp terminal_effects(key, waiter, reason) do
    [
      {:terminal_waiter, key, waiter.request, reason},
      {:release_lease, waiter.request, waiter.lease}
    ]
  end

  test "first admission fixes the attempt deadline and requests ordered launch commit" do
    waiting = waiter(1)
    {state, key, effects} = admit!(new(), waiting)

    assert {:epoch, reference} = key
    assert is_reference(reference)
    assert effects == [{:arm_deadline, key, 25_100}, {:request_launch_commit, key}]

    {issued, selected} = commit!(state, key)
    assert selected == definition()
    assert {:ok, ^issued, :ignored, []} = transition(issued, {:commit_issue, key, 1})
  end

  test "joining callers cannot extend the first deadline and each join consumes capacity" do
    first = waiter(1)
    {state, key, _effects} = admit!(new(max_pending_service_starts: 2), first)
    {state, ^key, []} = admit!(state, waiter(2), definition(), 20_000)

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(3), make_ref(), definition()}, 20_001)

    assert {:ok, state, :ok, []} = transition(state, {:expire, key}, 25_099)
    assert {:ok, _state, :ok, effects} = transition(state, {:expire, key}, 25_100)
    assert {:terminal_waiter, key, first.request, :timed_out} in effects
  end

  test "the reference default counts 512 waiting entries rather than names" do
    state =
      Enum.reduce(1..512, new(), fn serial, state ->
        {next, _key, _effects} = admit!(state, waiter(serial))
        next
      end)

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(513), make_ref(), definition()})
  end

  test "zero pending entries admits neither automatic nor explicit traffic" do
    state = new(max_pending_service_starts: 0)

    for kind <- [:automatic, :explicit] do
      assert {:error, :limits_exceeded, ^state} =
               transition(state, {:admit, waiter(1, %{kind: kind}), make_ref(), definition()})
    end
  end

  test "explicit starts directed signals and no-reply calls all consume waiter entries" do
    state = new(max_pending_service_starts: 3)
    {state, key, _effects} = admit!(state, waiter(1, %{kind: :explicit}))
    {state, ^key, []} = admit!(state, waiter(2, %{message_type: :signal}))
    {state, ^key, []} = admit!(state, waiter(3, %{flags: 0x1}))

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(4), make_ref(), definition()})
  end

  test "NO_AUTO_START forbids automatic launch and join but explicit start is unaffected" do
    state = new()
    forbidden = waiter(1, %{flags: 0x2})

    assert {:error, :no_auto_start, ^state} =
             transition(state, {:admit, forbidden, make_ref(), definition()})

    {state, key, _effects} = admit!(state, waiter(2))

    assert {:error, :no_auto_start, ^state} =
             transition(state, {:admit, forbidden, make_ref(), definition()})

    {state, ^key, []} = admit!(state, waiter(3, %{kind: :explicit, flags: 0x3}))
    forbidden_signal = waiter(4, %{message_type: :signal, flags: 0x2})

    assert {:error, :no_auto_start, ^state} =
             transition(state, {:admit, forbidden_signal, make_ref(), definition()})
  end

  test "duplicate serial preserves the original request and lease" do
    first = waiter(1)
    {state, key, _effects} = admit!(new(), first)
    duplicate = waiter(1)

    assert {:error, :duplicate_serial, ^state} =
             transition(state, {:admit, duplicate, make_ref(), definition()})

    assert {:ok, _state, :ok, effects} =
             transition(state, {:finish_waiter, key, first.request, {:terminal, :denied}})

    assert {:release_lease, first.request, first.lease} in effects
    refute {:release_lease, duplicate.request, duplicate.lease} in effects
  end

  test "duplicate request identity cannot replace an existing lease" do
    first = waiter(1)
    {state, _key, _effects} = admit!(new(), first)
    duplicate = waiter(2, %{request: first.request})

    assert {:error, :duplicate_request, ^state} =
             transition(state, {:admit, duplicate, make_ref(), definition()})
  end

  test "request and serial identities reject a foreign epoch without effects" do
    state = new()

    for invalid <- [
          waiter(1, %{request: {:old_epoch, make_ref()}}),
          waiter(1, %{serial: {:old_epoch, :caller, 1}}),
          waiter(1, %{serial: {:epoch, :different_caller, 1}})
        ] do
      assert {:error, :invalid_identity, ^state} =
               transition(state, {:admit, invalid, make_ref(), definition()})
    end
  end

  test "serial reuse by a new caller incarnation is independent" do
    {state, key, _effects} = admit!(new(), waiter(1))
    other = waiter(1, %{caller_incarnation: :new_caller, serial: {:epoch, :new_caller, 1}})
    {_state, ^key, []} = admit!(state, other)
  end

  test "a waiter with an expired deadline is rejected at the exact boundary" do
    state = new()
    expired = waiter(1, %{deadline: 100})

    assert {:error, :deadline_expired, ^state} =
             transition(state, {:admit, expired, make_ref(), definition()}, 100)
  end

  test "zero service timeout expires literally before any launch commit" do
    waiting = waiter(1)
    {state, key, effects} = admit!(new(service_start_timeout: 0), waiting)
    assert effects == [{:arm_deadline, key, 100}, {:request_launch_commit, key}]
    assert {:ok, _state, :ok, effects} = transition(state, {:commit_issue, key, 1}, 100)
    assert effects == terminal_effects(key, waiting, :timed_out) ++ [{:cancel_deadline, key}]
  end

  test "launch commit checks the deadline even when its timer event has not arrived" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(), waiting)
    assert {:ok, state, :ok, effects} = transition(state, {:commit_issue, key, 1}, 25_100)
    assert effects == terminal_effects(key, waiting, :timed_out) ++ [{:cancel_deadline, key}]
    assert {:ok, ^state, :ignored, []} = transition(state, {:expire, key}, 25_101)
  end

  test "an earlier waiter deadline rearms the timer without extending the attempt" do
    first = waiter(1)
    second = waiter(2, %{deadline: 500})
    {state, key, _effects} = admit!(new(), first)
    {state, ^key, effects} = admit!(state, second)
    assert effects == [{:arm_deadline, key, 500}]
    assert {:ok, state, :ok, []} = transition(state, {:expire, key}, 499)
    assert {:ok, state, :ok, effects} = transition(state, {:expire, key}, 500)
    assert effects == terminal_effects(key, second, :timed_out) ++ [{:arm_deadline, key, 25_100}]
    assert {:ok, _state, :ok, effects} = transition(state, {:expire, key}, 25_100)
    assert {:terminal_waiter, key, first.request, :timed_out} in effects
  end

  test "name availability schedules ordered resolution once and keeps capacity charged" do
    first = waiter(1)
    second = waiter(2)
    {state, key, _effects} = admit!(new(max_pending_service_starts: 2), first)
    {state, ^key, []} = admit!(state, second)
    assert {:ok, state, :ok, effects} = transition(state, {:name_available, @name})

    assert effects == [
             {:resolve_waiter, key, first.request},
             {:resolve_waiter, key, second.request}
           ]

    assert {:ok, ^state, :ok, []} = transition(state, {:name_available, @name})

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(3), make_ref(), definition()})

    assert {:ok, state, :ok, [{:release_lease, request, lease}]} =
             transition(state, {:finish_waiter, key, first.request, :delivered})

    assert {request, lease} == {first.request, first.lease}
    {_state, ^key, []} = admit!(state, waiter(3))
  end

  test "a lost owner leaves the waiter charged and permits a later resolution hint" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(max_pending_service_starts: 1), waiting)

    assert {:ok, state, :ok, [{:resolve_waiter, ^key, request}]} =
             transition(state, {:name_available, @name})

    assert request == waiting.request

    assert {:ok, state, :ok, []} =
             transition(state, {:finish_waiter, key, waiting.request, :retry})

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(2), make_ref(), definition()})

    assert {:ok, _state, :ok, [{:resolve_waiter, ^key, ^request}]} =
             transition(state, {:name_available, @name})
  end

  test "a name hint at the waiter deadline expires instead of resolving" do
    waiting = waiter(1, %{deadline: 500})
    {state, key, _effects} = admit!(new(), waiting)
    assert {:ok, _state, :ok, effects} = transition(state, {:name_available, @name}, 500)
    assert {:terminal_waiter, key, waiting.request, :timed_out} in effects
    refute {:resolve_waiter, key, waiting.request} in effects
  end

  test "exact completion releases a lease once and foreign request or attempt cannot retire it" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(), waiting)

    for event <- [
          {:finish_waiter, {:epoch, make_ref()}, waiting.request, :delivered},
          {:finish_waiter, key, {:epoch, make_ref()}, :delivered},
          {:finish_waiter, {:old_epoch, elem(key, 1)}, waiting.request, :delivered},
          {:finish_waiter, key, {:old_epoch, elem(waiting.request, 1)}, :delivered},
          {:expire, {:old_epoch, elem(key, 1)}},
          {:backend_result, {:epoch, make_ref()}, {:error, :failed}},
          {:commit_issue, {:epoch, make_ref()}, 1}
        ] do
      assert {:ok, ^state, :ignored, []} = transition(state, event)
    end

    assert {:ok, state, :ok, effects} =
             transition(state, {:finish_waiter, key, waiting.request, {:terminal, :denied}})

    assert effects == terminal_effects(key, waiting, :denied) ++ [{:cancel_deadline, key}]

    assert {:ok, ^state, :ignored, []} =
             transition(state, {:finish_waiter, key, waiting.request, :delivered})
  end

  test "caller death removes only that incarnation and cancels unissued last-waiter work" do
    first = waiter(1)
    other = waiter(2, %{caller_incarnation: :other, serial: {:epoch, :other, 2}})
    {state, key, _effects} = admit!(new(), first)
    {state, ^key, []} = admit!(state, other)
    assert {:ok, state, :ok, effects} = transition(state, {:caller_down, :caller})
    assert effects == terminal_effects(key, first, :caller_down)
    assert {:ok, state, :ok, effects} = transition(state, {:caller_down, :other})
    assert effects == terminal_effects(key, other, :caller_down) ++ [{:cancel_deadline, key}]
    assert {:ok, ^state, :ignored, []} = transition(state, {:commit_issue, key, 1})
    {_state, replacement, _effects} = admit!(state, waiter(1))
    refute replacement == key
  end

  test "issued helper cancellation retains a bounded per-name child tombstone until exit" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(max_attempts: 1, max_live_children: 1), waiting)
    {state, _selected} = commit!(state, key)
    assert {:ok, state, :ok, effects} = transition(state, {:caller_down, :caller})
    assert effects == terminal_effects(key, waiting, :caller_down) ++ [{:cancel_deadline, key}]

    assert {:error, :attempt_unresolved, ^state} =
             transition(state, {:admit, waiter(2), make_ref(), definition()})

    assert {:error, :limits_exceeded, ^state} =
             transition(
               state,
               {:admit, waiter(3, %{destination: @other_name}), make_ref(), definition()}
             )

    assert {:ok, state, :ok, []} = transition(state, {:backend_result, key, {:exited, 0}})
    {_state, replacement, _effects} = admit!(state, waiter(2))
    refute replacement == key
  end

  test "successful helper exit is not readiness and waiting persists until name resolution" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(max_pending_service_starts: 1), waiting)
    {state, _selected} = commit!(state, key)
    assert {:ok, state, :ok, []} = transition(state, {:backend_result, key, {:exited, 0}})

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:admit, waiter(2), make_ref(), definition()})

    assert {:ok, _state, :ok, [{:resolve_waiter, ^key, request}]} =
             transition(state, {:name_available, @name})

    assert request == waiting.request
  end

  test "name readiness cannot release a still-live helper child budget" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(max_live_children: 1), waiting)
    {state, _selected} = commit!(state, key)
    assert {:ok, state, :ok, _effects} = transition(state, {:name_available, @name})

    assert {:ok, state, :ok, _effects} =
             transition(state, {:finish_waiter, key, waiting.request, :delivered})

    {state, other_key, _effects} = admit!(state, waiter(2, %{destination: @other_name}))
    assert {:error, :limits_exceeded, ^state} = transition(state, {:commit_issue, other_key, 1})
    assert {:ok, state, :ok, []} = transition(state, {:backend_result, key, {:exited, 0}})
    {_state, _selected} = commit!(state, other_key)
  end

  test "verified ownership releases the per-name blocker while retaining the live child" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(max_live_children: 1), waiting)
    {state, _selected} = commit!(state, key)
    assert {:ok, state, :ok, _effects} = transition(state, {:caller_down, :caller})
    assert {:ok, state, :ok, []} = transition(state, {:backend_result, key, :owned})
    {state, replacement, _effects} = admit!(state, waiter(2))
    refute replacement == key

    assert {:error, :limits_exceeded, ^state} =
             transition(state, {:commit_issue, replacement, 1})

    assert {:ok, state, :ok, []} = transition(state, {:backend_result, key, {:exited, 0}})
    {_state, _selected} = commit!(state, replacement)
  end

  test "backend errors retire waiters once with exact structured reasons" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(), waiting)
    {state, _selected} = commit!(state, key)
    reason = {:spawn_failed, :eacces}

    assert {:ok, state, :ok, effects} =
             transition(state, {:backend_result, key, {:error, reason}})

    assert effects == terminal_effects(key, waiting, reason) ++ [{:cancel_deadline, key}]

    assert {:ok, ^state, :ignored, []} =
             transition(state, {:backend_result, key, {:error, reason}})
  end

  test "nonzero helper exit terminates rather than reporting readiness" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(), waiting)
    {state, _selected} = commit!(state, key)

    assert {:ok, _state, :ok, effects} =
             transition(state, {:backend_result, key, {:exited, 7}})

    assert {:terminal_waiter, key, waiting.request, {:backend_failed, 7}} in effects
    refute {:resolve_waiter, key, waiting.request} in effects
  end

  test "separate attempt and unit bounds reject new records while permitting same-unit joins" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    {state, _key, _effects} = admit!(new(max_attempts: 2, max_units: 1), waiter(1), selected)

    {state, _other_key, _effects} =
      admit!(state, waiter(2, %{destination: @other_name}), selected)

    assert {:error, :limits_exceeded, ^state} =
             transition(
               state,
               {:admit, waiter(3, %{destination: "org.example.Third"}), make_ref(), selected}
             )

    {unit_state, _key, _effects} = admit!(new(max_units: 1), waiter(1), selected)
    other_unit = %{selected | unit: "other.service", key: {:source_hash, "other"}}

    assert {:error, :limits_exceeded, ^unit_state} =
             transition(
               unit_state,
               {:admit, waiter(2, %{destination: @other_name, definition: other_unit.key}),
                make_ref(), other_unit}
             )
  end

  test "a shared systemd unit launches once and each destination resolves independently" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    first = waiter(1)
    second = waiter(2, %{destination: @other_name})
    {state, first_key, _effects} = admit!(new(), first, selected)
    {state, second_key, _effects} = admit!(state, second, selected)
    {state, ^selected} = commit!(state, first_key)
    assert {:ok, state, :coalesced, []} = transition(state, {:commit_issue, second_key, 1})

    assert {:ok, state, :ok, [{:resolve_waiter, ^first_key, request}]} =
             transition(state, {:name_available, @name})

    assert request == first.request

    assert {:ok, state, :ok, _effects} =
             transition(state, {:finish_waiter, first_key, first.request, :delivered})

    assert {:ok, _state, :ok, [{:resolve_waiter, ^second_key, request}]} =
             transition(state, {:name_available, @other_name})

    assert request == second.request
  end

  test "empty issued systemd tombstone keeps its fixed deadline then permits a fresh launch" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    waiting = waiter(1)
    options = [service_start_timeout: 400, max_attempts: 1, max_units: 1]
    {state, key, _effects} = admit!(new(options), waiting, selected, 100)
    {state, ^selected} = commit!(state, key, 100)
    assert {:ok, state, :ok, effects} = transition(state, {:caller_down, :caller}, 200)
    assert effects == terminal_effects(key, waiting, :caller_down)
    assert state.attempts[key].waiters == %{}
    assert state.attempts[key].deadline == 500
    assert state.attempts[key].timer_deadline == 500
    assert state.units[{:epoch, selected.unit}].attempts == MapSet.new([key])
    assert state.requests == %{}
    assert state.serials == %{}
    assert state.children == %{}

    incoming = waiter(2)

    assert {:error, :attempt_unresolved, ^state} =
             transition(state, {:admit, incoming, make_ref(), selected}, 499)

    assert {:ok, ^state, :ok, []} = transition(state, {:name_available, @name}, 250)
    refute state.attempts[key].owned
    assert {:ok, ^state, :ok, []} = transition(state, {:expire, key}, 499)
    assert {:ok, state, :ok, effects} = transition(state, {:expire, key}, 500)
    assert effects == [{:cancel_deadline, key}]
    assert state.attempts == %{}
    assert state.units == %{}
    assert state.names == %{}
    assert {:ok, ^state, :ignored, []} = transition(state, {:expire, key}, 500)

    {state, replacement, _effects} = admit!(state, incoming, selected, 500)
    refute replacement == key
    {state, ^selected} = commit!(state, replacement, 500)
    assert state.attempts[replacement].deadline == 900
    assert {:ok, ^state, :ignored, []} = transition(state, {:expire, key}, 900)

    assert {:ok, ^state, :ignored, []} =
             transition(state, {:backend_result, key, {:error, :late_failure}}, 900)
  end

  test "issued systemd timeout with a live waiter retires its unit at the exact deadline" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    waiting = waiter(1)

    {state, key, _effects} =
      admit!(
        new(service_start_timeout: 400, max_attempts: 1, max_units: 1),
        waiting,
        selected,
        100
      )

    {state, ^selected} = commit!(state, key, 100)
    assert {:ok, ^state, :ok, []} = transition(state, {:expire, key}, 499)
    assert {:ok, state, :ok, effects} = transition(state, {:expire, key}, 500)
    assert effects == terminal_effects(key, waiting, :timed_out) ++ [{:cancel_deadline, key}]
    assert state.attempts == %{}
    assert state.units == %{}
    assert state.names == %{}
    assert state.requests == %{}
    assert state.serials == %{}
    assert state.children == %{}
    assert {:ok, ^state, :ignored, []} = transition(state, {:expire, key}, 501)

    assert {:ok, ^state, :ignored, []} =
             transition(
               state,
               {:finish_waiter, key, waiting.request, {:terminal, :timed_out}},
               501
             )

    {state, replacement, _effects} = admit!(state, waiter(2), selected, 500)
    refute replacement == key
    {_state, ^selected} = commit!(state, replacement, 500)
  end

  test "shared systemd tombstone expiry preserves the other member until its own deadline" do
    selected = definition(%{backend: :systemd, unit: "example.service"})

    for retirement <- [:caller_down, :earlier_timeout] do
      first = waiter(1, %{deadline: 300})

      second =
        waiter(2, %{
          destination: @other_name,
          caller_incarnation: :other,
          serial: {:epoch, :other, 2}
        })

      {state, first_key, _effects} =
        admit!(
          new(service_start_timeout: 400, max_attempts: 2, max_units: 1),
          first,
          selected,
          100
        )

      {state, second_key, _effects} = admit!(state, second, selected, 200)
      {state, ^selected} = commit!(state, first_key, 200)

      assert {:ok, state, :coalesced, []} =
               transition(state, {:commit_issue, second_key, 1}, 200)

      assert state.attempts[second_key].deadline == 500

      {event, now, reason} =
        case retirement do
          :caller_down -> {{:caller_down, :caller}, 200, :caller_down}
          :earlier_timeout -> {{:expire, first_key}, 300, :timed_out}
        end

      assert {:ok, state, :ok, effects} = transition(state, event, now)

      assert effects ==
               terminal_effects(first_key, first, reason) ++
                 [{:arm_deadline, first_key, 500}]

      assert state.attempts[first_key].waiters == %{}
      assert state.attempts[first_key].timer_deadline == 500
      assert Map.has_key?(state.attempts[second_key].waiters, second.request)
      assert state.units[{:epoch, selected.unit}].attempts == MapSet.new([first_key, second_key])
      assert {:ok, ^state, :ok, []} = transition(state, {:expire, first_key}, 499)
      assert {:ok, ^state, :ok, []} = transition(state, {:expire, second_key}, 499)

      assert {:ok, state, :ok, [{:cancel_deadline, ^first_key}]} =
               transition(state, {:expire, first_key}, 500)

      refute Map.has_key?(state.attempts, first_key)
      assert Map.has_key?(state.attempts[second_key].waiters, second.request)
      assert state.units[{:epoch, selected.unit}].attempts == MapSet.new([second_key])
      assert {:ok, ^state, :ignored, []} = transition(state, {:expire, first_key}, 500)

      assert {:ok, state, :ok, effects} = transition(state, {:expire, second_key}, 500)

      assert effects ==
               terminal_effects(second_key, second, :timed_out) ++
                 [{:cancel_deadline, second_key}]

      assert state.attempts == %{}
      assert state.units == %{}
      assert state.requests == %{}
      assert state.serials == %{}
      assert state.children == %{}
      assert {:ok, ^state, :ignored, []} = transition(state, {:expire, second_key}, 501)
      {state, fresh_key, _effects} = admit!(state, waiter(3), selected, 500)
      {_state, ^selected} = commit!(state, fresh_key, 500)
    end
  end

  test "systemd backend failure applies to every pending name of the same unit" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    first = waiter(1)
    second = waiter(2, %{destination: @other_name})
    {state, first_key, _effects} = admit!(new(), first, selected)
    {state, second_key, _effects} = admit!(state, second, selected)
    {state, _selected} = commit!(state, first_key)
    assert {:ok, state, :coalesced, []} = transition(state, {:commit_issue, second_key, 1})
    reason = {:systemd_failure, "org.freedesktop.DBus.Error.Spawn.Failed", "missing unit"}

    assert {:ok, _state, :ok, effects} =
             transition(state, {:backend_result, first_key, {:error, reason}})

    assert {:terminal_waiter, first_key, first.request, reason} in effects
    assert {:terminal_waiter, second_key, second.request, reason} in effects
  end

  test "policy-only reload preserves semantic definitions and requires current launch commit" do
    waiting = waiter(1)
    {state, key, _effects} = admit!(new(), waiting)

    assert {:ok, state, :ok, [{:request_launch_commit, ^key}]} =
             transition(state, {:reload, 2, %{@name => definition()}})

    assert {:error, :stale_generation, ^state} = transition(state, {:commit_issue, key, 1})

    assert {:ok, _state, :issued, [{:launch, ^key, selected}]} =
             transition(state, {:commit_issue, key, 2})

    assert selected == definition()
  end

  test "reload cannot retarget an unissued launch to a changed or removed definition" do
    for definitions <- [%{@name => definition(%{key: {:source_hash, "v2"}})}, %{}] do
      waiting = waiter(1)
      {state, key, _effects} = admit!(new(), waiting)

      assert {:ok, state, :ok, [{:request_launch_commit, ^key}]} =
               transition(state, {:reload, 2, definitions})

      assert {:ok, _state, :ok, effects} = transition(state, {:commit_issue, key, 2})

      assert effects ==
               terminal_effects(key, waiting, :definition_changed) ++ [{:cancel_deadline, key}]
    end
  end

  test "reload pins issued definitions and refuses a changed definition behind unresolved work" do
    {state, key, _effects} = admit!(new(), waiter(1))
    {state, _selected} = commit!(state, key)
    changed = definition(%{key: {:source_hash, "v2"}})
    assert {:ok, state, :ok, []} = transition(state, {:reload, 2, %{@name => changed}})
    incoming = waiter(2, %{generation: 2, definition: changed.key})

    assert {:error, :definition_changed, ^state} =
             transition(state, {:admit, incoming, make_ref(), changed})

    assert {:ok, ^state, :ignored, []} = transition(state, {:commit_issue, key, 2})
  end

  test "stale reload leaves current generation and its selected definitions unchanged" do
    {state, key, _effects} = admit!(new(), waiter(1))
    assert {:ok, state, :ok, _effects} = transition(state, {:reload, 2, %{@name => definition()}})
    assert {:ok, ^state, :ignored, []} = transition(state, {:reload, 1, %{}})
    assert {:ok, _state, :issued, _effects} = transition(state, {:commit_issue, key, 2})
  end

  test "later names share the unresolved unit deadline and cannot extend or join its expired launch" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    {state, first_key, _effects} = admit!(new(), waiter(1), selected, 100)
    {state, _selected} = commit!(state, first_key, 100)
    second = waiter(2, %{destination: @other_name})
    {state, second_key, effects} = admit!(state, second, selected, 20_000)
    assert effects == [{:arm_deadline, second_key, 25_100}, {:request_launch_commit, second_key}]
    assert state.attempts[second_key].deadline == 25_100
    assert state.attempts[second_key].waiters[second.request].deadline == 25_100

    assert {:ok, state, :ok, effects} =
             transition(state, {:commit_issue, second_key, 1}, 25_100)

    assert effects ==
             terminal_effects(second_key, second, :timed_out) ++ [{:cancel_deadline, second_key}]

    third = waiter(3, %{destination: "org.example.Third"})

    assert {:error, :deadline_expired, ^state} =
             transition(state, {:admit, third, make_ref(), selected}, 25_100)

    assert {:ok, ^state, :ignored, []} =
             transition(state, {:commit_issue, second_key, 1}, 25_101)
  end

  test "PID1 ownership waiting commits without external launch or child charge and retires normally" do
    name = "org.freedesktop.systemd1"
    selected = definition(%{backend: :wait, key: {:source_hash, "systemd1"}})
    waiting = waiter(1, %{destination: name, definition: selected.key})

    for outcome <- [:timeout, :name] do
      {state, key, _effects} = admit!(new(max_live_children: 1), waiting, selected)
      assert {:ok, state, :waiting, []} = transition(state, {:commit_issue, key, 1})
      assert {:ok, ^state, :ignored, []} = transition(state, {:commit_issue, key, 1})
      {state, helper_key, _effects} = admit!(state, waiter(2, %{destination: @other_name}))
      {state, _selected} = commit!(state, helper_key)

      state =
        case outcome do
          :timeout ->
            assert {:ok, next, :ok, effects} = transition(state, {:expire, key}, 25_100)

            assert effects ==
                     terminal_effects(key, waiting, :timed_out) ++ [{:cancel_deadline, key}]

            next

          :name ->
            assert {:ok, next, :ok, [{:resolve_waiter, ^key, request}]} =
                     transition(state, {:name_available, name})

            assert request == waiting.request

            assert {:ok, next, :ok, effects} =
                     transition(next, {:finish_waiter, key, waiting.request, :delivered})

            assert effects == [
                     {:release_lease, waiting.request, waiting.lease},
                     {:cancel_deadline, key}
                   ]

            next
        end

      assert {:ok, ^state, :ignored, []} = transition(state, {:commit_issue, key, 1})
      {_state, replacement, _effects} = admit!(state, waiting, selected, 25_101)
      refute replacement == key
    end
  end

  test "terminal events retain resolving waiter charge until exact Router completion" do
    for trigger <- [:timeout, :caller_down, :backend_failure],
        outcome <- [:delivered, :terminal, :retry] do
      waiting = waiter(1)
      {state, key, _effects} = admit!(new(max_pending_service_starts: 1), waiting)
      {state, _selected} = commit!(state, key)

      assert {:ok, state, :ok, [{:resolve_waiter, ^key, request}]} =
               transition(state, {:name_available, @name})

      assert request == waiting.request

      {event, now, reason} =
        case trigger do
          :timeout -> {{:expire, key}, 25_100, :timed_out}
          :caller_down -> {{:caller_down, :caller}, 100, :caller_down}
          :backend_failure -> {{:backend_result, key, {:error, :failed}}, 100, :failed}
        end

      assert {:ok, state, :ok, [{:cancel_deadline, ^key}]} = transition(state, event, now)

      assert {:error, :limits_exceeded, ^state} =
               transition(
                 state,
                 {:admit, waiter(2, %{destination: @other_name}), make_ref(), definition()},
                 now
               )

      assert {:ok, ^state, :ok, []} = transition(state, {:expire, key}, 25_101)
      assert {:ok, ^state, :ok, []} = transition(state, {:name_available, @name}, 25_101)

      completion = if outcome == :terminal, do: {:terminal, reason}, else: outcome

      assert {:ok, state, :ok, effects} =
               transition(state, {:finish_waiter, key, waiting.request, completion}, 25_102)

      expected =
        if outcome == :delivered do
          [{:release_lease, waiting.request, waiting.lease}]
        else
          terminal_effects(key, waiting, reason)
        end

      assert effects == expected

      assert {:ok, ^state, :ignored, []} =
               transition(state, {:finish_waiter, key, waiting.request, completion}, 25_103)
    end
  end

  test "a failed shared unit refuses new names until pending Router completions drain" do
    selected = definition(%{backend: :systemd, unit: "example.service"})
    first = waiter(1)
    {state, key, _effects} = admit!(new(), first, selected)
    {state, _selected} = commit!(state, key)

    assert {:ok, state, :ok, [{:resolve_waiter, ^key, request}]} =
             transition(state, {:name_available, @name})

    assert request == first.request

    assert {:ok, state, :ok, [{:cancel_deadline, ^key}]} =
             transition(state, {:backend_result, key, {:error, :failed}})

    incoming = waiter(2, %{destination: @other_name})

    assert {:error, :attempt_unresolved, ^state} =
             transition(state, {:admit, incoming, make_ref(), selected}, 200)

    assert {:ok, state, :ok, effects} =
             transition(state, {:finish_waiter, key, first.request, {:terminal, :failed}}, 200)

    assert effects == terminal_effects(key, first, :failed)

    fresh = waiter(3, %{destination: @other_name})
    {state, fresh_key, effects} = admit!(state, fresh, selected, 200)
    refute fresh_key == key
    assert effects == [{:arm_deadline, fresh_key, 25_200}, {:request_launch_commit, fresh_key}]
    {_state, ^selected} = commit!(state, fresh_key, 200)
  end
end
