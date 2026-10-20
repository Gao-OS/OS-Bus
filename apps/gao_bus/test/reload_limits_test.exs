defmodule GaoBus.ReloadLimitsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  setup do
    %{limits: start_supervised!({Limits, name: nil})}
  end

  test "one global reload reservation is independent of wire queue credits", %{limits: limits} do
    assert {:ok, before} = Limits.snapshot(limits)
    assert {:ok, token} = Limits.reserve_reload(self(), 5000, limits)
    assert {:ok, during} = Limits.snapshot(limits)
    assert during.reload_reservations == 1
    assert during.global == before.global
    assert during.peers == before.peers
    assert during.reservations == 0
    assert {:error, :reload_busy} = Limits.reserve_reload(self(), 5000, limits)
    assert {:ok, deadline} = Limits.claim_reload(token, self(), limits)
    assert deadline > System.monotonic_time(:millisecond)
    assert {:error, :reload_already_claimed} = Limits.claim_reload(token, self(), limits)
    assert :ok = Limits.release_reload(token, limits)
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot(limits)
  end

  test "stale and duplicate releases cannot retire a later reservation", %{limits: limits} do
    assert {:ok, first} = Limits.reserve_reload(self(), 5000, limits)
    assert :ok = Limits.release_reload(first, limits)
    assert {:ok, second} = Limits.reserve_reload(self(), 5000, limits)
    assert :ok = Limits.release_reload(first, limits)
    assert :ok = Limits.release_reload(make_ref(), limits)
    send(limits, {:reload_expiry, first})
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot(limits)
    assert {:ok, _deadline} = Limits.claim_reload(second, self(), limits)
    assert :ok = Limits.release_reload(second, limits)
  end

  test "expiry rejects late claims while retaining credit for coordinator cleanup", %{
    limits: limits
  } do
    assert {:ok, token} = Limits.reserve_reload(self(), 1, limits)
    assert_receive {:reload_timeout, ^token}, 1000
    assert {:error, :reload_timeout} = Limits.claim_reload(token, self(), limits)
    assert {:error, :reload_busy} = Limits.reserve_reload(self(), 5000, limits)
    assert :ok = Limits.release_reload(token, limits)
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot(limits)
  end

  test "owner death reclaims its epoch reservation without touching newer work", %{limits: limits} do
    owner = start_supervised!({Task, fn -> receive do: (:stop -> :ok) end}, id: make_ref())
    assert {:ok, token} = Limits.reserve_reload(owner, 5000, limits)
    assert {:error, :reload_not_owner} = Limits.claim_reload(token, self(), limits)
    assert {:error, :reload_not_owner} = Limits.release_reload(token, limits)
    monitor = Process.monitor(owner)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}
    await_empty(limits, System.monotonic_time(:millisecond) + 1000)
    assert {:ok, next} = Limits.reserve_reload(self(), 5000, limits)
    assert :ok = Limits.release_reload(token, limits)
    assert {:ok, _} = Limits.claim_reload(next, self(), limits)
    assert :ok = Limits.release_reload(next, limits)
  end

  test "invalid owners and nonfinite deadlines allocate nothing", %{limits: limits} do
    assert {:error, :invalid_reload_owner} = Limits.reserve_reload(:absent, 5000, limits)

    for timeout <- [0, -1, :infinity, nil, 1.5, 60_001] do
      assert {:error, :invalid_reload_timeout} = Limits.reserve_reload(self(), timeout, limits)
    end

    assert {:error, :unknown_reload_reservation} = Limits.claim_reload(make_ref(), self(), limits)
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot(limits)
  end

  defp await_empty(limits, deadline) do
    case Limits.snapshot(limits) do
      {:ok, %{reload_reservations: 0}} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline
        await_empty(limits, deadline)
    end
  end
end
