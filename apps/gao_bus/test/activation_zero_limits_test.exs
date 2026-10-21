defmodule GaoBus.ActivationZeroLimitsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  # P10 / R-09 / R-13: XML zero is an enforced bound, not a default allowance.
  test "zero XML activation quota refuses a valid reservation without changing accounting" do
    limits =
      start_supervised!({Limits, name: nil, xml_limits: %{"max_pending_service_starts" => 0}})

    assert :ok = Limits.acquire(self(), %{uid: 1000, gid: 1000, pid: 123}, limits)
    assert {:ok, ingress} = Limits.reserve_ingress(self(), 128, limits)

    identity = %{
      caller: self(),
      caller_incarnation: {make_ref(), ":1.1"},
      request_key: {make_ref(), make_ref()},
      deadline: System.monotonic_time(:millisecond) + 5000
    }

    assert {:ok, before} = Limits.snapshot(limits)
    assert before.global.ingress_messages == 1
    assert before.global.ingress_bytes == 128
    assert before.global.activation_messages == 0
    assert before.reservations == 1

    assert {:error, {:xml_limit_exceeded, "max_pending_service_starts"}} =
             Limits.reserve_activation(ingress, identity, 128, [], self(), limits)

    assert {:ok, ^before} = Limits.snapshot(limits)
    assert :ok = Limits.release(ingress, limits)
    assert {:ok, released} = Limits.snapshot(limits)
    assert released.global.ingress_messages == 0
    assert released.global.ingress_bytes == 0
    assert released.global.activation_messages == 0
    assert released.reservations == 0
  end
end
