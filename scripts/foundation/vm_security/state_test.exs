ExUnit.start()

helper = Path.join(__DIR__, "state.ex")
if File.exists?(helper), do: Code.require_file(helper)

defmodule GaoBusSecurityFixture.StateTest do
  use ExUnit.Case, async: true

  alias GaoBusSecurityFixture.State

  test "peer DOWN does not make unrelated egress reservations quiescent" do
    retained = expected(1, 128)
    transient = snapshot(retained, 2, 1)
    settled = snapshot(retained, 1, 0)
    count = :atomics.new(1, [])

    read = fn ->
      if :atomics.add_get(count, 1, 1) == 1, do: transient, else: settled
    end

    assert {:ok, ^settled} = State.await(read, "victim", retained, 1000)
    assert :atomics.get(count, 1) == 2
  end

  test "persistent resource credit cannot qualify peer cleanup" do
    retained = expected(1, 128)
    leaked = snapshot(retained, 2, 1)

    assert {:error, {:quiescence_timeout, ^leaked}} =
             State.await(fn -> leaked end, "victim", retained, 0)
  end

  test "consumer release must settle every reservation exactly to zero" do
    released = expected(0, 0)
    settled = snapshot(released, 0, 0)
    assert {:ok, ^settled} = State.await(fn -> settled end, "victim", released, 0)

    stale = %{settled | peers: [%{peer: "victim"}]}

    assert {:error, {:quiescence_timeout, ^stale}} =
             State.await(fn -> stale end, "victim", released, 0)
  end

  defp expected(messages, bytes),
    do: %{
      reservations: messages,
      ingress_messages: messages,
      ingress_bytes: bytes,
      ingress_fds: 0
    }

  defp snapshot(expected, reservations, egress) do
    %{
      peers: [],
      usage: %{
        peers: [],
        reservations: reservations,
        global: %{
          authenticating: 0,
          ingress_messages: expected.ingress_messages,
          ingress_bytes: expected.ingress_bytes,
          ingress_fds: expected.ingress_fds,
          frame_bytes: 0,
          frame_fds: 0,
          egress_messages: egress,
          egress_bytes: egress * 128,
          egress_fds: 0
        }
      }
    }
  end
end

