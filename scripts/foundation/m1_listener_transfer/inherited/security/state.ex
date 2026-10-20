defmodule GaoBusSecurityFixture.State do
  @moduledoc false

  @transient [
    :authenticating,
    :frame_bytes,
    :frame_fds,
    :egress_messages,
    :egress_bytes,
    :egress_fds
  ]
  @ingress [:ingress_messages, :ingress_bytes, :ingress_fds]

  def await(snapshot, peer, expected, timeout_ms) do
    poll(snapshot, peer, expected, System.monotonic_time(:millisecond) + timeout_ms)
  end

  defp poll(snapshot, peer, expected, deadline) do
    state = snapshot.()
    usage = state.usage

    settled? =
      not Enum.any?(state.peers, &(&1.peer == peer)) and
        not Enum.any?(usage.peers, &(&1.peer == peer)) and
        usage.reservations == expected.reservations and
        Enum.all?(@ingress, &(Map.fetch!(usage.global, &1) == Map.fetch!(expected, &1))) and
        Enum.all?(@transient, &(Map.fetch!(usage.global, &1) == 0))

    cond do
      settled? -> {:ok, state}
      System.monotonic_time(:millisecond) >= deadline -> {:error, {:quiescence_timeout, state}}
      true -> poll(snapshot, peer, expected, deadline)
    end
  end
end

