defmodule GaoBus.ConfigQueueRuntimeTest do
  use ExUnit.Case, async: true

  alias GaoBus.Limits

  defp accounting(xml),
    do: start_supervised!({Limits, name: nil, xml_limits: xml}, id: make_ref())

  defp peer(limits, uid \\ 1000) do
    parent = self()
    pid = start_supervised!({Task, fn -> forward(parent) end}, id: make_ref())
    assert :ok = Limits.acquire(pid, %{uid: uid, gid: 1000, pid: 123}, limits)
    pid
  end

  defp forward(parent) do
    receive do
      :stop ->
        :ok

      message ->
        send(parent, {:peer_message, self(), message})
        forward(parent)
    end
  end

  defp snapshot(limits) do
    assert {:ok, result} = Limits.snapshot(limits)
    result
  end

  for {key, count} <- [{"max_outgoing_bytes", 0}, {"max_outgoing_unix_fds", 1}] do
    test "XML #{key} permits one frame at the threshold and rejects after overshoot" do
      key = unquote(key)
      count = unquote(count)
      limits = accounting(%{key => count})
      pid = peer(limits)
      fds = if key == "max_outgoing_unix_fds", do: 1, else: 0
      assert {:ok, first} = Limits.reserve_egress(pid, 1, fds, limits)

      tokens =
        if count == 1 do
          assert {:ok, second} = Limits.reserve_egress(pid, 1, fds, limits)
          [first, second]
        else
          [first]
        end

      before = snapshot(limits)

      assert {:error, {:xml_limit_exceeded, ^key}} =
               Limits.reserve_egress(pid, 1, fds, limits)

      assert snapshot(limits) == before
      Enum.each(tokens, &assert(:ok = Limits.release(&1, limits)))
      assert {:ok, next} = Limits.reserve_egress(pid, 1, fds, limits)
      assert :ok = Limits.release(next, limits)
    end
  end

  for {key, fds} <- [{"max_incoming_bytes", 0}, {"max_incoming_unix_fds", 1}] do
    test "XML #{key} pauses at the threshold and wakes only after credit retires" do
      key = unquote(key)
      fds = unquote(fds)
      limits = accounting(%{key => 1})
      pid = peer(limits)
      assert :ok = Limits.ingress_ready(pid, limits)
      assert :ok = Limits.set_frame(pid, 1, fds, limits)
      assert {:ok, token} = Limits.promote_frame(pid, 1, fds, limits)
      assert {:error, {:xml_limit_exceeded, ^key}} = Limits.ingress_ready(pid, limits)
      assert {:error, {:xml_limit_exceeded, ^key}} = Limits.ingress_ready(pid, limits)
      assert :ok = Limits.release(token, limits)
      assert_receive {:peer_message, ^pid, :ingress_capacity}
      refute_receive {:peer_message, ^pid, :ingress_capacity}, 0
      assert :ok = Limits.ingress_ready(pid, limits)
    end
  end

  test "XML received-message credit survives Router release and every fan-out output" do
    limits = accounting(%{"max_incoming_bytes" => 1})
    source = peer(limits)
    first = peer(limits)
    second = peer(limits, 2000)
    assert :ok = Limits.set_frame(source, 8, 2, limits)
    assert {:ok, incoming} = Limits.promote_frame(source, 8, 2, limits)
    assert {:ok, outgoing1} = Limits.reserve_egress(first, 8, 2, limits, incoming)
    assert {:ok, outgoing2} = Limits.reserve_egress(second, 8, 2, limits, incoming)
    assert :ok = Limits.release(incoming, limits)
    assert {:error, :unknown_reservation} = Limits.release(incoming, limits)
    assert %{ingress_bytes: 8, ingress_fds: 2, egress_bytes: 16} = snapshot(limits).global

    assert {:error, {:xml_limit_exceeded, "max_incoming_bytes"}} =
             Limits.ingress_ready(source, limits)

    assert :ok = Limits.release(outgoing1, limits)
    assert %{ingress_bytes: 8, ingress_fds: 2, egress_bytes: 8} = snapshot(limits).global
    refute_receive {:peer_message, ^source, :ingress_capacity}, 0
    assert :ok = Limits.release(outgoing2, limits)
    assert_receive {:peer_message, ^source, :ingress_capacity}
    assert %{ingress_bytes: 0, ingress_fds: 0, egress_bytes: 0} = snapshot(limits).global
    assert snapshot(limits).reservations == 0
  end

  test "source DOWN retains forwarded credits until recipient DOWN reclaims the last output" do
    limits = accounting(%{})
    source = peer(limits)
    recipient = peer(limits)
    assert {:ok, incoming} = Limits.reserve_ingress_fds(source, 8, 1, limits)
    assert {:ok, outgoing} = Limits.reserve_egress(recipient, 8, 1, limits, incoming)
    assert :ok = Limits.release(incoming, limits)
    reference = Process.monitor(source)
    Process.exit(source, :kill)
    assert_receive {:DOWN, ^reference, :process, ^source, :killed}
    await_removed(limits, source, System.monotonic_time(:millisecond) + 1000)
    assert %{ingress_bytes: 8, ingress_fds: 1} = snapshot(limits).global
    reference = Process.monitor(recipient)
    Process.exit(recipient, :kill)
    assert_receive {:DOWN, ^reference, :process, ^recipient, :killed}
    await_removed(limits, recipient, System.monotonic_time(:millisecond) + 1000)
    assert {:error, :unknown_reservation} = Limits.release(outgoing, limits)
    assert %{ingress_bytes: 0, ingress_fds: 0, egress_bytes: 0} = snapshot(limits).global
    assert snapshot(limits).reservations == 0
    assert snapshot(limits).uids == %{}
  end

  test "failed egress admission and invalid source tokens cannot retain input credit" do
    limits = accounting(%{"max_outgoing_bytes" => 0})
    source = peer(limits)
    recipient = peer(limits)
    assert {:ok, incoming} = Limits.reserve_ingress_fds(source, 8, 1, limits)
    assert {:ok, full} = Limits.reserve_egress(recipient, 1, 0, limits)
    before = snapshot(limits)

    assert {:error, {:xml_limit_exceeded, "max_outgoing_bytes"}} =
             Limits.reserve_egress(recipient, 8, 1, limits, incoming)

    assert snapshot(limits) == before
    assert :ok = Limits.release(full, limits)

    assert {:error, :invalid_ingress_reservation} =
             Limits.reserve_egress(recipient, 8, 1, limits, make_ref())

    assert :ok = Limits.release(incoming, limits)
    assert snapshot(limits).reservations == 0
  end

  test "XML queue settings validate raw values and preserve zero input thresholds" do
    for value <- [-1, "1", :infinity] do
      assert {:error, {:invalid_limits, :invalid_xml_queue_limits}} =
               Limits.start_link(name: nil, xml_limits: %{"max_incoming_bytes" => value})
    end

    limits = accounting(%{"max_incoming_bytes" => 0})
    pid = peer(limits)

    assert {:error, {:xml_limit_exceeded, "max_incoming_bytes"}} =
             Limits.ingress_ready(pid, limits)

    assert %{ingress_bytes: 0, ingress_fds: 0} = snapshot(limits).global
  end

  defp await_removed(limits, pid, deadline) do
    if Map.has_key?(snapshot(limits).peers, pid) do
      assert System.monotonic_time(:millisecond) < deadline
      await_removed(limits, pid, deadline)
    end
  end
end
