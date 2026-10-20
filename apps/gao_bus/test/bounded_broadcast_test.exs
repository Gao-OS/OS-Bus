defmodule GaoBus.BoundedBroadcastTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, MatchRules, NameRegistry, Policy, Router}

  setup do
    Application.stop(:gao_bus)
    start_supervised!(Limits)
    start_supervised!(NameRegistry)
    start_supervised!(MatchRules)
    start_supervised!({Policy, rules: Policy.session_rules()})
    {:ok, state} = Router.init([])
    %{state: register(state, self(), ":1.900")}
  end

  test "nonmatching and duplicate rows consume the scan budget; later adds cannot extend it", ctx do
    for _ <- 1..65, do: assert(:ok == MatchRules.add_match(self(), "member='Other'"))
    signal = signal("Broadcast")
    assert {:ok, cursor} = MatchRules.broadcast_cursor(signal, [":1.900"])
    assert :ok = MatchRules.add_match(self(), "member='Broadcast'")
    assert {:more, [], first} = MatchRules.broadcast_batch(cursor)
    assert first.position - cursor.position == 32
    assert {:more, [], second} = MatchRules.broadcast_batch(first)
    assert second.position - first.position == 32
    assert {:done, [], last} = MatchRules.broadcast_batch(second)
    assert last.position == cursor.ceiling

    # Duplicate subscriptions count against quota but deliver once.
    for _ <- 1..40, do: assert(:ok == MatchRules.add_match(self(), "member='Broadcast'"))
    assert {:ok, cursor} = MatchRules.broadcast_cursor(signal, [":1.900"])
    assert {recipients, turns} = scan(cursor, [], 0)
    assert recipients == [self()]
    assert turns >= 4
    assert ctx.state.active_fanout == nil
  end

  test "eight recipients per turn; later unicast waits and frame acknowledgement occurs once", ctx do
    {state, peers} = recipients(ctx.state, 17)
    assert :ok = Limits.set_frame(self(), 128, 0)
    assert {:ok, token} = Limits.enqueue_route(signal("Broadcast"), self(), 128, :frame, self())
    assert_receive {:owned_route, _, _, ^token, _, :frame} = envelope
    assert {:noreply, state} = Router.handle_info(envelope, state)
    assert state.active_fanout != nil

    first = hd(peers)
    directed = %{signal("After") | destination: ":1.1"}
    assert {:ok, later} = Limits.enqueue_route(directed, self(), 128, :route, self())
    assert_receive {:owned_route, _, _, ^later, _, :route} = envelope
    assert {:noreply, state} = Router.handle_info(envelope, state)
    assert :queue.len(state.work_queue) == 1

    state = turn(state)
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    refute_receive {:route_complete, ^token}, 0
    assert {:ok, %{global: %{ingress_messages: 2}}} = Limits.snapshot()

    state = drain(state)
    assert state.active_fanout == nil
    assert_receive {:route_complete, ^token}
    refute_receive {:route_complete, ^token}, 0
    assert messages(first) == ["Broadcast", "After"]
    for peer <- tl(peers), do: assert(messages(peer) == ["Broadcast"])
    assert {:ok, %{global: %{ingress_messages: 0}}} = Limits.snapshot()
  end

  test "new registrations cannot join an in-progress broadcast", ctx do
    {state, peers} = recipients(ctx.state, 9)
    state = start_broadcast(state)
    late = recipient()
    state = register(state, late, ":1.99")
    assert :ok = MatchRules.add_match(late, "member='Broadcast'")
    _state = drain(state)
    for peer <- peers, do: assert(messages(peer) == ["Broadcast"])
    assert messages(late) == []
  end

  test "a replacement match table cannot extend an old cursor" do
    assert :ok = MatchRules.add_match(self(), "member='Broadcast'")
    assert {:ok, cursor} = MatchRules.broadcast_cursor(signal("Broadcast"), [":1.900"])
    assert :ok = stop_supervised(MatchRules)
    start_supervised!(MatchRules)
    assert :ok = MatchRules.add_match(self(), "member='Broadcast'")
    assert {:error, :match_index_unavailable} = MatchRules.broadcast_batch(cursor)
  end

  test "revoking sender permission cancels the remaining broadcast and acknowledges once", ctx do
    {state, peers} = recipients(ctx.state, 17)
    state = state |> start_broadcast(:frame) |> turn()
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert {:ok, _generation} =
             Policy.reload(Policy.session_rules() ++ [%{action: :send, effect: :deny, match: %{}}])
    state = turn(state)
    assert state.active_fanout == nil
    _state = drain(state)
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert_receive {:route_complete, token}
    refute_receive {:route_complete, ^token}, 0
    assert {:ok, %{global: %{ingress_messages: 0}}} = Limits.snapshot()
  end

  test "delayed recipients use the current receive policy", ctx do
    {state, peers} = recipients(ctx.state, 17)
    state = state |> start_broadcast() |> turn()
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert {:ok, _generation} =
             Policy.reload(Policy.session_rules() ++ [%{action: :receive, effect: :deny, match: %{}}])
    _state = drain(state)
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert {:ok, %{global: %{ingress_messages: 0}}} = Limits.snapshot()
  end

  test "source removal cancels remaining turns and returns the held window once", ctx do
    {state, peers} = recipients(ctx.state, 17)
    state = start_broadcast(state, :frame)
    state = turn(state)
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert {:reply, :ok, state} = Router.handle_call({:unregister_peer, self()}, {self(), make_ref()}, state)
    assert state.active_fanout == nil
    _state = drain(state)
    assert Enum.sum(Enum.map(peers, &(length(messages(&1))))) == 8
    assert_receive {:route_complete, _token}
    refute_receive {:route_complete, _token}, 0
    assert {:ok, %{global: %{ingress_messages: 0}}} = Limits.snapshot()
  end

  defp register(state, peer, name) do
    credentials = %{uid: 1000, gid: 1000, pid: 123, unique_name: name}
    assert :ok = Limits.acquire(peer, credentials)
    assert :ok = Limits.auth_completed(peer)
    assert {:noreply, state} = Router.handle_cast({:register_peer, peer, name, credentials, false}, state)
    assert :ok = NameRegistry.register_unique(name, peer)
    state
  end

  defp recipients(state, count) do
    Enum.reduce(1..count, {state, []}, fn number, {state, peers} ->
      peer = recipient()
      state = register(state, peer, ":1.#{number}")
      assert :ok = MatchRules.add_match(peer, "member='Broadcast'")
      {state, peers ++ [peer]}
    end)
  end

  defp recipient do
    start_supervised!({Task, fn -> recipient_loop([]) end}, id: make_ref())
  end

  defp recipient_loop(messages) do
    receive do
      {:send_message, message, {token, _queued_at}} ->
        :ok = Limits.release(token)
        recipient_loop(messages ++ [message.member])
      {:messages, caller, reference} ->
        send(caller, {reference, messages})
        recipient_loop(messages)
    end
  end

  defp messages(peer) do
    reference = make_ref()
    send(peer, {:messages, self(), reference})
    assert_receive {^reference, messages}
    messages
  end

  defp signal(member),
    do: Message.signal("/example", "org.example.Events", member, serial: 1)

  defp start_broadcast(state, mode \\ :route) do
    if mode == :frame, do: assert(:ok == Limits.set_frame(self(), 128, 0))
    assert {:ok, token} = Limits.enqueue_route(signal("Broadcast"), self(), 128, mode, self())
    assert_receive {:owned_route, _, _, ^token, _, _} = envelope
    assert {:noreply, state} = Router.handle_info(envelope, state)
    state
  end

  defp turn(state) do
    tick = state.work_tick
    assert is_reference(tick)
    assert_receive {:drain_work, ^tick}
    assert {:noreply, state} = Router.handle_info({:drain_work, tick}, state)
    state
  end

  defp drain(%{work_tick: nil} = state), do: state
  defp drain(state), do: state |> turn() |> drain()

  defp scan(cursor, peers, turns) do
    case MatchRules.broadcast_batch(cursor) do
      {:more, batch, cursor} -> scan(cursor, peers ++ batch, turns + 1)
      {:done, batch, _cursor} -> {peers ++ batch, turns + 1}
    end
  end
end
