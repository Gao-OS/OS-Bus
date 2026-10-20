defmodule GaoBus.NameSignalTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{MatchRules, NameRegistry, Router}

  setup do
    Application.stop(:gao_bus)

    start_supervised!(GaoBus.Limits)
    start_supervised!({GaoBus.Policy, rules: GaoBus.Policy.session_rules()})
    start_supervised!(NameRegistry)
    start_supervised!(MatchRules)
    start_supervised!(Router)

    :ok
  end

  describe "well-known name signals" do
    test "RequestName delivers NameAcquired to the acquirer without match rules" do
      peer = start_fake_peer()
      unique_name = ":1.10"
      register_peer(peer, unique_name)

      assert {:ok, 1} = NameRegistry.request_name("com.test.Acquired", 0, peer, unique_name)

      assert_peer_signal(%{
        member: "NameAcquired",
        destination: unique_name,
        signature: "s",
        body: ["com.test.Acquired"]
      })
    end

    test "ReleaseName delivers NameLost to the releasing owner" do
      peer = start_fake_peer()
      unique_name = ":1.11"
      register_peer(peer, unique_name)

      assert {:ok, 1} = NameRegistry.request_name("com.test.Lost", 0, peer, unique_name)
      flush_peer_messages()

      assert {:ok, 1} = NameRegistry.release_name("com.test.Lost", peer)

      assert_peer_signal(%{
        member: "NameLost",
        destination: unique_name,
        signature: "s",
        body: ["com.test.Lost"]
      })
    end

    test "disconnect cleanup broadcasts NameOwnerChanged without delivering NameLost to gone peer" do
      owner = start_fake_peer(:owner)
      watcher = start_fake_peer(:watcher)

      register_peer(owner, ":1.12")
      register_peer(watcher, ":1.13")
      :ok = MatchRules.add_match(watcher, "type='signal',member='NameOwnerChanged'")

      assert {:ok, 1} = NameRegistry.request_name("com.test.Disconnected", 0, owner, ":1.12")
      flush_peer_messages()

      Router.unregister_peer(owner)
      sync_router()

      NameRegistry.peer_disconnected(owner)
      sync_name_registry()
      sync_router()

      assert_tagged_signal(:watcher, %{
        member: "NameOwnerChanged",
        body: ["com.test.Disconnected", ":1.12", ""]
      })

      refute_receive {:owner, {:send_message, %Message{member: "NameLost"}}}, 50
    end
  end

  defp register_peer(peer, unique_name) do
    credentials = %{uid: 1000, gid: 1000, pid: 1}
    :ok = GaoBus.Limits.acquire(peer, credentials)
    :ok = GaoBus.Limits.auth_completed(peer)
    assert :ok = NameRegistry.register_unique(unique_name, peer)
    # Explicit trusted router fixture metadata; socket identity is tested separately.
    Router.register_peer(peer, unique_name, %{uid: 1000, gid: 1000, pid: 1})
    sync_router()
    flush_peer_messages()
  end

  defp start_fake_peer(tag \\ :peer) do
    test_pid = self()

    start_supervised!(%{
      id: {:peer, make_ref()},
      start: {Task, :start_link, [fn -> fake_peer_loop(test_pid, tag) end]}
    })
  end

  defp fake_peer_loop(test_pid, tag) do
    receive do
      {:send_message, msg, {token, _queued_at}} ->
        :ok = GaoBus.Limits.release(token)
        send(test_pid, {tag, {:send_message, msg}})
        fake_peer_loop(test_pid, tag)

      msg ->
        send(test_pid, {tag, msg})
        fake_peer_loop(test_pid, tag)
    end
  end

  defp assert_peer_signal(expected) do
    assert_receive {:peer, {:send_message, %Message{} = msg}}, 500

    if signal_matches?(msg, expected) do
      assert msg.destination == expected.destination
    else
      assert_peer_signal(expected)
    end
  end

  defp assert_tagged_signal(tag, expected) do
    assert_receive {^tag, {:send_message, %Message{} = msg}}, 500

    if signal_matches?(msg, expected) do
      :ok
    else
      assert_tagged_signal(tag, expected)
    end
  end

  defp signal_matches?(%Message{} = msg, expected) do
    Enum.all?(expected, fn
      {:member, value} -> msg.member == value
      {:destination, value} -> msg.destination == value
      {:signature, value} -> msg.signature == value
      {:body, value} -> msg.body == value
    end)
  end

  defp sync_router do
    :sys.get_state(Router)
    :ok
  end

  defp sync_name_registry do
    :sys.get_state(NameRegistry)
    :ok
  end

  defp flush_peer_messages do
    receive do
      {:peer, _} -> flush_peer_messages()
      {:owner, _} -> flush_peer_messages()
      {:watcher, _} -> flush_peer_messages()
    after
      0 -> :ok
    end
  end
end
