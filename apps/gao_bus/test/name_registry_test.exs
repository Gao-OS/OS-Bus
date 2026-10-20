defmodule GaoBus.NameRegistryTest do
  use ExUnit.Case, async: false

  alias GaoBus.NameRegistry

  import Bitwise

  # RequestName flags
  @flag_allow_replacement 0x1
  @flag_replace_existing 0x2
  @flag_do_not_queue 0x4

  # RequestName results
  @name_primary_owner 1
  @name_in_queue 2
  @name_exists 3
  @name_already_owner 4

  # ReleaseName results
  @name_released 1
  @name_non_existent 2
  @name_not_owner 3

  setup do
    Application.stop(:gao_bus)
    start_supervised!(GaoBus.Limits)
    %{registry: start_supervised!(NameRegistry)}
  end

  describe "register_unique/2" do
    test "registers a unique name" do
      peer = spawn_peer()
      assert :ok = NameRegistry.register_unique(":1.1", peer)
    end

    test "unique name appears in list_names" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)

      names = NameRegistry.list_names()
      assert ":1.1" in names
    end

    test "unique name is resolvable" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)

      assert {:ok, ^peer} = NameRegistry.resolve(":1.1")
    end

    test "unique name has owner" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)

      assert NameRegistry.name_has_owner?(":1.1")
    end

    test "get_name_owner returns self for unique names" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)

      assert {:ok, ":1.1"} = NameRegistry.get_name_owner(":1.1")
    end
  end

  describe "request_name/4 — basic ownership" do
    test "grants ownership when name is free" do
      peer = spawn_peer()

      assert {:ok, @name_primary_owner} =
               NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")
    end

    test "name appears in list after request" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      names = NameRegistry.list_names()
      assert "com.test.Svc" in names
    end

    test "get_name_owner returns unique name of owner" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      assert {:ok, ":1.1"} = NameRegistry.get_name_owner("com.test.Svc")
    end

    test "resolve returns owner pid" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      assert {:ok, ^peer} = NameRegistry.resolve("com.test.Svc")
    end

    test "name_has_owner? returns true for owned name" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      assert NameRegistry.name_has_owner?("com.test.Svc")
    end

    test "already_owner when same peer requests same name" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      assert {:ok, @name_already_owner} =
               NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")
    end
  end

  describe "request_name/4 — replacement flags" do
    test "cannot replace when current owner disallows replacement" do
      owner = spawn_peer()
      challenger = spawn_peer()

      # Owner does NOT set allow_replacement
      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")

      # Challenger tries to replace
      assert {:ok, @name_exists} =
               NameRegistry.request_name(
                 "com.test.Svc",
                 @flag_replace_existing ||| @flag_do_not_queue,
                 challenger,
                 ":1.2"
               )

      # Original owner still owns
      assert {:ok, ":1.1"} = NameRegistry.get_name_owner("com.test.Svc")
    end

    test "replaces when owner allows and challenger requests replacement" do
      owner = spawn_peer()
      challenger = spawn_peer()

      # Owner sets allow_replacement
      NameRegistry.request_name("com.test.Svc", @flag_allow_replacement, owner, ":1.1")

      # Challenger replaces
      assert {:ok, @name_primary_owner} =
               NameRegistry.request_name(
                 "com.test.Svc",
                 @flag_replace_existing,
                 challenger,
                 ":1.2"
               )

      # Challenger is now owner
      assert {:ok, ":1.2"} = NameRegistry.get_name_owner("com.test.Svc")
      assert {:ok, ^challenger} = NameRegistry.resolve("com.test.Svc")
    end

    test "cannot replace even with replace_existing if owner disallows" do
      owner = spawn_peer()
      challenger = spawn_peer()

      # Owner does NOT allow replacement (flags = 0)
      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")

      # Challenger wants to replace but will be queued
      assert {:ok, @name_in_queue} =
               NameRegistry.request_name(
                 "com.test.Svc",
                 @flag_replace_existing,
                 challenger,
                 ":1.2"
               )

      # Original still owns
      assert {:ok, ":1.1"} = NameRegistry.get_name_owner("com.test.Svc")
    end
  end

  describe "request_name/4 — queuing" do
    test "queues when name is taken and do_not_queue is not set" do
      owner = spawn_peer()
      waiter = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")

      assert {:ok, @name_in_queue} =
               NameRegistry.request_name("com.test.Svc", 0, waiter, ":1.2")
    end

    test "returns exists when name is taken and do_not_queue is set" do
      owner = spawn_peer()
      waiter = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")

      assert {:ok, @name_exists} =
               NameRegistry.request_name("com.test.Svc", @flag_do_not_queue, waiter, ":1.2")
    end

    test "queued peer becomes owner when current owner releases" do
      owner = spawn_peer()
      waiter = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")
      NameRegistry.request_name("com.test.Svc", 0, waiter, ":1.2")

      # Owner releases
      assert {:ok, @name_released} = NameRegistry.release_name("com.test.Svc", owner)

      # Waiter is now owner
      assert {:ok, ":1.2"} = NameRegistry.get_name_owner("com.test.Svc")
      assert {:ok, ^waiter} = NameRegistry.resolve("com.test.Svc")
    end

    test "multiple queued peers are promoted in order" do
      owner = spawn_peer()
      waiter1 = spawn_peer()
      waiter2 = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")
      NameRegistry.request_name("com.test.Svc", 0, waiter1, ":1.2")
      NameRegistry.request_name("com.test.Svc", 0, waiter2, ":1.3")

      # Owner releases → waiter1 promoted
      NameRegistry.release_name("com.test.Svc", owner)
      assert {:ok, ":1.2"} = NameRegistry.get_name_owner("com.test.Svc")

      # Waiter1 releases → waiter2 promoted
      NameRegistry.release_name("com.test.Svc", waiter1)
      assert {:ok, ":1.3"} = NameRegistry.get_name_owner("com.test.Svc")
    end
  end

  describe "release_name/2" do
    test "releases owned name" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      assert {:ok, @name_released} = NameRegistry.release_name("com.test.Svc", peer)
      refute NameRegistry.name_has_owner?("com.test.Svc")
    end

    test "non-existent name returns non_existent" do
      peer = spawn_peer()
      assert {:ok, @name_non_existent} = NameRegistry.release_name("com.test.NoSuch", peer)
    end

    test "releasing name not owned returns not_owner" do
      owner = spawn_peer()
      other = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")

      assert {:ok, @name_not_owner} = NameRegistry.release_name("com.test.Svc", other)
    end

    test "name disappears from list after release with no queue" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")
      NameRegistry.release_name("com.test.Svc", peer)

      names = NameRegistry.list_names()
      refute "com.test.Svc" in names
    end
  end

  describe "resolve/1" do
    test "resolves org.freedesktop.DBus to {:bus, _}" do
      assert {:bus, _pid} = NameRegistry.resolve("org.freedesktop.DBus")
    end

    test "returns error for unknown name" do
      assert {:error, :name_not_found} = NameRegistry.resolve("com.test.Unknown")
    end
  end

  describe "list_names/0" do
    test "always includes org.freedesktop.DBus" do
      names = NameRegistry.list_names()
      assert "org.freedesktop.DBus" in names
    end

    test "includes both well-known and unique names" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)
      NameRegistry.request_name("com.test.Svc", 0, peer, ":1.1")

      names = NameRegistry.list_names()
      assert "org.freedesktop.DBus" in names
      assert ":1.1" in names
      assert "com.test.Svc" in names
    end
  end

  describe "name_has_owner?/1" do
    test "org.freedesktop.DBus always has owner" do
      assert NameRegistry.name_has_owner?("org.freedesktop.DBus")
    end

    test "unknown name has no owner" do
      refute NameRegistry.name_has_owner?("com.test.Unknown")
    end
  end

  describe "get_name_owner/1" do
    test "error for unknown name" do
      assert {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"} =
               NameRegistry.get_name_owner("com.test.Unknown")
    end
  end

  describe "peer_disconnected/1" do
    test "releases all well-known names owned by peer" do
      peer = spawn_peer()
      NameRegistry.request_name("com.test.A", 0, peer, ":1.1")
      NameRegistry.request_name("com.test.B", 0, peer, ":1.1")

      NameRegistry.peer_disconnected(peer)
      _ = :sys.get_state(NameRegistry)

      refute NameRegistry.name_has_owner?("com.test.A")
      refute NameRegistry.name_has_owner?("com.test.B")
    end

    test "removes unique name on disconnect" do
      peer = spawn_peer()
      NameRegistry.register_unique(":1.1", peer)

      NameRegistry.peer_disconnected(peer)
      _ = :sys.get_state(NameRegistry)

      refute NameRegistry.name_has_owner?(":1.1")
      assert {:error, :name_not_found} = NameRegistry.resolve(":1.1")
    end

    test "promotes queued peer when owner disconnects" do
      owner = spawn_peer()
      waiter = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")
      NameRegistry.request_name("com.test.Svc", 0, waiter, ":1.2")

      NameRegistry.peer_disconnected(owner)
      _ = :sys.get_state(NameRegistry)

      assert {:ok, ":1.2"} = NameRegistry.get_name_owner("com.test.Svc")
    end

    test "removes peer from queue without affecting owner" do
      owner = spawn_peer()
      waiter = spawn_peer()

      NameRegistry.request_name("com.test.Svc", 0, owner, ":1.1")
      NameRegistry.request_name("com.test.Svc", 0, waiter, ":1.2")

      NameRegistry.peer_disconnected(waiter)
      _ = :sys.get_state(NameRegistry)

      # Owner still owns
      assert {:ok, ":1.1"} = NameRegistry.get_name_owner("com.test.Svc")

      # Now if owner releases, name goes away (queue was cleaned)
      NameRegistry.release_name("com.test.Svc", owner)
      refute NameRegistry.name_has_owner?("com.test.Svc")
    end
  end

  # --- Helpers ---

  defp spawn_peer do
    peer = start_supervised!(%{id: make_ref(), start: {Agent, :start_link, [fn -> :peer end]}})
    :ok = GaoBus.Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(peer)
    peer
  end
end
