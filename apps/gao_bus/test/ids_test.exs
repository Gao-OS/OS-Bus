defmodule GaoBus.IdsTest do
  use ExUnit.Case, async: false

  alias GaoBus.Ids

  @guid_key :gao_bus_auth_guid
  @bus_id_key :gao_bus_instance_id

  setup do
    # Clear cached values so each test generates fresh ones
    try do
      :persistent_term.erase(@guid_key)
    catch
      :error, :badarg -> :ok
    end

    try do
      :persistent_term.erase(@bus_id_key)
    catch
      :error, :badarg -> :ok
    end

    on_exit(fn ->
      try do
        :persistent_term.erase(@guid_key)
      catch
        :error, :badarg -> :ok
      end

      try do
        :persistent_term.erase(@bus_id_key)
      catch
        :error, :badarg -> :ok
      end
    end)

    :ok
  end

  describe "auth_guid/0" do
    test "returns a 32 lowercase hex character string" do
      guid = Ids.auth_guid()

      assert is_binary(guid)
      assert byte_size(guid) == 32
      assert String.match?(guid, ~r/^[0-9a-f]{32}$/)
    end

    test "is idempotent — returns same value on subsequent calls" do
      guid1 = Ids.auth_guid()
      guid2 = Ids.auth_guid()

      assert guid1 == guid2
    end

    test "caches value in persistent_term" do
      guid = Ids.auth_guid()

      cached = :persistent_term.get(@guid_key)
      assert cached == guid
    end

    test "generates a new value after persistent_term is cleared" do
      guid1 = Ids.auth_guid()

      :persistent_term.erase(@guid_key)

      guid2 = Ids.auth_guid()

      # Both are valid format
      assert String.match?(guid1, ~r/^[0-9a-f]{32}$/)
      assert String.match?(guid2, ~r/^[0-9a-f]{32}$/)

      # Extremely unlikely to collide (128-bit random)
      assert guid1 != guid2
    end
  end

  describe "bus_id/0" do
    test "returns a 32 lowercase hex character string" do
      id = Ids.bus_id()

      assert is_binary(id)
      assert byte_size(id) == 32
      assert String.match?(id, ~r/^[0-9a-f]{32}$/)
    end

    test "is idempotent — returns same value on subsequent calls" do
      id1 = Ids.bus_id()
      id2 = Ids.bus_id()

      assert id1 == id2
    end

    test "caches value in persistent_term" do
      id = Ids.bus_id()

      cached = :persistent_term.get(@bus_id_key)
      assert cached == id
    end

    # D-Bus GetId identifies the bus instance, not the machine:
    # https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-id
    test "is independent of /etc/machine-id" do
      id = Ids.bus_id()

      case File.read("/etc/machine-id") do
        {:ok, content} ->
          machine_id = String.trim(content)

          if byte_size(machine_id) == 32 and String.match?(machine_id, ~r/^[0-9a-f]+$/) do
            refute id == machine_id
          end

        _ ->
          # No machine-id file, falls back to random — just verify format
          assert String.match?(id, ~r/^[0-9a-f]{32}$/)
      end
    end
  end

  describe "auth_guid/0 and bus_id/0 independence" do
    test "auth_guid and bus_id are independent values" do
      guid = Ids.auth_guid()
      id = Ids.bus_id()

      # Both valid format
      assert String.match?(guid, ~r/^[0-9a-f]{32}$/)
      assert String.match?(id, ~r/^[0-9a-f]{32}$/)

      refute guid == id

      # They use different persistent_term keys
      assert :persistent_term.get(@guid_key) == guid
      assert :persistent_term.get(@bus_id_key) == id
    end
  end
end
