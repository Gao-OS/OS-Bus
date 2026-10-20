defmodule GaoBus.Config.HelperBindingTest do
  use ExUnit.Case, async: true

  alias GaoBus.Activation.{HelperBinding, HelperWorker}
  alias GaoBus.Config
  alias GaoBus.Config.{Capture, Runtime}

  @endpoint "unix:path=/run/dbus/system_bus_socket"
  @root "/etc/dbus-1/system.conf"
  @helper "/run/wrappers/bin/dbus-daemon-launch-helper"
  @service "org.example.Activated"
  @hash String.duplicate("a", 64)

  test "exact captured package generation pairs without filesystem effects" do
    {config, manifest, identity} = fixture()

    for mode <- [0o4550, 0o4750] do
      assert :ok = HelperBinding.pair(config, put_in(manifest, ["entrypoint", "mode"], mode), identity, @endpoint)
    end
  end

  test "helper path, fixed configuration root and canonical endpoint must agree" do
    {config, manifest, identity} = fixture()

    for changed <- [
          %{manifest | "compiled_helper_path" => "/different/helper"},
          %{manifest | "configuration_root" => "/different/system.conf"},
          %{manifest | "endpoint" => "unix:path=/tmp/other-bus"},
          put_in(manifest, ["bridge", "path"], "/other/gao_helper_bridge")
        ] do
      assert {:error, _reason} = HelperBinding.pair(config, changed, identity, @endpoint)
    end

    assert {:error, _reason} = HelperBinding.pair(config, manifest, identity, "unix:path=/tmp/bus")
  end

  test "service inventory, captured bytes and local account bindings cannot drift" do
    {config, manifest, identity} = fixture()

    for changed <- [
          put_in(manifest, ["files", @root], String.duplicate("b", 64)),
          put_in(manifest, ["directories", "/services"], []),
          %{manifest | "servicedirs" => ["/other-services"]},
          put_in(manifest, ["accounts", "messagebus", "gid"], 43)
        ] do
      assert {:error, _reason} = HelperBinding.pair(config, changed, identity, @endpoint)
    end

    assert {:error, :helper_daemon_identity_mismatch} =
             HelperBinding.pair(config, manifest, %{identity | real_uid: 0}, @endpoint)

    config = %{config | accounts: Map.delete(config.accounts, :sources)}
    assert {:error, :helper_account_sources_unavailable} =
             HelperBinding.pair(config, manifest, identity, @endpoint)
  end

  test "malformed metadata and approval fields cannot authorize a helper" do
    {config, manifest, identity} = fixture()

    for changed <- [
          nil,
          %{},
          %{manifest | "version" => 2},
          Map.put(manifest, "approved", true),
          put_in(manifest, ["entrypoint", "mode"], 0o4777),
          put_in(manifest, ["helper", "sha256"], "unknown"),
          put_in(manifest, ["directories", "/services"], ["../escape"])
        ] do
      assert {:error, :invalid_helper_manifest} =
               HelperBinding.pair(config, changed, identity, @endpoint)
    end
  end

  test "the exact retained ELF section binds both word sizes and byte orders" do
    for class <- [1, 2], endian <- [:little, :big], path <- [@helper, ""] do
      assert {:ok, ^path} = HelperBinding.bridge_binding(elf(path, class, endian))
    end
  end

  test "an ELF-looking substring, missing section table and truncated sections prove no binding" do
    bytes = elf(@helper, 2, :little)

    for invalid <- [
          <<127, "ELF", @helper::binary, 0>>,
          binary_part(bytes, 0, 63),
          binary_part(bytes, 0, byte_size(bytes) - 1),
          put_number(bytes, 60, 0, 2, :little),
          put_number(bytes, 40, byte_size(bytes), 8, :little)
        ] do
      assert {:error, _reason} = HelperBinding.bridge_binding(invalid)
    end
  end

  test "helper mode refuses publication without an installed binding and retains origins" do
    {config, _manifest, _identity} = fixture()

    assert {:error, %{reason: {:helper_binding, :missing_helper_binding}, origins: origins}} =
             Runtime.validate_activation(config, :systemd_helper)

    assert Enum.any?(origins, &(&1.file == @root))
  end

  test "a reserved worker with no binding refuses before opening a Port" do
    token = make_ref()
    epoch = make_ref()
    attempt = make_ref()

    worker = start_supervised!({HelperWorker,
      owner: self(), epoch: epoch, attempt: attempt, token: token, name: @service})

    assert :sys.get_state(worker).port == nil
    monitor = Process.monitor(worker)
    assert :ok = HelperWorker.launch(worker, token)
    assert_receive {:helper_result, ^worker, ^epoch, ^attempt, ^token, {:error, :backend_unavailable}}
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}
  end

  defp fixture do
    identity = %{uid: 42, gid: 42, real_uid: 42, real_gid: 42}
    account = %{name: "messagebus", uid: 42, gid: 42, groups: [42], provenance: nil}
    files = Map.new([@root, "/etc/passwd", "/etc/group", "/services/#{@service}.service"], &{&1, @hash})
    directories = %{"/services" => [@service <> ".service"]}

    config = %Config{
      daemon_uid: 42,
      settings: %{type: :system, user: 42, servicehelper: @helper,
                  servicedir: ["/services"], listen: [@endpoint]},
      sources: [%{file: @root, line: 1, element: "busconfig", sha256: @hash}],
      accounts: %{users: %{"messagebus" => 42}, groups: %{"messagebus" => 42},
                  memberships: %{42 => [42]}, user_records: %{"messagebus" => account},
                  sources: %{passwd: %{file: "/etc/passwd", sha256: @hash},
                             group: %{file: "/etc/group", sha256: @hash}}},
      services: %{selected: %{@service => %{user: "messagebus", account: account,
                                           systemd_service: nil}}},
      captures: %Capture{
        files: Map.new(files, fn {path, hash} -> {path, {:ok, %{sha256: hash}}} end),
        directories: Map.new(directories, fn {path, names} -> {path, {:ok, %{names: names}}} end)
      }
    }

    artifact = %{"path" => "/nix/store/package/artifact", "sha256" => @hash,
                 "uid" => 0, "gid" => 0, "mode" => 0o555}

    manifest = %{
      "version" => 1,
      "bridge" => %{artifact | "path" => "gao_helper_bridge"},
      "helper" => artifact,
      "wrapper_source" => artifact,
      "entrypoint" => %{artifact | "path" => @helper, "gid" => 42, "mode" => 0o4750},
      "compiled_helper_path" => @helper,
      "configuration_root" => @root,
      "endpoint" => @endpoint,
      "daemon" => %{"name" => "messagebus", "uid" => 42, "gid" => 42},
      "servicedirs" => ["/services"],
      "files" => files,
      "directories" => directories,
      "accounts" => %{"messagebus" => %{"uid" => 42, "gid" => 42, "groups" => [42]}}
    }

    {config, manifest, identity}
  end

  defp elf(path, class, endian) do
    {word, entry_size, offset_position, entry_position, count_position, names_position} =
      if class == 2, do: {8, 64, 40, 58, 60, 62}, else: {4, 40, 32, 46, 48, 50}

    names = <<0, ".shstrtab", 0, ".gao_helper_binding", 0>>
    names_offset = 64 + entry_size * 3
    data = if endian == :little, do: 1, else: 2

    header =
      <<127, "ELF", class, data, 1, 0::456>>
      |> put_number(offset_position, 64, word, endian)
      |> put_number(entry_position, entry_size, 2, endian)
      |> put_number(count_position, 3, 2, endian)
      |> put_number(names_position, 1, 2, endian)

    names_header = section(1, 3, 0, names_offset, byte_size(names), class, endian)
    binding_header = section(11, 1, 2, names_offset + byte_size(names), byte_size(path) + 1, class, endian)

    header <> :binary.copy(<<0>>, entry_size) <> names_header <> binding_header <> names <> path <> <<0>>
  end

  defp section(name, type, flags, offset, size, class, endian) do
    {entry_size, word, offset_position, size_position} =
      if class == 2, do: {64, 8, 24, 32}, else: {40, 4, 16, 20}

    :binary.copy(<<0>>, entry_size)
    |> put_number(0, name, 4, endian)
    |> put_number(4, type, 4, endian)
    |> put_number(8, flags, word, endian)
    |> put_number(offset_position, offset, word, endian)
    |> put_number(size_position, size, word, endian)
  end

  defp put_number(bytes, offset, number, size, endian) do
    encoded = :binary.encode_unsigned(number, endian)
    padding = :binary.copy(<<0>>, size - byte_size(encoded))
    value = if endian == :little, do: encoded <> padding, else: padding <> encoded
    binary_part(bytes, 0, offset) <> value <>
      binary_part(bytes, offset + size, byte_size(bytes) - offset - size)
  end
end
