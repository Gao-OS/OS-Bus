defmodule GaoBusTest.InteropTest do
  @moduledoc """
  Interop compliance tests using real D-Bus tools (dbus-send, busctl)
  against gao_bus.

  These tests verify that gao_bus is compatible with standard D-Bus clients.
  They require the AUTH handshake to fully match the reference dbus-daemon
  implementation (SASL EXTERNAL with SO_PEERCRED).

  These tests are tagged `:interop` and excluded by default.
  Run with: mix test --include interop
  """
  use ExUnit.Case

  @moduletag :interop

  @dbus_send System.find_executable("dbus-send")
  @busctl System.find_executable("busctl")

  setup_all do
    assert is_nil(Process.whereis(GaoBus.Supervisor)), "interop requires its own supervised bus"
    assert @dbus_send, "dbus-send is required for all original interop cases"
    assert @busctl, "busctl is required for all original interop cases"
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-interop-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    socket_path = Path.join(directory, "bus")

    settings = [
      socket_path: socket_path,
      profile: :session,
      cluster: false,
      config_file: nil,
      policy_rules: GaoBus.Policy.session_rules()
    ]

    previous =
      for {key, _value} <- settings do
        {key, Application.fetch_env(:gao_bus, key)}
      end

    on_exit(fn ->
      for {key, original} <- previous do
        case original do
          {:ok, value} -> Application.put_env(:gao_bus, key, value)
          :error -> Application.delete_env(:gao_bus, key)
        end

        assert Application.fetch_env(:gao_bus, key) == original
      end

      assert is_nil(Process.whereis(GaoBus.Supervisor))
      assert {:error, :enoent} = File.lstat(socket_path)
      File.rmdir!(directory)
      evidence(%{event: :cleanup, directory: directory, environment_restored: true})
    end)

    for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)

    start_supervised!(%{
      id: :interop_bus,
      start: {GaoBus.Application, :start, [:normal, []]},
      type: :supervisor,
      restart: :temporary
    })

    assert File.exists?(socket_path)
    evidence(%{event: :ready, directory: directory, mode: File.stat!(directory).mode})
    %{socket_path: socket_path}
  end

  describe "dbus-send" do
    test "Hello via dbus-send", %{socket_path: socket_path} do
      {output, code} =
        run_dbus_send(
          socket_path,
          [
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Hello"
          ],
          :peer
        )

      assert code == 0, "dbus-send Hello failed (exit #{code}): #{output}"
      assert output =~ "string"
      assert output =~ ":1."
      assert output =~ ~r/string ":1\.\d+"/

      {duplicate, duplicate_code} =
        run_dbus_send(socket_path, [
          "--print-reply",
          "--dest=org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.Hello"
        ])

      assert duplicate_code == 1
      assert duplicate =~ "Error org.freedesktop.DBus.Error.Failed: Already called Hello"
    end

    test "ListNames via dbus-send", %{socket_path: socket_path} do
      {output, code} =
        run_dbus_send(socket_path, [
          "--print-reply",
          "--dest=org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.ListNames"
        ])

      assert code == 0, "dbus-send ListNames failed (exit #{code}): #{output}"
      assert output =~ "array"
      assert output =~ "org.freedesktop.DBus"
    end

    test "GetId via dbus-send", %{socket_path: socket_path} do
      {output, code} =
        run_dbus_send(socket_path, [
          "--print-reply",
          "--dest=org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.GetId"
        ])

      assert code == 0, "dbus-send GetId failed (exit #{code}): #{output}"
      assert output =~ "string"
    end

    test "Introspect via dbus-send", %{socket_path: socket_path} do
      {output, code} =
        run_dbus_send(socket_path, [
          "--print-reply",
          "--dest=org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.Introspectable.Introspect"
        ])

      assert code == 0, "dbus-send Introspect failed (exit #{code}): #{output}"
      assert output =~ "<interface"
      assert output =~ "org.freedesktop.DBus"
    end

    test "NameHasOwner via dbus-send", %{socket_path: socket_path} do
      {output, code} =
        run_dbus_send(socket_path, [
          "--print-reply",
          "--dest=org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.NameHasOwner",
          "string:org.freedesktop.DBus"
        ])

      assert code == 0, "dbus-send NameHasOwner failed (exit #{code}): #{output}"
      assert output =~ "boolean true"
    end
  end

  describe "busctl" do
    test "busctl list shows bus name", %{socket_path: socket_path} do
      {output, code} = run_busctl(socket_path, ["list", "--no-pager"])

      assert code == 0, "busctl list failed (exit #{code}): #{output}"
      assert output =~ "org.freedesktop.DBus"
    end

    test "busctl call Hello rejects duplicate registration", %{socket_path: socket_path} do
      {output, code} =
        run_busctl(socket_path, [
          "call",
          "org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus",
          "Hello"
        ])

      assert code == 1, "busctl duplicate Hello returned exit #{code}: #{output}"
      assert output =~ "Call failed: Already called Hello"
    end

    test "busctl call ListNames", %{socket_path: socket_path} do
      {output, code} =
        run_busctl(socket_path, [
          "call",
          "org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus",
          "ListNames"
        ])

      assert code == 0, "busctl call ListNames failed (exit #{code}): #{output}"
      assert output =~ "org.freedesktop.DBus"
    end

    test "busctl introspect", %{socket_path: socket_path} do
      {output, code} =
        run_busctl(socket_path, [
          "introspect",
          "org.freedesktop.DBus",
          "/org/freedesktop/DBus",
          "--no-pager"
        ])

      assert code == 0, "busctl introspect failed (exit #{code}): #{output}"
      assert output =~ "Hello"
      assert output =~ "ListNames"
    end
  end

  # --- Helpers ---

  # Peer mode is only for the first Hello; bus mode registers before the explicit call.
  defp run_dbus_send(socket_path, args, mode \\ :bus) when mode in [:bus, :peer] do
    run_tool(@dbus_send, ["--#{mode}=unix:path=#{socket_path}" | args], socket_path)
  end

  # busctl always registers automatically, so an explicit Hello must be rejected.
  defp run_busctl(socket_path, args) do
    run_tool(@busctl, ["--address=unix:path=#{socket_path}" | args], socket_path)
  end

  defp run_tool(executable, args, socket_path) do
    {output, code} =
      System.cmd(executable, args,
        stderr_to_stdout: true,
        env: [
          {"DBUS_SESSION_BUS_ADDRESS", "unix:path=#{socket_path}"},
          {"DBUS_SYSTEM_BUS_ADDRESS", "unix:path=#{socket_path}"}
        ]
      )

    evidence(%{executable: executable, argv: args, output: output, exit_status: code})
    {output, code}
  end

  defp evidence(record) do
    if System.get_env("OS_BUS_INTEROP_TRACE") == "1" do
      IO.inspect(record, label: "interop evidence", limit: :infinity, printable_limit: :infinity)
    end
  end
end
