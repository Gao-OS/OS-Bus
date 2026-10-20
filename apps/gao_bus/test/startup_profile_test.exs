defmodule GaoBus.StartupProfileTest do
  use ExUnit.Case, async: false

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-profile-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)

    values = %{
      profile: :system,
      cluster: false,
      policy_rules: [],
      socket_path: Path.join(directory, "bus")
    }

    previous = Map.new(values, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(values, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)

      File.rm_rf!(directory)
    end)

    %{path: values.socket_path}
  end

  test "FAIL-04 system profile rejects cluster startup before readiness", ctx do
    Application.put_env(:gao_bus, :cluster, true)

    assert {:error, reason} =
             start_supervised(%{
               id: :profile_bus,
               start: {GaoBus.Application, :start, [:normal, []]}
             })

    assert inspect(reason) =~ "unsupported_system_cluster"
    refute File.exists?(ctx.path)
    assert Process.whereis(GaoBus.Router) == nil
  end

  test "SYS-04 an unknown configured profile never falls back to a session bus", ctx do
    Application.put_env(:gao_bus, :profile, :unknown_profile)

    assert {:error, reason} =
             start_supervised(%{
               id: :profile_bus,
               start: {GaoBus.Application, :start, [:normal, []]}
             })

    assert inspect(reason) =~ "unsupported_profile"
    refute File.exists?(ctx.path)
    assert Process.whereis(GaoBus.Router) == nil
  end
end
