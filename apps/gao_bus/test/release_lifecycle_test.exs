defmodule GaoBus.ReleaseLifecycleTest do
  use ExUnit.Case, async: false

  setup do
    refute Process.whereis(GaoBus.Supervisor)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-life-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    config = Path.join(directory, "bus.conf")

    File.write!(config, """
    <busconfig><type>system</type><listen>unix:path=#{path}</listen>
      <policy context="default"><allow user="*"/><allow own="*"/>
        <allow send_destination="*"/><allow receive_sender="*"/></policy>
    </busconfig>
    """)

    values = [
      profile: :system,
      cluster: false,
      lifecycle: :release,
      config_file: config,
      config_options: [],
      socket_path: path,
      inherited_listener: false,
      runtime_invocation: %{nofork: true, nopidfile: true, log_target: :stderr}
    ]

    previous = Enum.map(values, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(values, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)
    notify_before = System.get_env("NOTIFY_SOCKET")
    System.delete_env("NOTIFY_SOCKET")

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)

      if notify_before,
        do: System.put_env("NOTIFY_SOCKET", notify_before),
        else: System.delete_env("NOTIFY_SOCKET")

      File.rm_rf!(directory)
    end)

    %{path: path, config: config, directory: directory}
  end

  test "readiness is sent only after valid policy, authority and listener are operational", ctx do
    notify = Path.join(ctx.directory, "notify")
    {:ok, socket} = :socket.open(:local, :dgram, :default)
    :ok = :socket.bind(socket, %{family: :local, path: notify})
    on_exit(fn -> :socket.close(socket) end)
    System.put_env("NOTIFY_SOCKET", notify)
    start_supervised!(bus_spec())
    assert {:ok, "READY=1"} = :socket.recv(socket, 0, 1000)
    assert {:ok, _, _} = GaoBus.Policy.snapshot()
    assert is_pid(Process.whereis(GaoBus.Router))
    assert %{socket_path: path} = :sys.get_state(GaoBus.Listener)
    assert path == ctx.path
  end

  @tag :capture_log
  test "a release authority crash stops the entire core rather than restarting in place", ctx do
    supervisor = start_supervised!(bus_spec())
    monitor = Process.monitor(supervisor)
    router = Process.whereis(GaoBus.Router)
    Process.exit(router, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^supervisor, :shutdown}, 2000
    assert Process.whereis(GaoBus.Router) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    refute File.exists?(ctx.path)
  end

  test "failed readiness removes the owned socket and never leaves a running core", ctx do
    System.put_env("NOTIFY_SOCKET", Path.join(ctx.directory, "absent-notify"))
    assert {:error, reason} = start_supervised(bus_spec())
    assert inspect(reason) =~ "readiness_failed"
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Router) == nil
    refute File.exists?(ctx.path)
  end

  test "a headless release requires explicit valid configuration before listening", ctx do
    Application.delete_env(:gao_bus, :config_file)
    assert {:error, reason} = start_supervised(bus_spec())
    assert inspect(reason) =~ "missing_configuration"
    assert Process.whereis(GaoBus.Supervisor) == nil
    refute File.exists?(ctx.path)
  end

  defp bus_spec do
    %{
      id: :release_fixture,
      start: {GaoBus.Application, :start, [:normal, []]},
      restart: :temporary,
      type: :supervisor
    }
  end
end
