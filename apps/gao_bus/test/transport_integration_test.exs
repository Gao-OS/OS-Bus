defmodule GaoBus.TransportIntegrationTest do
  use ExUnit.Case, async: false

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(System.tmp_dir!(), "osbus-transport-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    {uid, 0} = System.cmd("id", ["-u"])
    uid = String.to_integer(String.trim(uid))

    options = [
      socket_path: path,
      profile: :system,
      cluster: false,
      resource_limits: Map.get(tags, :resource_limits, %{}),
      policy_rules:
        Enum.map(
          [:connect, :own, :send, :receive],
          &%{action: &1, effect: :allow, match: %{uid: uid}}
        )
    ]

    old = Enum.map(options, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    for {key, value} <- options, do: Application.put_env(:gao_bus, key, value)
    start_supervised!(%{id: :transport_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    on_exit(fn ->
      for {key, previous} <- old do
        case previous do
          {:ok, value} -> Application.put_env(:gao_bus, key, value)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    %{path: path}
  end

  for mode <- ~w(resources fragments coalesced invalid fanout unnegotiated) do
    @mode mode
    test "independent product FD transport: #{mode}", %{path: path} do
      executable = System.find_executable("python3") || flunk("required Python actor unavailable")
      source = Path.expand("fixtures/transport_actor.py", __DIR__)
      {output, result} = System.cmd(executable, [source, path, @mode], stderr_to_stdout: true)
      assert result == 0, output
      assert %{"result" => "PASS", "scenario" => @mode} = Jason.decode!(output)
    end
  end

  test "GLib reads and returns an actual descriptor through the product bus", %{path: path} do
    alias GaoBusTest.E2E.ChildProcess
    fixture = Path.expand("../../gao_bus_test/test/fixture/external_fixture", __DIR__)

    worker =
      start_supervised!(
        {ChildProcess,
         command: fixture, args: ["--bus-address", "unix:path=" <> path], owner: self()}
      )

    assert {:ok, _} = ChildProcess.await_ready(worker, &String.contains?(&1, "READY\n"), 5000)
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    actor = Path.expand("fixtures/transport_actor.py", __DIR__)

    {output, result} =
      System.cmd(executable, [actor, path, "glib_return"], stderr_to_stdout: true)

    assert result == 0, output
    assert %{"result" => "PASS", "scenario" => "glib_return"} = Jason.decode!(output)
    assert :ok = ChildProcess.stop(worker)
  end

  for mode <- ~w(slow_write source_exit recipient_exit backpressure fanout_stall) do
    @mode mode
    @tag resource_limits: %{peer: %{egress_bytes: 262_144}}
    test "bounded partial delivery: #{mode}", %{path: path} do
      executable = System.find_executable("python3") || flunk("required Python actor unavailable")
      source = Path.expand("fixtures/transport_actor.py", __DIR__)

      port =
        Port.open({:spawn_executable, executable}, [
          :binary,
          :exit_status,
          {:line, 4096},
          args: [source, path, @mode]
        ])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)

      assert %{"event" => "ready", "source" => source_name, "target" => target_name} =
               port_json(port)

      assert {:ok, target} = GaoBus.NameRegistry.resolve(target_name)
      assert {:ok, source_peer} = GaoBus.NameRegistry.resolve(source_name)
      target_ref = Process.monitor(target)
      source_ref = Process.monitor(source_peer)
      socket = :sys.get_state(target).socket
      assert :ok = :socket.setopt(socket, {:socket, :sndbuf}, 1024)
      before_fds = length(File.ls!("/proc/self/fd"))
      Port.command(port, "continue\n")
      assert %{"event" => "queued"} = port_json(port)
      output = :sys.get_state(target).current_output
      assert output.writer.offset > 0
      assert output.writer.offset < byte_size(output.writer.bytes)
      assert output.writer.rights_sent
      assert {:ok, accounting} = GaoBus.Limits.snapshot()
      assert %{egress_messages: 1, egress_fds: 1} = accounting.peers[target]
      assert accounting.peers[target].egress_bytes <= 262_144

      if @mode == "source_exit" do
        assert_receive {:DOWN, ^source_ref, :process, ^source_peer, :normal}, 1000
        # One queued delivery FD remains; both source OTP/native socket FDs close.
        assert length(File.ls!("/proc/self/fd")) == before_fds - 1
      else
        assert length(File.ls!("/proc/self/fd")) == before_fds + 1
      end

      if @mode == "fanout_stall" do
        # Launch a real independent process while the daemon holds the test
        # memfd. No transport resource may survive exec into a child actor.
        script =
          "import os; print(any('foundation-fanout-held' in os.readlink('/proc/self/fd/'+fd) for fd in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+fd)))"

        assert {"False\n", 0} = System.cmd(executable, ["-c", script])
      end

      if @mode in ["recipient_exit", "fanout_stall"] do
        Process.exit(target, :kill)
        assert_receive {:DOWN, ^target_ref, :process, ^target, :killed}, 1000
        assert {:ok, cleaned} = GaoBus.Limits.snapshot()
        assert cleaned.global.egress_fds == 0
      end

      Port.command(port, "continue\n")
      assert %{"result" => "PASS", "scenario" => @mode} = port_json(port)
      assert_receive {^port, {:exit_status, 0}}, 5000

      unless @mode in ["recipient_exit", "fanout_stall"],
        do: assert_receive({:DOWN, ^target_ref, :process, ^target, :normal}, 1000)

      unless @mode == "source_exit",
        do: assert_receive({:DOWN, ^source_ref, :process, ^source_peer, :normal}, 1000)

      assert {:ok, final} = GaoBus.Limits.snapshot()
      assert final.global.egress_fds == 0
      assert final.global.egress_bytes == 0
      assert final.global.ingress_fds == 0
    end
  end

  defp port_json(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 5000
    Jason.decode!(line)
  end
end
