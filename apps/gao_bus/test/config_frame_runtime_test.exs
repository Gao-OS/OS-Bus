defmodule GaoBus.ConfigFrameRuntimeTest do
  use ExUnit.Case, async: false
  alias GaoBus.{Limits, NameRegistry}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-p09-f-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    %{path: Path.join(directory, "bus")}
  end

  defp bus(path, xml) do
    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})

    safety =
      Map.new(
        [:global, :uid, :peer],
        &{&1,
         %{
           frame_bytes: 67_108_864,
           frame_fds: 512,
           ingress_bytes: 67_108_864,
           ingress_fds: 1024,
           egress_fds: 1024,
           egress_bytes: 67_108_864
         }}
      )

    start_supervised!({Limits, limits: safety, xml_limits: xml})

    rules =
      Enum.map([:connect, :own, :send, :receive], &%{action: &1, effect: :allow, match: %{}})

    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Router)
    start_supervised!({GaoBus.PeerSupervisor, max_children: 32})

    start_supervised!(
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600, peer_options: [xml_limits: xml]}
    )
  end

  for {mode, xml} <- [
        {"size", %{"max_message_size" => 4096}},
        {"large", %{"max_message_size" => 1_049_600}},
        {"fds17", %{"max_message_unix_fds" => 17}},
        {"fds253", %{"max_message_unix_fds" => 253}},
        {"overfds", %{"max_message_unix_fds" => 16}},
        {"unnegotiated", %{"max_message_unix_fds" => 17}},
        {"malformed", %{"max_message_unix_fds" => 17}}
      ] do
    test "independent XML frame actor #{mode}", %{path: path} do
      mode = unquote(mode)
      bus(path, unquote(Macro.escape(xml)))
      assert {output, 0} = System.cmd(python!(), [actor(), path, mode], stderr_to_stdout: true)
      assert String.contains?(output, "PASS " <> mode)

      await(fn ->
        {:ok, state} = Limits.snapshot()
        state.global.connections == 0 and state.reservations == 0
      end)
    end
  end

  test "pending FD timer starts first positive and growth does not reset", %{path: path} do
    bus(path, %{"pending_fd_timeout" => 300})
    port = port(path, "pending")
    assert_receive {^port, {:data, {:eol, "READY " <> name}}}, 1500
    {:ok, peer} = NameRegistry.resolve(name)
    await(fn -> length(:sys.get_state(peer).incoming_fds) == 1 end)
    initial = :sys.get_state(peer)
    original_handles = initial.incoming_fds
    assert initial.frame_timer == nil
    assert initial.pending_fd_timer != nil
    Port.command(port, "GROW\n")
    assert_receive {^port, {:data, {:eol, "GROWN"}}}, 500
    await(fn -> length(:sys.get_state(peer).incoming_fds) == 2 end)
    assert :sys.get_state(peer).pending_fd_timer == initial.pending_fd_timer
    monitor = Process.monitor(peer)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 650

    for handle <- original_handles,
        do: assert(GaoBus.Unix.Resources.info(handle) == {:error, :closed})

    assert_receive {^port, {:data, {:eol, "PASS pending"}}}, 500
    assert_receive {^port, {:exit_status, 0}}, 500
  end

  test "complete frame disables pending FD deadline and stale token is harmless", %{path: path} do
    bus(path, %{"pending_fd_timeout" => 1000})
    port = port(path, "complete")
    assert_receive {^port, {:data, {:eol, "READY " <> name}}}, 1500
    {:ok, peer} = NameRegistry.resolve(name)
    await(fn -> length(:sys.get_state(peer).incoming_fds) == 1 end)
    first = :sys.get_state(peer)
    {_timer, token} = first.pending_fd_timer
    original_handles = first.incoming_fds
    Port.command(port, "GROW\n")
    assert_receive {^port, {:data, {:eol, "GROWN"}}}, 500
    Port.command(port, "FINISH\n")
    assert_receive {^port, {:data, {:eol, "CONSUMED"}}}, 500
    assert :sys.get_state(peer).pending_fd_timer == nil
    assert :sys.get_state(peer).incoming_fds == []

    for handle <- original_handles,
        do: assert(GaoBus.Unix.Resources.info(handle) == {:error, :closed})

    send(peer, {:pending_fd_expiry, token})
    assert GaoBus.Peer.get_unique_name(peer) == name
    Port.command(port, "SECOND\n")
    assert_receive {^port, {:data, {:eol, "SECOND"}}}, 500
    await(fn -> length(:sys.get_state(peer).incoming_fds) == 1 end)
    assert {_timer, next_token} = :sys.get_state(peer).pending_fd_timer
    assert next_token != token
    Port.command(port, "FINISH2\n")
    assert_receive {^port, {:data, {:eol, "PASS complete"}}}, 500
    assert_receive {^port, {:exit_status, 0}}, 500
  end

  test "zero pending FD timeout closes a descriptor-bearing partial frame", %{path: path} do
    bus(path, %{"pending_fd_timeout" => 0})

    assert {output, 0} =
             System.cmd(python!(), [actor(), path, "pending_zero"], stderr_to_stdout: true)

    assert String.contains?(output, "PASS pending_zero")
  end

  test "XML small receive cap permits legal large output with protocol safety bound", %{
    path: path
  } do
    bus(path, %{"max_message_size" => 4096})
    port = port(path, "output")
    assert_receive {^port, {:data, {:eol, "READY " <> name}}}, 1500
    {:ok, peer} = NameRegistry.resolve(name)

    message =
      ExDBus.Message.signal("/foundation", "org.foundation.Transport", "Output",
        serial: 12,
        sender: "org.freedesktop.DBus",
        destination: name,
        signature: "s",
        body: [:binary.copy("x", 1_049_600)]
      )

    bytes = byte_size(ExDBus.Message.encode_message(message))
    assert {:ok, token} = Limits.reserve_egress(peer, bytes, 0)
    assert :ok = Limits.bind_egress(token, [])
    send(peer, {:send_message, message, {token, System.monotonic_time(:millisecond)}})
    assert_receive {^port, {:data, {:eol, "PASS output"}}}, 1500
    assert_receive {^port, {:exit_status, 0}}, 500
  end

  test "raw XML frame defaults and unsupported bounds remain distinct from connection state" do
    assert {:ok, native} = GaoBus.Peer.init(socket: :unused)

    assert native.frame_options == %{
             max_bytes: 1_048_576,
             max_fds: 16,
             pending_fd_timeout: nil,
             max_output_bytes: 1_048_576
           }

    assert native.frame_timeout_ms == 5000
    assert {:ok, xml} = GaoBus.Peer.init(socket: :unused, xml_limits: %{})
    Process.cancel_timer(elem(xml.registration_timer, 0))

    assert xml.frame_options == %{
             max_bytes: 33_554_432,
             max_fds: 16,
             pending_fd_timeout: 150_000,
             max_output_bytes: 134_217_728
           }

    assert xml.frame_timeout_ms == nil

    for invalid <- [
          %{"max_message_size" => 0},
          %{"max_message_size" => 134_217_729},
          %{"max_message_unix_fds" => 0},
          %{"max_message_unix_fds" => 254},
          %{"pending_fd_timeout" => -1}
        ] do
      assert {:stop, :invalid_xml_frame_limits} =
               GaoBus.Peer.init(socket: :unused, xml_limits: invalid)
    end

    assert {:ok, bounded} =
             GaoBus.Peer.init(socket: :unused, xml_limits: %{}, frame_timeout_ms: 700)

    Process.cancel_timer(elem(bounded.registration_timer, 0))
    assert bounded.frame_timeout_ms == 700
  end

  test "Writer explicit output safety bound preserves native default and rejects unbounded options" do
    alias GaoBus.Unix.Writer
    bytes = :binary.copy("x", 1_048_577)
    assert {:error, :invalid_writer} = Writer.new(bytes, [], 0)
    assert {:ok, _} = Writer.new(bytes, [], 0, max_bytes: byte_size(bytes))
    assert {:error, :invalid_writer} = Writer.new(bytes, [], 0, max_bytes: byte_size(bytes) - 1)

    for limit <- [0, -1, :infinity, 134_217_729] do
      assert {:error, :invalid_writer} = Writer.new("x", [], 0, max_bytes: limit)
    end
  end

  defp python!,
    do: System.find_executable("python3") || flunk("required Python actor unavailable")

  defp actor, do: Path.expand("fixtures/frame_actor.py", __DIR__)

  defp port(path, mode) do
    port =
      Port.open({:spawn_executable, python!()}, [
        :binary,
        :exit_status,
        {:line, 8192},
        args: [actor(), path, mode]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    port
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 1000)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(check, deadline)
    end
  end
end
