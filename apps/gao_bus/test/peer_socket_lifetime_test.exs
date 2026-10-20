defmodule GaoBus.PeerSocketLifetimeTest do
  use ExUnit.Case, async: false

  alias GaoBus.PeerSupervisor
  alias GaoBus.Unix.{Native, Resources}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    _identity = Native.identity()
    directory = Path.join(System.tmp_dir!(), "gb-lifetime-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)

    values = %{
      profile: :session,
      cluster: false,
      policy_rules: [%{action: :connect, effect: :allow, match: %{}}],
      socket_path: Path.join(directory, "bus"),
      auth_limits: [idle_timeout_ms: 10_000, timeout_ms: 10_000]
    }

    previous = Map.new(values, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(values, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)
    start_supervised!(%{id: :lifetime_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)

      File.rm_rf!(directory)
    end)

    %{path: values.socket_path}
  end

  test "normal Peer termination closes its native socket even with another handle reference",
       ctx do
    client = authenticate(ctx.path)
    [{_, peer, _, _}] = DynamicSupervisor.which_children(PeerSupervisor)
    state = :sys.get_state(peer)
    assert {:ok, native_socket} = Map.fetch(state, :native_socket)
    assert {:ok, %{cloexec: true}} = Resources.info(native_socket)
    assert {:error, :not_socket_owner} = Resources.capture(state.socket)
    monitor = Process.monitor(peer)

    GenServer.stop(peer, :normal)

    assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 1500
    assert {:error, :closed} = Resources.info(native_socket)
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1500)
    assert [] = DynamicSupervisor.which_children(PeerSupervisor)
  end

  test "killed Peer releases its OTP socket and sole native socket reference", ctx do
    baseline = external_fd_count()
    client = authenticate(ctx.path)
    [{_, peer, _, _}] = DynamicSupervisor.which_children(PeerSupervisor)
    monitor = Process.monitor(peer)

    Process.exit(peer, :kill)

    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}, 1500
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1500)
    :gen_tcp.close(client)
    await_fd_count(baseline, System.monotonic_time(:millisecond) + 1500)
    assert [] = DynamicSupervisor.which_children(PeerSupervisor)
  end

  defp authenticate(path) do
    assert {:ok, client} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1500)
    on_exit(fn -> :gen_tcp.close(client) end)
    identity = Base.encode16(Integer.to_string(Native.identity().uid))
    assert :ok = :gen_tcp.send(client, <<0>> <> "AUTH EXTERNAL " <> identity <> "\r\n")
    assert "OK " <> _guid = auth_response(client, <<>>)
    client
  end

  defp auth_response(client, bytes) do
    assert {:ok, byte} = :gen_tcp.recv(client, 1, 1500)
    bytes = bytes <> byte
    if String.ends_with?(bytes, "\r\n"), do: bytes, else: auth_response(client, bytes)
  end

  defp external_fd_count do
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"
    {count, 0} = System.cmd(System.find_executable("python3"), ["-c", script, System.pid()])
    String.to_integer(String.trim(count))
  end

  defp await_fd_count(expected, deadline) do
    actual = external_fd_count()

    if actual != expected do
      assert System.monotonic_time(:millisecond) < deadline,
             "expected #{expected} descriptors after Peer death, got #{actual}"

      await_fd_count(expected, deadline)
    end
  end
end
