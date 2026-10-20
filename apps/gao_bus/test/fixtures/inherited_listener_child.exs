ExUnit.start()
Application.load(:gao_bus)

defmodule GaoBus.InheritedListenerChildTest do
  use ExUnit.Case, async: false
  import Bitwise
  alias ExDBus.Message
  alias GaoBus.Unix.{InheritedListener, Native}

  test "private manager inherited-listener handoff" do
    path = System.fetch_env!("P11_PATH")
    case_name = System.fetch_env!("P11_CASE")

    case case_name do
      "healthy" ->
        healthy(path)

      owner_case when owner_case in ["owner-death", "owner-kill"] ->
        owner_death(path)

      "native" ->
        native(path)

      "dup-probe" ->
        dup_probe(path)

      mismatch when mismatch in ["native-reused-file", "native-mismatch"] ->
        before = flags()
        original = File.read_link!("/proc/self/fd/3")
        {:ok, other} = :socket.open(:local, :stream, :default)
        :ok = :socket.bind(other, %{family: :local, path: path <> "-other"})
        :ok = :socket.listen(other)
        {:ok, other_fd} = :socket.getopt(other, {:otp, :fd})
        other_flags = fd_flags(other_fd)
        assert {:error, :invalid_inherited_identity} = Native.inherited_listener_handoff(other_fd)
        assert fd_flags(other_fd) == other_flags
        assert flags() == before
        assert File.read_link!("/proc/self/fd/3") == original
        assert {:error, :invalid_inherited_fd} = Native.inherited_listener_handoff(3)
        assert flags() == before
        assert {:error, :invalid_inherited_fd} = Native.inherited_listener_handoff(-1)
        assert :ok = :socket.close(other)
        assert flags() == before
        assert File.read_link!("/proc/self/fd/3") == original

      native_case
      when native_case in ["native-wrong-domain", "native-wrong-type", "native-not-listening"] ->
        reason =
          %{
            "native-wrong-domain" => :invalid_inherited_domain,
            "native-wrong-type" => :invalid_inherited_type,
            "native-not-listening" => :inherited_socket_not_listening
          }[native_case]

        {:ok, socket} = :socket.open(3, %{dup: true})
        {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
        before = fd_flags(fd)
        assert {:error, ^reason} = Native.inherited_listener_handoff(fd)
        assert fd_flags(fd) == before
        assert :ok = :socket.close(socket)

      _ ->
        original = File.read_link("/proc/self/fd/3")
        expected_path = if case_name == "wrong-path", do: path <> "-expected", else: path

        assert {:error, _} =
                 start_supervised({GaoBus.Listener, inherited: true, socket_path: expected_path})

        refute File.exists?(path <> "-expected")

        if case_name != "wrong-fd" do
          assert {:ok, identity} = original

          assert Enum.filter(File.ls!("/proc/self/fd"), fn fd ->
                   File.read_link("/proc/self/fd/#{fd}") == {:ok, identity}
                 end) == ["3"]
        end

        if case_name in ["wrong-path", "wrong-domain", "wrong-type", "not-listening"] do
          # Failed permanent startup closes the public owned duplicate; the
          # unconsumed raw original is released by daemon process exit.
          assert File.exists?("/proc/self/fd/3")
          consumed()
        end
    end
  end

  defp dup_probe(path) do
    original = File.read_link!("/proc/self/fd/3")
    IO.inspect(%{original: original, flags: fd_flags(3)}, label: "before dup:true")
    {:ok, socket} = :socket.open(3, %{dup: true})
    assert {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
    assert fd != 3
    assert {:ok, %{family: :local, path: ^path}} = :socket.sockname(socket)
    assert File.read_link!("/proc/self/fd/#{fd}") == original

    IO.inspect(%{fd: fd, original_flags: fd_flags(3), duplicate_flags: fd_flags(fd)},
      label: "after dup:true"
    )

    assert :ok = :socket.close(socket)
    assert {:error, :closed} = :socket.getopt(socket, {:otp, :fd})
    assert {:error, :enoent} = File.read_link("/proc/self/fd/#{fd}")
    assert File.read_link!("/proc/self/fd/3") == original

    IO.inspect(%{duplicate: File.read_link("/proc/self/fd/#{fd}"), original_flags: fd_flags(3)},
      label: "after public close"
    )

    parent = self()

    owner =
      start_supervised!(
        {Task,
         fn ->
           {:ok, owned} = :socket.open(3, %{dup: true})
           {:ok, owned_fd} = :socket.getopt(owned, {:otp, :fd})
           send(parent, {:owned_duplicate, owned, owned_fd})
           receive do: (:exit -> :ok)
         end}
      )

    assert_receive {:owned_duplicate, owned, owned_fd}
    assert File.read_link!("/proc/self/fd/#{owned_fd}") == original
    IO.inspect(%{fd: owned_fd, flags: fd_flags(owned_fd)}, label: "owner duplicate")
    monitor = Process.monitor(owner)
    send(owner, :exit)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert {:error, :closed} = :socket.getopt(owned, {:otp, :fd})
    assert {:error, :enoent} = File.read_link("/proc/self/fd/#{owned_fd}")
    assert File.read_link!("/proc/self/fd/3") == original

    IO.inspect(
      %{duplicate: File.read_link("/proc/self/fd/#{owned_fd}"), original_flags: fd_flags(3)},
      label: "after owner death"
    )
  end

  defp native(path) do
    original = File.read_link!("/proc/self/fd/3")
    {:ok, socket} = :socket.open(3, %{dup: true})
    {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
    assert fd != 3
    assert {:ok, %{family: :local, path: ^path}} = :socket.sockname(socket)
    adopted_flags = fd_flags(fd)
    assert (adopted_flags &&& 0o2000000) == 0
    assert :ok = Native.inherited_listener_handoff(fd)
    assert fd_flags(fd) == (adopted_flags ||| 0o2000000)
    assert {:error, :enoent} = File.read_link("/proc/self/fd/3")
    assert File.read_link!("/proc/self/fd/#{fd}") == original
    assert {:error, :ebadf} = Native.inherited_listener_handoff(fd)
    assert {:error, :invalid_inherited_fd} = Native.inherited_listener_handoff(3)
    assert {:ok, true} = :socket.getopt(socket, {:socket, :acceptconn})
    assert :ok = :socket.close(socket)
    assert {:error, :enoent} = File.read_link("/proc/self/fd/#{fd}")
  end

  defp owner_death(path) do
    parent = self()

    owner =
      start_supervised!(
        {Task,
         fn ->
           assert {:ok, socket} = InheritedListener.adopt(path)
           assert {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
           assert fd != 3
           send(parent, {:adopted, socket, fd})
           receive do: (:exit -> :ok)
         end}
      )

    assert_receive {:adopted, socket, fd}
    assert (fd_flags(fd) &&& 0o2000000) != 0
    assert {:error, :enoent} = File.read_link("/proc/self/fd/3")
    consumed()
    monitor = Process.monitor(owner)

    expected_reason =
      if System.fetch_env!("P11_CASE") == "owner-kill" do
        Process.exit(owner, :kill)
        :killed
      else
        send(owner, :exit)
        :normal
      end

    assert_receive {:DOWN, ^monitor, :process, ^owner, ^expected_reason}
    assert {:error, :closed} = :socket.getopt(socket, {:otp, :fd})
    assert {:error, :enoent} = File.read_link("/proc/self/fd/#{fd}")
  end

  defp healthy(path) do
    {:ok, _} = Application.ensure_all_started(:crypto)
    Application.put_env(:gao_bus, :profile, :session)

    Application.put_env(
      :gao_bus,
      :policy_rules,
      Enum.map([:connect, :own, :send, :receive], &%{action: &1, effect: :allow, match: %{}})
    )

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(GaoBus.Limits)
    start_supervised!({GaoBus.Policy, publication: :router})
    start_supervised!(GaoBus.NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(GaoBus.Router)
    start_supervised!({GaoBus.PeerSupervisor, []})

    listener =
      start_supervised!({GaoBus.Listener, inherited: true, socket_path: path, socket_mode: 0o777})

    state = :sys.get_state(listener)
    assert {:ok, listener_fd} = :socket.getopt(state.listen_socket, {:otp, :fd})
    assert listener_fd != 3
    listener_identity = File.read_link!("/proc/self/fd/#{listener_fd}")
    assert (fd_flags(listener_fd) &&& 0o2000000) != 0
    assert {:error, :enoent} = File.read_link("/proc/self/fd/3")
    consumed()
    assert {:error, :invalid_inherited_environment} = InheritedListener.adopt(path)

    assert {:ok, client} =
             :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line], 1000)

    on_exit(fn -> :gen_tcp.close(client) end)
    uid = Native.identity().uid |> Integer.to_string() |> Base.encode16(case: :lower)
    assert :ok = :gen_tcp.send(client, "\0AUTH EXTERNAL #{uid}\r\n")
    assert {:ok, "OK " <> _} = :gen_tcp.recv(client, 0, 1000)
    :ok = :inet.setopts(client, packet: :raw)
    :ok = :gen_tcp.send(client, "BEGIN\r\n")
    assert %Message{type: :method_return} = query(client, "Hello", 1)
    assert %Message{type: :method_return, body: [id]} = query(client, "GetId", 2)
    assert is_binary(id)
    assert byte_size(id) == 32
    assert :ok = stop_supervised(GaoBus.Listener)
    assert {:error, :closed} = :socket.getopt(state.listen_socket, {:otp, :fd})
    refute File.read_link("/proc/self/fd/#{listener_fd}") == {:ok, listener_identity}

    refute Enum.any?(File.ls!("/proc/self/fd"), fn fd ->
             File.read_link("/proc/self/fd/#{fd}") == {:ok, listener_identity}
           end)

    assert File.exists?(path)
  end

  defp consumed do
    for variable <- ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] do
      assert System.get_env(variable) == nil
    end
  end

  defp flags do
    fd_flags(3)
  end

  defp fd_flags(fd) do
    [_, octal] = Regex.run(~r/^flags:\s+([0-7]+)$/m, File.read!("/proc/self/fdinfo/#{fd}"))
    String.to_integer(octal, 8)
  end

  defp query(socket, member, serial) do
    request =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(request))
    reply(socket, serial, System.monotonic_time(:millisecond) + 1000)
  end

  defp reply(socket, serial, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    assert remaining > 0
    assert {:ok, header} = :gen_tcp.recv(socket, 16, remaining)
    <<?l, _::binary-size(3), bytes::little-32, _::little-32, fields::little-32>> = header

    assert {:ok, rest} =
             :gen_tcp.recv(socket, fields + rem(8 - rem(fields, 8), 8) + bytes, remaining)

    assert {:ok, message, <<>>} = Message.decode_message(header <> rest)
    if message.reply_serial == serial, do: message, else: reply(socket, serial, deadline)
  end
end
