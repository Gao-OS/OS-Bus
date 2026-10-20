defmodule GaoBus.ApiIdentityTest do
  use ExUnit.Case, async: false
  alias ExDBus.Message
  alias GaoBus.{BusInterface, BusMethod, Ids, NameRegistry}
  @moduletag :tmp_dir
  @bus "org.freedesktop.DBus"
  @peer @bus <> ".Peer"
  @queries ["GetConnectionUnixUser", "GetConnectionUnixProcessID", "GetConnectionCredentials"]

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    unless tags[:pure] do
      directory = Path.join(System.tmp_dir!(), "gb-api-#{System.unique_integer([:positive])}")
      File.mkdir!(directory)
      File.chmod!(directory, 0o700)
      on_exit(fn -> File.rm_rf!(directory) end)
      uid = GaoBus.Unix.Native.identity().uid

      settings = %{
        socket_path: Path.join(directory, "bus"),
        profile: :session,
        cluster: false,
        policy_rules:
          for(
            action <- [:connect, :own, :send, :receive],
            do: %{action: action, effect: :allow, match: %{uid: uid}}
          )
      }

      previous = Map.new(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
      Enum.each(settings, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

      on_exit(fn ->
        Enum.each(previous, fn
          {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
          {key, :error} -> Application.delete_env(:gao_bus, key)
        end)
      end)

      start_supervised!(%{id: :identity_core, start: {GaoBus.Application, :start, [:normal, []]}})
      %{path: settings.socket_path}
    else
      :ok
    end
  end

  for mode <- ["identity", "peer", "invalid"] do
    @mode mode
    test "independent wire client verifies #{@mode} API behavior", ctx do
      actor = Path.expand("api/identity_actor.py", __DIR__)

      {output, status} =
        System.cmd(
          System.find_executable("python3"),
          ["-B", actor, @mode, ctx.path, System.pid()],
          stderr_to_stdout: true
        )

      assert status == 0, output
      assert output =~ ~s("result": "PASS"), output
      IO.puts(output)
    end
  end

  @tag :pure
  test "all identity and Peer schemas validate before dispatch" do
    for {interface, member, signature, body} <-
          for(member <- @queries, do: {@bus, member, "s", [":1.88"]}) ++
            [{@peer, "Ping", "", []}, {@peer, "GetMachineId", "", []}] do
      message = call(interface, member, signature, body)
      assert {:ok, _} = BusMethod.validate(message)

      assert {:error, "InvalidArgs", _} =
               BusMethod.validate(%{message | signature: "u", body: [1]})

      assert {:error, "InvalidArgs", _} = BusMethod.validate(%{message | body: body ++ ["extra"]})
      assert {:error, "UnknownObject", _} = BusMethod.validate(%{message | path: "invalid"})
    end

    for member <- @queries do
      for name <- ["invalid", "org.1invalid.Name", "", "org.test\0Injected", ":1.88\n", <<255>>] do
        assert {:error, "InvalidArgs", _} = BusMethod.validate(call(@bus, member, "s", [name]))
      end
    end

    assert {:ok, %{interface: @peer}} =
             BusMethod.validate(%{call(nil, "Ping", "", []) | path: "/"})
  end

  @tag :pure
  test "credential replies use immutable authority metadata and omit unavailable fields" do
    start_supervised!(NameRegistry)
    peer = start_supervised!({Task, fn -> receive do: (:stop -> :ok) end})
    :ok = NameRegistry.register_unique(":1.88", peer)

    state = %{
      peers: %{peer => %{unique_name: ":1.88", credentials: %{uid: 1000, pid: 4321, gid: 123}}},
      next_serial: 1
    }

    for {member, signature, body} <- [
          {"GetConnectionUnixUser", "u", [1000]},
          {"GetConnectionUnixProcessID", "u", [4321]},
          {"GetConnectionCredentials", "a{sv}",
           [[{"UnixUserID", {"u", 1000}}, {"ProcessID", {"u", 4321}}]]}
        ] do
      {reply, _} = BusInterface.handle_message(call(@bus, member, "s", [":1.88"]), self(), state)
      assert reply.type == :method_return
      assert reply.signature == signature
      assert reply.body == body
    end

    missing = put_in(state.peers[peer].credentials, %{})

    {reply, _} =
      BusInterface.handle_message(
        call(@bus, "GetConnectionCredentials", "s", [":1.88"]),
        self(),
        missing
      )

    assert reply.body == [[]]

    for member <- ["GetConnectionUnixUser", "GetConnectionUnixProcessID"] do
      {reply, _} =
        BusInterface.handle_message(call(@bus, member, "s", [":1.88"]), self(), missing)

      assert reply.error_name == @bus <> ".Error.NotSupported"
    end

    {reply, _} =
      BusInterface.handle_message(
        call(@bus, "GetConnectionCredentials", "s", [":1.88"]),
        self(),
        %{state | peers: %{}}
      )

    assert reply.error_name == @bus <> ".Error.NameHasNoOwner"
  end

  @tag :pure
  test "machine identity is cached from a trusted file independently of the bus epoch ID", ctx do
    path = Path.join(ctx.tmp_dir, "machine-id")
    id = "0123456789abcdef0123456789abcdef"
    File.write!(path, id <> "\n")
    start_supervised!({Ids, machine_id_paths: [path]})
    assert {:ok, ^id} = Ids.machine_id()
    File.write!(path, "changed")
    assert {:ok, ^id} = Ids.machine_id()
    refute Ids.bus_id() == id

    {reply, _} =
      BusInterface.handle_message(call(@peer, "GetMachineId", "", []), self(), %{
        peers: %{},
        next_serial: 1
      })

    assert reply.body == [id]
  end

  @tag :pure
  test "machine identity falls back only to another valid trusted file", ctx do
    invalid = Path.join(ctx.tmp_dir, "invalid")
    valid = Path.join(ctx.tmp_dir, "valid")
    File.write!(invalid, "uninitialized\n")
    File.write!(valid, "fedcba9876543210fedcba9876543210\n")
    start_supervised!({Ids, machine_id_paths: [invalid, valid]})
    assert {:ok, "fedcba9876543210fedcba9876543210"} = Ids.machine_id()
  end

  @tag :pure
  test "missing or invalid machine identity gives a controlled error without random substitution",
       ctx do
    path = Path.join(ctx.tmp_dir, "machine-id")

    for content <- [
          nil,
          "",
          "uninitialized\n",
          String.duplicate("0", 32),
          String.duplicate("g", 32),
          String.duplicate("a", 31)
        ] do
      if content, do: File.write!(path, content), else: File.rm(path)
      start_supervised!({Ids, machine_id_paths: [path]})
      assert {:error, :machine_id_unavailable} = Ids.machine_id()

      {reply, _} =
        BusInterface.handle_message(call(@peer, "GetMachineId", "", []), self(), %{
          peers: %{},
          next_serial: 1
        })

      assert reply.error_name == @bus <> ".Error.Failed"

      {ping, _} =
        BusInterface.handle_message(call(@peer, "Ping", "", []), self(), %{
          peers: %{},
          next_serial: 1
        })

      assert ping.type == :method_return

      {bus_id, _} =
        BusInterface.handle_message(call(@bus, "GetId", "", []), self(), %{
          peers: %{},
          next_serial: 1
        })

      assert [id] = bus_id.body
      assert id =~ ~r/\A[0-9a-f]{32}\z/
      stop_supervised!(Ids)
    end
  end

  defp call(interface, member, signature, body) do
    %Message{
      type: :method_call,
      path: "/org/freedesktop/DBus",
      destination: @bus,
      interface: interface,
      member: member,
      signature: signature,
      body: body,
      serial: 1
    }
  end
end
