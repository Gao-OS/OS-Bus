defmodule GaoBus.NameReferenceTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.NameRegistry
  alias GaoBusTest.E2E.Actor.RawUnix
  alias GaoBusTest.E2E.Backend.ReferenceDBusDaemon
  alias GaoBusTest.E2E.Context

  setup do
    Application.stop(:gao_bus)
    start_supervised!(GaoBus.Limits)
    start_supervised!({NameRegistry, max_name_entries: 4})
    base = Path.join(System.tmp_dir!(), "osbus-name-ref-#{System.unique_integer([:positive])}")
    File.mkdir!(base)
    File.chmod!(base, 0o700)
    assert {:ok, backend} = ReferenceDBusDaemon.start(tmp_base: base)
    File.chmod!(backend.tmpdir, 0o700)
    File.chmod!(backend.socket_path, 0o600)

    on_exit(fn ->
      ReferenceDBusDaemon.stop(backend)
      File.rm_rf!(base)
    end)

    {uid, 0} = System.cmd("id", ["-u"])
    uid = uid |> String.trim() |> String.to_integer()

    peers =
      for n <- 1..4 do
        context =
          Context.new(
            scenario_id: "SEM-names-#{n}",
            backend_name: :reference,
            backend_mod: ReferenceDBusDaemon,
            backend_state: backend
          )

        assert {:ok, context} = RawUnix.start(context)
        :ok = RawUnix.send(context, RawUnix.external_auth(uid))
        assert {:ok, "OK " <> _} = RawUnix.recv(context, 0, 2000)
        :ok = RawUnix.send(context, "BEGIN\r\n")
        assert %Message{type: :method_return, body: [unique]} = call(context, "Hello", nil, [])
        pid = start_supervised!(%{id: {:peer, n}, start: {Agent, :start_link, [fn -> :peer end]}})
        :ok = GaoBus.Limits.acquire(pid, %{uid: 1000, gid: 1000, pid: 123})
        :ok = GaoBus.Limits.auth_completed(pid)
        :ok = NameRegistry.register_unique(unique, pid)
        %{context: context, unique: unique, pid: pid}
      end

    %{peers: peers, backend: backend, name: "org.foundation.ReferenceQueue"}
  end

  test "SEM-01–04 required reference comparison exposes queued-repeat specification conflict",
       ctx do
    sequence = [
      {:request, 0, 0},
      {:request, 0, 1},
      {:request, 1, 0},
      {:request, 2, 0},
      {:request, 1, 1},
      {:request, 3, 2},
      {:request, 1, 2},
      {:release, 3},
      {:request, 1, 2},
      {:request, 1, 5},
      {:request, 3, 2},
      {:request, 0, 4},
      {:release, 2},
      {:release, 3}
    ]

    for action <- sequence do
      {peer, member, signature, body, local} =
        case action do
          {:request, n, flags} ->
            peer = Enum.at(ctx.peers, n)

            {peer, "RequestName", "su", [ctx.name, flags],
             NameRegistry.request_name(ctx.name, flags, peer.pid, peer.unique)}

          {:release, n} ->
            peer = Enum.at(ctx.peers, n)
            {peer, "ReleaseName", "s", [ctx.name], NameRegistry.release_name(ctx.name, peer.pid)}
        end

      assert %Message{type: :method_return, body: [result]} =
               call(peer.context, member, signature, body)

      assert local == {:ok, result}
      reference = call(peer.context, "ListQueuedOwners", "s", [ctx.name])

      case reference do
        %Message{type: :method_return, body: [names]} ->
          assert NameRegistry.list_queued_owners(ctx.name) == {:ok, names},
                 "required reference comparison differs after #{inspect(action)}; see D-Bus RequestName queued-repeat requirement"

        %Message{type: :error, error_name: reason} ->
          assert NameRegistry.list_queued_owners(ctx.name) == {:error, reason}
      end
    end
  end

  test "SEM-04 self and unique-name queries agree with reference", ctx do
    [peer | _] = ctx.peers

    for name <- ["org.freedesktop.DBus", peer.unique, "org.foundation.Missing"] do
      owner = call(peer.context, "GetNameOwner", "s", [name])
      queue = call(peer.context, "ListQueuedOwners", "s", [name])
      assert NameRegistry.get_name_owner(name) == result(owner)
      assert NameRegistry.list_queued_owners(name) == result(queue)
    end

    for name <- ["org.freedesktop.DBus", peer.unique, "bad", "org..bad"] do
      assert %Message{type: :error, error_name: error} =
               call(peer.context, "RequestName", "su", [name, 0])

      assert NameRegistry.request_name(name, 0, peer.pid, peer.unique) == {:error, error}
    end
  end

  test "SEM-08 reference accepts literal quoting and rejects invalid typed keys", ctx do
    [peer | _] = ctx.peers

    for rule <- [
          ~S(arg0='a,b',arg1='a'\''b',arg2='\',arg3=\\),
          "arg0namespace=org.foundation",
          "path_namespace=/",
          "member=Foo,",
          "destination=org.foundation.Service"
        ] do
      assert %Message{type: :method_return} = call(peer.context, "AddMatch", "s", [rule])
      assert {:ok, _} = GaoBus.MatchRules.parse(rule)
    end

    for rule <- [
          "member",
          "member=Foo,member=Bar",
          "path=/test,path_namespace=/",
          "eavesdrop=maybe",
          "interface=bad",
          "member=bad.member",
          "sender=bad",
          "path=relative",
          "arg64=x",
          "arg0namespace=org..bad"
        ] do
      assert %Message{type: :error} = call(peer.context, "AddMatch", "s", [rule])
      assert {:error, _} = GaoBus.MatchRules.parse(rule)
    end
  end

  defp result(%Message{type: :method_return, body: [value]}), do: {:ok, value}
  defp result(%Message{type: :error, error_name: reason}), do: {:error, reason}

  defp call(context, member, signature, body) do
    serial = System.unique_integer([:positive])

    message =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial,
        signature: signature,
        body: body
      )

    :ok = RawUnix.send(context, Message.encode_message(message))
    reply(context, serial)
  end

  defp reply(context, serial) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             RawUnix.recv(context, 16, 2000)

    assert {:ok, tail} = RawUnix.recv(context, header + rem(8 - rem(header, 8), 8) + body, 2000)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    if message.reply_serial == serial, do: message, else: reply(context, serial)
  end
end
