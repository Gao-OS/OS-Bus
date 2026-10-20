defmodule GaoBus.SocketAuthorizationTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{NameRegistry, Policy, Router}

  setup tags do
    Application.stop(:gao_bus)
    previous_profile = Application.get_env(:gao_bus, :profile)
    Application.put_env(:gao_bus, :profile, Map.get(tags, :profile, :system))

    on_exit(fn ->
      if previous_profile,
        do: Application.put_env(:gao_bus, :profile, previous_profile),
        else: Application.delete_env(:gao_bus, :profile)
    end)

    {:ok, _} = Application.ensure_all_started(:crypto)
    {uid_text, 0} = System.cmd("id", ["-u"])
    uid = uid_text |> String.trim() |> String.to_integer()

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-policy-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    socket_path = Path.join(directory, "bus")

    rules = [
      rule(:connect, :allow, %{uid: uid}),
      rule(:own, :allow, %{uid: uid, name: {:prefix, "org.foundation"}}),
      rule(:own, :deny, %{name: "org.foundation.Forbidden"}),
      rule(:send, :allow, %{uid: uid}),
      rule(:receive, :allow, %{uid: uid})
    ]

    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(GaoBus.Limits)
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!({Policy, rules: rules}, restart: :temporary)
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(Router)
    start_supervised!(GaoBus.PeerSupervisor)
    start_supervised!({GaoBus.Listener, socket_path: socket_path})
    on_exit(fn -> File.rm_rf!(directory) end)

    {observer, observer_name} = registered(socket_path)
    own(observer, "org.foundation.Observer")
    barrier(observer)

    %{
      path: socket_path,
      uid: uid,
      rules: rules,
      observer: observer,
      observer_name: observer_name,
      router: Process.whereis(Router)
    }
  end

  test "SEC-08 denied RequestName creates neither owner nor queue entry", ctx do
    {socket, _name} = registered(ctx.path)
    send_call(socket, "RequestName", 10, "su", ["org.foundation.Forbidden", 0])

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(socket, 10)

    assert {:error, :name_not_found} = NameRegistry.resolve("org.foundation.Forbidden")
    healthy(ctx)
  end

  test "SEC-09 a denied destination remains denied via its unique name and alias", ctx do
    {target, target_name} = registered(ctx.path)
    own(target, "org.foundation.Protected")
    own(target, "org.foundation.Alias")
    barrier(target)

    {:ok, _} =
      Policy.reload(ctx.rules ++ [rule(:send, :deny, %{destination: "org.foundation.Protected"})])

    for destination <- ["org.foundation.Protected", "org.foundation.Alias", target_name] do
      send_message(
        ctx.observer,
        call_to(destination, "/private", "org.foundation.Secret", "Read", serial: 30)
      )

      assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
               reply(ctx.observer, 30)

      assert {:error, :timeout} = :gen_tcp.recv(target, 0, 50)
    end

    healthy(ctx)
  end

  test "SEC-10 receiving is authorized independently for calls signals and replies", ctx do
    {target, target_name} = registered(ctx.path)
    barrier(target)

    {:ok, _} =
      Policy.reload(
        ctx.rules ++
          [
            rule(:receive, :deny, %{interface: "org.foundation.Secret"}),
            rule(:receive, :deny, %{type: :method_return, sender: ctx.observer_name})
          ]
      )

    send_message(
      ctx.observer,
      call_to(target_name, "/private", "org.foundation.Secret", "Read", serial: 40)
    )

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.observer, 40)

    send_message(
      ctx.observer,
      Message.signal("/private", "org.foundation.Secret", "Changed",
        destination: target_name,
        serial: 41
      )
    )

    send_message(
      ctx.observer,
      Message.method_return(9,
        destination: target_name,
        serial: 42,
        signature: "s",
        body: ["private payload"]
      )
    )

    barrier(ctx.observer)
    assert {:error, :timeout} = :gen_tcp.recv(target, 0, 50)
    healthy(ctx)
  end

  test "SEC-11 denied admission closes before authentication", ctx do
    {:ok, _} = Policy.reload(ctx.rules ++ [rule(:connect, :deny, %{})])
    socket = connect(ctx.path)
    :ok = :gen_tcp.send(socket, <<0, "AUTH EXTERNAL\r\n">>)
    assert {:error, reason} = :gen_tcp.recv(socket, 0, 1000)
    assert reason in [:closed, :econnreset]
    healthy(ctx)
  end

  test "SEC-11 privileged bus control cannot bypass policy by addressing the bus", ctx do
    for member <- ["ReloadConfig", "UpdateActivationEnvironment", "StartServiceByName"] do
      {signature, body} =
        case member do
          "UpdateActivationEnvironment" -> {"a{ss}", [[{"FOUNDATION", "denied"}]]}
          "StartServiceByName" -> {"su", ["org.foundation.Service", 0]}
          _ -> {nil, []}
        end

      send_call(ctx.observer, member, 50, signature, body)

      assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
               reply(ctx.observer, 50)
    end

    healthy(ctx)
  end

  test "SEC-12 unauthorized eavesdropping does not install a match", ctx do
    send_call(ctx.observer, "AddMatch", 60, "s", ["eavesdrop='true'"])

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.observer, 60)

    {:ok, peer} = NameRegistry.resolve(ctx.observer_name)
    refute GaoBus.MatchRules.has_rules?(peer)
    healthy(ctx)
  end

  @tag profile: :session
  test "SEC-12 denied message payload is absent from internal diagnostics", ctx do
    {:ok, _} = Application.ensure_all_started(:phoenix_pubsub)
    pubsub = GaoBusWeb.PubSub
    start_supervised!({Phoenix.PubSub, name: pubsub})
    :ok = GaoBus.PubSub.subscribe()
    GaoBus.PubSub.broadcast(:diagnostic_observer_ready)
    assert_receive :diagnostic_observer_ready

    {:ok, _} =
      Policy.reload(ctx.rules ++ [rule(:send, :deny, %{interface: "org.foundation.Secret"})])

    send_message(
      ctx.observer,
      call_to("org.foundation.Unknown", "/private", "org.foundation.Secret", "Read",
        serial: 70,
        signature: "s",
        body: ["must not disclose this payload"]
      )
    )

    assert %Message{type: :error} = reply(ctx.observer, 70)
    refute_receive {:message_routed, _message}, 50
    healthy(ctx)
  end

  test "SEC-12 system profile never publishes to optional UI diagnostics", ctx do
    {:ok, _} = Application.ensure_all_started(:phoenix_pubsub)
    start_supervised!({Phoenix.PubSub, name: GaoBusWeb.PubSub})
    Phoenix.PubSub.subscribe(GaoBusWeb.PubSub, GaoBus.PubSub.topic())
    own(ctx.observer, "org.foundation.PrivateName")
    refute_receive {:name_acquired, "org.foundation.PrivateName", _owner}, 50
    healthy(ctx)
  end

  test "SEC-13 loss of policy cannot fall back to the capability engine", ctx do
    policy = Process.whereis(Policy)
    ref = Process.monitor(policy)
    Process.exit(policy, :kill)
    assert_receive {:DOWN, ^ref, :process, ^policy, :killed}
    send_call(ctx.observer, "RequestName", 80, "su", ["org.foundation.AfterPolicyDeath", 0])

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.observer, 80)

    assert {:error, :name_not_found} = NameRegistry.resolve("org.foundation.AfterPolicyDeath")
    assert Process.whereis(Router) == ctx.router
    assert {:ok, ctx.observer_name} == NameRegistry.get_name_owner("org.foundation.Observer")
  end

  defp rule(action, effect, match), do: %{action: action, effect: effect, match: match}

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    socket
  end

  defp registered(path) do
    socket = connect(path)
    {uid, 0} = System.cmd("id", ["-u"])

    :ok =
      :gen_tcp.send(
        socket,
        <<0>> <> "AUTH EXTERNAL " <> Base.encode16(String.trim(uid)) <> "\r\n"
      )

    assert {:ok, "OK " <> _} = :gen_tcp.recv(socket, 0, 1000)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    send_call(socket, "Hello", 1)
    assert %Message{type: :method_return, body: [name]} = reply(socket, 1)
    {socket, name}
  end

  defp own(socket, name) do
    send_call(socket, "RequestName", 2, "su", [name, 0])
    assert %Message{type: :method_return, body: [1]} = reply(socket, 2)
  end

  defp barrier(socket) do
    send_call(socket, "GetId", 900)
    assert %Message{type: :method_return} = reply(socket, 900)
  end

  defp healthy(ctx) do
    assert Process.whereis(Router) == ctx.router
    assert {:ok, ctx.observer_name} == NameRegistry.get_name_owner("org.foundation.Observer")
    barrier(ctx.observer)
  end

  defp send_call(socket, member, serial, signature \\ nil, body \\ []) do
    send_message(
      socket,
      call_to("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        serial: serial,
        signature: signature,
        body: body
      )
    )
  end

  defp call_to(destination, path, interface, member, opts) do
    Message.method_call(path, interface, member, Keyword.put(opts, :destination, destination))
  end

  defp send_message(socket, msg), do: :gen_tcp.send(socket, Message.encode_message(msg))

  defp reply(socket, serial) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    assert {:ok, tail} = :gen_tcp.recv(socket, header + rem(8 - rem(header, 8), 8) + body, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    if message.reply_serial == serial, do: message, else: reply(socket, serial)
  end
end
