# Guest-only fixture channel; no production management endpoint is added.
[socket, policy_file] = System.argv()
"isolated-vm\n" = File.read!("/etc/osbus-security-guest")

unless Path.expand(socket) == socket and
         String.starts_with?(socket, "/run/osbus-security/pro05-complete/"),
       do: raise("PRO05 private guest socket required")

Code.require_file(Path.join(__DIR__, "resource_probe.exs"))
alias GaoBus.Foundation.PRO05.Resources

%{uid: 0, real_uid: 0, gid: 0, real_gid: 0} = identity = GaoBus.Unix.Native.identity()
%{uid: 0, type: :regular} = File.stat!("/etc/osbus-security-guest")
rules = elem(Code.eval_file(policy_file), 0)

settings = [
  socket_path: socket,
  profile: :system,
  lifecycle: :embedded,
  cluster: false,
  capability_restrictions: false,
  auth_limits: [timeout_ms: 1500, idle_timeout_ms: 500],
  resource_limits: GaoBus.Limits.defaults(),
  policy_rules: rules
]

Application.delete_env(:gao_bus, :config_file)
Application.delete_env(:gao_bus, :inherited_listener)
for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)
{:ok, _} = Application.ensure_all_started(:gao_bus)

emit = fn event ->
  encoder = fn
    nil, _encode -> "null"
    value, encode -> :json.encode_value(value, encode)
  end

  IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(event, encoder)))
end

resolve = fn name, timeout ->
  if is_nil(name) do
    nil
  else
    true = is_binary(name)
    unless String.starts_with?(name, ":"), do: raise("unique peer name required")

    case GenServer.call(GaoBus.NameRegistry, {:resolve, name}, timeout) do
      {:ok, peer} -> peer
      {:error, :name_not_found} -> nil
      other -> raise "peer resolution failed: #{inspect(other)}"
    end
  end
end

remaining = fn deadline ->
  left = deadline - System.monotonic_time(:millisecond)
  if left <= 0, do: raise("watched peer DOWN deadline")
  left
end

same_incarnation = fn name, peer, deadline ->
  case resolve.(name, remaining.(deadline)) do
    nil -> :ok
    ^peer -> :ok
    _other -> raise "watched peer identity replaced"
  end
end

loop = fn loop, watch ->
  case IO.read(:stdio, :line) do
    :eof ->
      watch

    line ->
      case :json.decode(line) do
        %{"op" => "sample"} = command ->
          budget = Map.get(command, "remaining_ms", 1500)
          true = is_integer(budget) and budget > 0 and budget <= 1500
          started = System.monotonic_time(:millisecond)
          deadline = started + budget
          source = Map.get(command, "source")
          observer = Map.get(command, "observer")
          source_peer = resolve.(source, remaining.(deadline))
          observer_peer = resolve.(observer, remaining.(deadline))
          captured = Resources.capture(source_peer, observer_peer, remaining.(deadline))
          _ = remaining.(deadline)
          elapsed = System.monotonic_time(:millisecond) - started

          emit.(
            Map.merge(captured, %{
              event: "sample",
              source: source,
              observer: observer,
              elapsed_ms: elapsed
            })
          )

          loop.(loop, watch)

        %{"op" => "watch", "name" => name} = command ->
          unless is_nil(watch), do: raise("duplicate or outstanding peer watch")
          budget = Map.get(command, "remaining_ms", 1500)
          true = is_integer(budget) and budget > 0 and budget <= 1500
          started = System.monotonic_time(:millisecond)
          deadline = started + budget
          peer = resolve.(name, remaining.(deadline))
          unless is_pid(peer), do: raise("watched peer absent")
          reference = Process.monitor(peer)
          ^peer = resolve.(name, remaining.(deadline))
          observer = Map.get(command, "observer")
          observer_peer = resolve.(observer, remaining.(deadline))

          peer_options =
            peer
            |> :sys.get_state(remaining.(deadline))
            |> Map.take([:frame_options, :xml_limits, :frame_timeout_ms, :auth_limits])
            |> Map.update!(:auth_limits, &Map.new/1)

          captured = Resources.capture(peer, observer_peer, remaining.(deadline))
          _ = remaining.(deadline)
          elapsed = System.monotonic_time(:millisecond) - started
          watch = %{name: name, peer: peer, reference: reference}

          emit.(
            Map.merge(captured, %{
              event: "watched",
              name: name,
              peer: inspect(peer),
              reference: inspect(reference),
              observer: observer,
              elapsed_ms: elapsed,
              peer_options: peer_options
            })
          )

          loop.(loop, watch)

        %{"op" => "await_down", "name" => name} = command ->
          %{name: ^name, peer: peer, reference: reference} = watch
          budget = Map.get(command, "remaining_ms", 1500)
          true = is_integer(budget) and budget > 0 and budget <= 1500
          started = System.monotonic_time(:millisecond)
          deadline = started + budget
          same_incarnation.(name, peer, deadline)
          receive_ms = remaining.(deadline)

          receive do
            {:DOWN, ^reference, :process, ^peer, :normal} ->
              :ok

            {:DOWN, ^reference, :process, ^peer, reason} ->
              raise "watched peer DOWN was not normal: #{inspect(reason)}"
          after
            receive_ms -> raise "watched peer DOWN deadline"
          end

          down_elapsed = System.monotonic_time(:millisecond) - started
          _ = remaining.(deadline)
          Process.demonitor(reference, [:flush])
          same_incarnation.(name, peer, deadline)
          observer = Map.get(command, "observer")
          observer_peer = resolve.(observer, remaining.(deadline))
          captured = Resources.capture(peer, observer_peer, remaining.(deadline))
          _ = remaining.(deadline)
          elapsed = System.monotonic_time(:millisecond) - started

          emit.(
            Map.merge(captured, %{
              event: "down",
              name: name,
              peer: inspect(peer),
              reference: inspect(reference),
              reason: "normal",
              elapsed_ms: elapsed,
              down_elapsed_ms: down_elapsed,
              elapsed_basis: "await_down matching receive and fresh capture",
              monitored: true,
              watch_removed: true,
              watches: 0,
              observer: observer
            })
          )

          loop.(loop, nil)

        %{"op" => "quit"} ->
          watch

        other ->
          raise "unknown PRO05 fixture command #{inspect(other)}"
      end
  end
end

try do
  # The first connection-close log lazily loads OTP's timestamp formatter.
  # VM7 attributed its one-time 42-atom increase to calendar; load that fixed
  # runtime module before resource baselines, without sending target traffic.
  Code.ensure_loaded!(:calendar)

  # Initialize constant live/absent metric and JSON paths without target traffic.
  initialized = Resources.capture(nil, nil)
  %{complete: true, errors: []} = initialized
  _ = Resources.delta(initialized.resources, initialized.resources)
  _ = :json.encode(initialized)

  emit.(%{
    event: "ready",
    pid: System.pid(),
    otp: to_string(:erlang.system_info(:system_version)),
    elixir: System.version(),
    identity: identity,
    core: Resources.core(),
    policy: inspect(rules, limit: :infinity),
    configuration: %{
      profile: "system",
      lifecycle: "embedded",
      config_file:
        case Application.get_env(:gao_bus, :config_file) do
          nil -> :null
          value -> value
        end,
      inherited_listener: Application.get_env(:gao_bus, :inherited_listener, false),
      socket_path: socket,
      authentication: ["EXTERNAL"],
      cluster: false,
      capability_restrictions: false,
      auth_limits: %{timeout_ms: 1500, idle_timeout_ms: 500},
      resource_limits: GaoBus.Limits.defaults()
    }
  })

  remaining_watch = loop.(loop, nil)
  if remaining_watch, do: Process.demonitor(remaining_watch.reference, [:flush])
after
  :ok = Application.stop(:gao_bus)
end

emit.(%{event: "stopped", normal: true, watches: 0})
