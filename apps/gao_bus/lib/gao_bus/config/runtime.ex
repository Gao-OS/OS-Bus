defmodule GaoBus.Config.Runtime do
  @moduledoc """
  Pure binding of XML configuration to one immutable startup plan.

  XML limits retain their reference meaning separately from finite Foundation
  safety budgets. Compiling a plan does not start a listener or mutate runtime
  configuration. Application must verify each consumer before using the plan.
  """
  alias GaoBus.{Config, Limits}

  @max_output_bytes 134_217_728

  # dbus-daemon 1.14.10 bus/config-parser.c:488-554, dbus-sysdeps.h.
  @defaults %{
    "max_incoming_bytes" => 133_169_152,
    "max_incoming_unix_fds" => 64,
    "max_outgoing_bytes" => 133_169_152,
    "max_outgoing_unix_fds" => 64,
    "max_message_size" => 33_554_432,
    "max_message_unix_fds" => 16,
    "service_start_timeout" => 25_000,
    "auth_timeout" => 30_000,
    "pending_fd_timeout" => 150_000,
    "max_completed_connections" => 2048,
    "max_incomplete_connections" => 64,
    "max_connections_per_user" => 256,
    "max_pending_service_starts" => 512,
    "max_names_per_connection" => 512,
    "max_match_rules_per_connection" => 512,
    "max_replies_per_connection" => 128,
    "reply_timeout" => :infinity
  }
  @long_limits ~w(max_incoming_bytes max_incoming_unix_fds max_outgoing_bytes max_outgoing_unix_fds max_message_size max_message_unix_fds)
  @zero_supported ~w(max_incoming_bytes max_incoming_unix_fds max_outgoing_bytes max_outgoing_unix_fds max_completed_connections max_incomplete_connections max_connections_per_user max_names_per_connection max_match_rules_per_connection max_replies_per_connection auth_timeout pending_fd_timeout reply_timeout)
  @settings [
    :type,
    :user,
    :auth,
    :listen,
    :fork,
    :pidfile,
    :syslog,
    :apparmor,
    :servicedir,
    :servicehelper,
    :keep_umask
  ]
  @activation_limits ~w(service_start_timeout max_pending_service_starts)

  def compile(%Config{settings: settings, limits: limits} = config, invocation, %{uid: uid})
      when is_map(settings) and is_map(limits) and is_map(invocation) and
             is_integer(uid) and uid >= 0 and uid < 0xFFFFFFFF do
    profile = Map.get(invocation, :profile, :system)

    with :ok <- identity(config, profile, uid),
         :ok <- settings(settings, invocation),
         {:ok, socket_path} <- listener(settings, invocation),
         :ok <- limits(limits),
         xml = Map.merge(@defaults, limits),
         {:ok, safety} <- safety(xml, Map.get(invocation, :safety_limits, %{})) do
      peer_options = [xml_limits: xml, frame_timeout_ms: 5000]

      {:ok,
       %{
         configuration: config,
         profile: profile,
         xml_limits: xml,
         safety_limits: safety,
         logging: :stderr,
         limits_options: [limits: safety, xml_limits: xml],
         peer_options: peer_options,
         peer_supervisor_options: [
           max_children:
             max(1, xml["max_completed_connections"] + xml["max_incomplete_connections"])
         ],
         listener_options: [socket_path: socket_path, peer_options: peer_options],
         name_options: [xml_limits: xml],
         match_options: [xml_limits: xml],
         router_options: [
           max_output_bytes: @max_output_bytes,
           pending_limits: %{
             per_peer: xml["max_replies_per_connection"],
             per_uid: max(512, xml["max_replies_per_connection"]),
             global: max(4096, xml["max_replies_per_connection"]),
             timeout_ms: reply_timeout(xml["reply_timeout"])
           }
         ]
       }}
    else
      {:error, reason} -> refusal(config, reason)
    end
  end

  def compile(%Config{} = config, _, _), do: refusal(config, :invalid_runtime_configuration)
  def compile(_, _, _), do: {:error, :invalid_runtime_configuration}

  defp refusal(%Config{sources: [], directives: []}, reason), do: {:error, reason}

  defp refusal(config, reason) do
    {kind, names} = refusal_directives(reason)

    origins = Config.directive_origins(config, kind, names)

    {:error, %{reason: reason, origins: origins}}
  end

  defp refusal_directives(:configuration_profile_mismatch), do: {:setting, [:type]}
  defp refusal_directives(:daemon_uid_mismatch), do: {:setting, [:user]}
  defp refusal_directives({:unsupported_runtime_setting, name}), do: {:setting, [name]}
  defp refusal_directives({:unimplemented_activation_settings, names}), do: {:setting, names}
  defp refusal_directives({:unimplemented_runtime_limits, names}), do: {:limit, names}
  defp refusal_directives({:invalid_runtime_limit, name}), do: {:limit, [name]}
  defp refusal_directives({:unsupported_zero_limit, name}), do: {:limit, [name]}

  defp refusal_directives({:unsupported_message_fd_limit, _}),
    do: {:limit, ["max_message_unix_fds"]}

  defp refusal_directives({:unsupported_message_size, _}), do: {:limit, ["max_message_size"]}

  defp refusal_directives({reason, scope, metric})
       when reason in [:inconsistent_safety_limit, :unrepresentable_safety_limit] do
    names =
      case metric do
        :frame_bytes ->
          ["max_message_size"]

        :frame_fds ->
          ["max_message_unix_fds"]

        :ingress_bytes ->
          ["max_incoming_bytes", "max_message_size"]

        :egress_bytes ->
          ["max_outgoing_bytes"]

        :ingress_fds ->
          ["max_incoming_unix_fds", "max_message_unix_fds"]

        :egress_fds ->
          ["max_outgoing_unix_fds", "max_message_unix_fds"]

        :connections ->
          case scope do
            :uid -> ["max_connections_per_user", "max_incomplete_connections"]
            :global -> ["max_completed_connections", "max_incomplete_connections"]
            _ -> []
          end

        :authenticating ->
          ["max_incomplete_connections"]

        _ ->
          []
      end

    {:limit, names}
  end

  defp refusal_directives(_reason), do: {:setting, []}

  # dbus-daemon 1.14.10 bus/expirelist.c:149-180: zero disables timed expiry.
  defp reply_timeout(0), do: :infinity
  defp reply_timeout(value), do: value

  defp identity(config, profile, uid) do
    cond do
      profile not in [:system, :session] ->
        {:error, :unsupported_profile}

      Map.get(config.settings, :type, profile) != profile ->
        {:error, :configuration_profile_mismatch}

      config.daemon_uid != uid ->
        {:error, :daemon_uid_mismatch}

      Map.get(config.settings, :user, uid) != uid ->
        {:error, :daemon_uid_mismatch}

      true ->
        :ok
    end
  end

  defp settings(settings, invocation) do
    unknown = (Map.keys(settings) -- @settings) |> Enum.sort()

    activation =
      Map.keys(settings) |> Enum.filter(&(&1 in [:servicedir, :servicehelper])) |> Enum.sort()

    cond do
      unknown != [] ->
        {:error, {:unsupported_runtime_setting, hd(unknown)}}

      Enum.any?(
        [:fork, :syslog, :keep_umask],
        &(is_map_key(settings, &1) and not is_boolean(Map.get(settings, &1)))
      ) ->
        {:error, :invalid_runtime_configuration}

      Map.get(invocation, :log_target, :stderr) != :stderr ->
        {:error, {:unsupported_runtime_setting, :log_target}}

      Map.get(settings, :fork, false) and Map.get(invocation, :nofork) != true ->
        {:error, {:unsupported_runtime_setting, :fork}}

      Map.has_key?(settings, :pidfile) and Map.get(invocation, :nopidfile) != true ->
        {:error, {:unsupported_runtime_setting, :pidfile}}

      Map.get(settings, :syslog, false) and Map.get(invocation, :log_target) != :stderr ->
        {:error, {:unsupported_runtime_setting, :syslog}}

      Map.get(settings, :auth, ["EXTERNAL"]) not in [[], ["EXTERNAL"]] ->
        {:error, {:unsupported_runtime_setting, :auth}}

      Map.get(settings, :apparmor, :disabled) != :disabled ->
        {:error, {:unsupported_runtime_setting, :apparmor}}

      Map.has_key?(settings, :keep_umask) ->
        {:error, {:unsupported_runtime_setting, :keep_umask}}

      activation != [] ->
        {:error, {:unimplemented_activation_settings, activation}}

      true ->
        :ok
    end
  end

  defp listener(settings, invocation) do
    path =
      case Map.fetch(invocation, :socket_path) do
        {:ok, path} ->
          path

        :error ->
          case Map.get(settings, :listen, []) do
            ["unix:path=" <> path] -> path
            _ -> nil
          end
      end

    if is_binary(path) and byte_size(path) in 1..107 and Path.type(path) == :absolute and
         not String.contains?(path, <<0>>),
       do: {:ok, path},
       else: {:error, {:unsupported_runtime_setting, :listen}}
  end

  defp limits(limits) do
    Enum.reduce_while(Enum.sort(limits), :ok, fn {name, value}, :ok ->
      maximum = if name in @long_limits, do: 0x7FFFFFFFFFFFFFFF, else: 0x7FFFFFFF

      result =
        cond do
          not is_map_key(@defaults, name) or not is_integer(value) or value < 0 or value > maximum ->
            {:error, {:invalid_runtime_limit, name}}

          name in @activation_limits ->
            {:error, {:unimplemented_runtime_limits, [name]}}

          value == 0 and name not in @zero_supported ->
            {:error, {:unsupported_zero_limit, name}}

          name == "max_message_unix_fds" and value > 253 ->
            {:error, {:unsupported_message_fd_limit, value}}

          name == "max_message_size" and value > 134_217_728 ->
            {:error, {:unsupported_message_size, value}}

          true ->
            :ok
        end

      if result == :ok, do: {:cont, :ok}, else: {:halt, result}
    end)
  end

  defp safety(xml, overrides) when is_map(overrides) do
    message = xml["max_message_size"]
    fds = xml["max_message_unix_fds"]
    incoming = xml["max_incoming_bytes"] + message
    # max_message_size bounds input. Generated replies and sender-header growth
    # are bounded by the protocol maximum, rather than that input-only setting.
    outgoing = xml["max_outgoing_bytes"] + @max_output_bytes
    incoming_fds = xml["max_incoming_unix_fds"] + fds
    outgoing_fds = xml["max_outgoing_unix_fds"] + fds

    defaults =
      Map.new(Limits.defaults(), fn {scope, values} ->
        factor =
          case scope do
            :peer -> 1
            :uid -> 2
            :global -> 4
          end

        values =
          Map.merge(values, %{
            frame_bytes: message * factor,
            frame_fds: max(values.frame_fds, fds * factor),
            ingress_bytes: incoming * factor,
            egress_bytes: outgoing * factor,
            ingress_fds: (xml["max_incoming_unix_fds"] + fds) * factor,
            egress_fds: (xml["max_outgoing_unix_fds"] + fds) * factor
          })

        values =
          case scope do
            :peer ->
              values

            :uid ->
              Map.merge(values, %{
                connections:
                  max(1, xml["max_connections_per_user"] + xml["max_incomplete_connections"]),
                authenticating: max(1, xml["max_incomplete_connections"])
              })

            :global ->
              Map.merge(values, %{
                connections:
                  max(1, xml["max_completed_connections"] + xml["max_incomplete_connections"]),
                authenticating: max(1, xml["max_incomplete_connections"])
              })
          end

        {scope, values}
      end)

    if Map.keys(overrides) -- Map.keys(defaults) != [] do
      {:error, :invalid_safety_limits}
    else
      merge_safety(
        defaults,
        overrides,
        message,
        fds,
        incoming,
        outgoing,
        incoming_fds,
        outgoing_fds
      )
    end
  end

  defp safety(_, _), do: {:error, :invalid_safety_limits}

  defp merge_safety(
         defaults,
         overrides,
         message,
         fds,
         incoming,
         outgoing,
         incoming_fds,
         outgoing_fds
       ) do
    Enum.reduce_while(defaults, {:ok, %{}}, fn {scope, values}, {:ok, acc} ->
      overrides = Map.get(overrides, scope, %{})

      if is_map(overrides) and Map.keys(overrides) -- Map.keys(values) == [] do
        values = Map.merge(values, overrides)

        result =
          Enum.find_value(values, fn {metric, value} ->
            cond do
              not is_integer(value) or value not in 1..0x7FFFFFFF ->
                {:error, {:unrepresentable_safety_limit, scope, metric}}

              metric == :frame_bytes and value < message ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              metric == :ingress_bytes and value < incoming ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              metric == :egress_bytes and value < outgoing ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              metric == :frame_fds and value < fds ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              metric == :ingress_fds and value < incoming_fds ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              metric == :egress_fds and value < outgoing_fds ->
                {:error, {:inconsistent_safety_limit, scope, metric}}

              true ->
                nil
            end
          end)

        if result, do: {:halt, result}, else: {:cont, {:ok, Map.put(acc, scope, values)}}
      else
        {:halt, {:error, :invalid_safety_limits}}
      end
    end)
  end
end
