defmodule GaoBus.BusInterface do
  @moduledoc """
  Implementation of the org.freedesktop.DBus interface.

  The bus itself responds to these standard methods:
  - Hello() → assign unique name
  - RequestName(name, flags) → register well-known name
  - ReleaseName(name) → release
  - GetNameOwner(name) → lookup
  - ListNames() → all registered names
  - ListActivatableNames() → names from the captured configuration generation
  - NameHasOwner(name) → boolean check
  - AddMatch(rule) → subscribe to signals
  - RemoveMatch(rule) → unsubscribe
  - GetId() → bus instance ID
  - Introspect() → introspection XML (on org.freedesktop.DBus.Introspectable)
  """

  alias ExDBus.Message

  @bus_name "org.freedesktop.DBus"
  @credential_methods [
    "GetConnectionUnixUser",
    "GetConnectionUnixProcessID",
    "GetConnectionCredentials"
  ]
  @implemented_interfaces [
    @bus_name,
    "org.freedesktop.DBus.Introspectable",
    "org.freedesktop.DBus.Properties",
    "org.freedesktop.DBus.Peer"
  ]

  @doc """
  Handle a message addressed to org.freedesktop.DBus.

  Returns `{reply_message | nil, updated_router_state}`.
  """
  @spec handle_message(Message.t(), pid(), map()) :: {Message.t() | nil, map()}
  def handle_message(msg, from_peer_pid, state),
    do: handle_message(msg, from_peer_pid, state, :synchronous)

  @doc false
  def handle_message(%Message{type: :method_call} = msg, from_peer_pid, state, mode)
      when mode in [:synchronous, :deferred] do
    case GaoBus.BusMethod.resolve(msg) do
      {:ok, validated} ->
        authorize_method(validated, from_peer_pid, state, mode)

      {:error, name, explanation} ->
        make_error(msg, "org.freedesktop.DBus.Error." <> name, explanation, state)
    end
  end

  def handle_message(_msg, _from_peer_pid, state, _mode), do: {nil, state}

  defp authorize_method(msg, from_peer_pid, state, mode) do
    case control_scope(msg) do
      nil ->
        validate_and_dispatch(msg, from_peer_pid, state, mode)

      {action, scope} ->
        context = %{
          credentials: credentials(state, from_peer_pid),
          control: scope,
          name: List.first(msg.body),
          message: msg,
          sender_names:
            state.peers |> Map.get(from_peer_pid, %{}) |> Map.get(:unique_name) |> List.wrap(),
          destination_names: [@bus_name]
        }

        case GaoBus.Policy.authorize(policy_snapshot(state), action, context) do
          {:allow, _} ->
            validate_and_dispatch(msg, from_peer_pid, state, mode)

          {:deny, _} ->
            denied(msg, state)
        end
    end
  end

  defp validate_and_dispatch(msg, from_peer_pid, state, mode) do
    case GaoBus.BusMethod.validate_arguments(msg) do
      {:ok, validated} ->
        if control_scope(validated),
          do: dispatch_control(validated, state, mode),
          else: dispatch_message(validated, from_peer_pid, state)

      {:error, name, explanation} ->
        make_error(msg, "org.freedesktop.DBus.Error." <> name, explanation, state)
    end
  end

  defp dispatch_control(%{member: "ReloadConfig"} = msg, state, :deferred) do
    result =
      if Map.get(state, :reload_waiter),
        do: {:error, :reload_busy},
        else: GaoBus.Policy.request_reload_file(self())

    case result do
      {:ok, handle} -> {{:deferred, handle}, state}
      {:error, _reason} = error -> reload_reply(msg, error, state)
    end
  end

  defp dispatch_control(%{member: "ReloadConfig"} = msg, state, :synchronous),
    do: reload_reply(msg, GaoBus.Policy.reload_file(), state)

  defp dispatch_control(
         %{member: "StartServiceByName"} = msg,
         %{activation_options: options} = state,
         :deferred
       )
       when not is_nil(options),
       do: {{:activation_start, msg}, state}

  defp dispatch_control(msg, state, _mode),
    do:
      make_error(
        msg,
        "org.freedesktop.DBus.Error.NotSupported",
        "Control is not implemented",
        state
      )

  @doc false
  def activation_reply(request, result, state) when result in [1, 2],
    do: make_reply(request, "u", [result], state)

  @doc false
  def reload_reply(request, result, state) do
    case result do
      {:ok, _generation} ->
        make_reply(request, "", [], state)

      {:error, :reload_busy} ->
        make_error(
          request,
          "org.freedesktop.DBus.Error.LimitsExceeded",
          "Configuration reload was rejected",
          state
        )

      {:error, :file_reload_unavailable} ->
        make_error(
          request,
          "org.freedesktop.DBus.Error.NotSupported",
          "No reloadable configuration",
          state
        )

      {:error, %{reason: {:file_error, :enoent}}} ->
        make_error(
          request,
          "org.freedesktop.DBus.Error.FileNotFound",
          "Configuration reload was rejected",
          state
        )

      {:error, _reason} ->
        make_error(
          request,
          "org.freedesktop.DBus.Error.Failed",
          "Configuration reload was rejected",
          state
        )
    end
  end

  defp dispatch_message(msg, from_peer_pid, state) do
    case {msg.interface, msg.member} do
      {"org.freedesktop.DBus.Introspectable", "Introspect"} ->
        handle_introspect(msg, from_peer_pid, state)

      {"org.freedesktop.DBus.Properties", "Get"} ->
        handle_properties_get(msg, from_peer_pid, state)

      {"org.freedesktop.DBus.Properties", "GetAll"} ->
        handle_properties_get_all(msg, from_peer_pid, state)

      {"org.freedesktop.DBus.Properties", "Set"} ->
        handle_properties_set(msg, from_peer_pid, state)

      {"org.freedesktop.DBus.Peer", "Ping"} ->
        make_reply(msg, "", [], state)

      {"org.freedesktop.DBus.Peer", "GetMachineId"} ->
        case GaoBus.Ids.machine_id() do
          {:ok, id} ->
            make_reply(msg, "s", [id], state)

          {:error, :machine_id_unavailable} ->
            make_error(
              msg,
              "org.freedesktop.DBus.Error.Failed",
              "Machine identity is unavailable",
              state
            )
        end

      _ ->
        dispatch_bus_method(msg, from_peer_pid, state)
    end
  end

  defp dispatch_bus_method(msg, from_peer_pid, state) do
    case msg.member do
      "Hello" -> handle_hello(msg, from_peer_pid, state)
      "RequestName" -> handle_request_name(msg, from_peer_pid, state)
      "ReleaseName" -> handle_release_name(msg, from_peer_pid, state)
      "GetNameOwner" -> handle_get_name_owner(msg, from_peer_pid, state)
      "ListQueuedOwners" -> handle_list_queued_owners(msg, from_peer_pid, state)
      "ListNames" -> handle_list_names(msg, from_peer_pid, state)
      _ -> dispatch_bus_method_ext(msg, from_peer_pid, state)
    end
  end

  defp dispatch_bus_method_ext(msg, from_peer_pid, state) do
    case msg.member do
      "ListActivatableNames" ->
        handle_list_activatable_names(msg, from_peer_pid, state)

      "NameHasOwner" ->
        handle_name_has_owner(msg, from_peer_pid, state)

      "AddMatch" ->
        handle_add_match(msg, from_peer_pid, state)

      "RemoveMatch" ->
        handle_remove_match(msg, from_peer_pid, state)

      "GetId" ->
        handle_get_id(msg, from_peer_pid, state)

      member when member in @credential_methods ->
        handle_connection_credentials(msg, state)

      _ ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.UnknownMethod",
          "Unknown method: #{msg.member}",
          state
        )
    end
  end

  # --- Method handlers ---

  defp handle_connection_credentials(%{body: [name]} = msg, state) do
    case connection_credentials(name, state) do
      {:ok, credentials} ->
        case msg.member do
          "GetConnectionUnixUser" ->
            credential_reply(msg, credentials, :uid, state)

          "GetConnectionUnixProcessID" ->
            credential_reply(msg, credentials, :pid, state)

          "GetConnectionCredentials" ->
            entries =
              for {key, field} <- [{"UnixUserID", :uid}, {"ProcessID", :pid}],
                  value = Map.get(credentials, field),
                  uint32?(value),
                  do: {key, {"u", value}}

            make_reply(msg, "a{sv}", [entries ++ group_credential(credentials)], state)
        end

      {:error, :name_not_found} ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.NameHasNoOwner",
          "Name has no registered owner",
          state
        )
    end
  end

  defp group_credential(%{groups: groups, gid: primary} = credentials) when is_list(groups) do
    if not Map.has_key?(credentials, :groups_error) and length(groups) <= 65_537 and
         primary in groups and Enum.all?(groups, &(uint32?(&1) and &1 != 0xFFFFFFFF)) do
      [{"UnixGroupIDs", {"au", Enum.sort(groups)}}]
    else
      []
    end
  end

  defp group_credential(_credentials), do: []

  defp connection_credentials(name, state) do
    case GaoBus.NameRegistry.resolve_with_names(name) do
      {:bus, _pid} ->
        {:ok, GaoBus.Unix.Native.identity()}

      {:ok, pid, names} ->
        case state.peers[pid] do
          %{unique_name: unique, credentials: credentials} when is_binary(unique) ->
            if unique in names, do: {:ok, credentials}, else: {:error, :name_not_found}

          _ ->
            {:error, :name_not_found}
        end

      {:error, :name_not_found} ->
        {:error, :name_not_found}
    end
  end

  defp credential_reply(msg, credentials, field, state) do
    value = Map.get(credentials, field)

    if uint32?(value),
      do: make_reply(msg, "u", [value], state),
      else:
        make_error(
          msg,
          "org.freedesktop.DBus.Error.NotSupported",
          "Credential is unavailable",
          state
        )
  end

  defp uint32?(value), do: is_integer(value) and value in 0..0xFFFFFFFF

  defp handle_hello(msg, from_peer_pid, state) do
    # Assign a unique connection name
    unique_name = state.peers[from_peer_pid].unique_name

    case unique_name do
      nil ->
        # First Hello — assign name
        case GaoBus.Peer.assign_unique_name(from_peer_pid) do
          name when is_binary(name) ->
            credentials = credentials(state, from_peer_pid) |> Map.put(:unique_name, name)
            GaoBus.NameRegistry.register_unique(name, from_peer_pid)

            state =
              update_in(
                state.peers[from_peer_pid],
                &%{&1 | unique_name: name, credentials: credentials}
              )

            {reply, state} = make_reply(%{msg | sender: name}, "s", [name], state)
            {reply, state}

          {:error, {:xml_limit_exceeded, limit}} ->
            make_error(msg, "org.freedesktop.DBus.Error.LimitsExceeded", limit, state)

          {:error, _reason} ->
            make_error(msg, "org.freedesktop.DBus.Error.Failed", "Hello admission failed", state)
        end

      _ ->
        # Already has a name — error per spec
        make_error(msg, "org.freedesktop.DBus.Error.Failed", "Already called Hello", state)
    end
  end

  defp handle_request_name(msg, from_peer_pid, state) do
    [name, flags] = msg.body
    credentials = credentials(state, from_peer_pid)

    with {:allow, _} <-
           GaoBus.Policy.authorize(policy_snapshot(state), :own, %{
             credentials: credentials,
             name: name
           }),
         :allow <- capability_own(credentials, name) do
      unique_name = state.peers[from_peer_pid].unique_name

      case GaoBus.NameRegistry.request_name(name, flags, from_peer_pid, unique_name) do
        {:ok, result} -> make_reply(msg, "u", [result], state)
        {:error, error} -> make_error(msg, error, "Name request rejected", state)
      end
    else
      _ -> denied(msg, state)
    end
  end

  defp handle_release_name(msg, from_peer_pid, state) do
    [name] = msg.body

    case GaoBus.NameRegistry.release_name(name, from_peer_pid) do
      {:ok, result} -> make_reply(msg, "u", [result], state)
      {:error, error} -> make_error(msg, error, "Invalid name to release", state)
    end
  end

  defp handle_list_queued_owners(msg, _from_peer_pid, state) do
    [name] = msg.body

    case GaoBus.NameRegistry.list_queued_owners(name) do
      {:ok, owners} -> make_reply(msg, "as", [owners], state)
      {:error, error} -> make_error(msg, error, "Name has no queued owners", state)
    end
  end

  defp handle_get_name_owner(msg, _from_peer_pid, state) do
    [name] = msg.body

    case GaoBus.NameRegistry.get_name_owner(name) do
      {:ok, owner} ->
        {reply, state} = make_reply(msg, "s", [owner], state)
        {reply, state}

      {:error, error_name} ->
        make_error(
          msg,
          error_name,
          "The name #{name} was not provided by any .service files",
          state
        )
    end
  end

  defp handle_list_names(msg, _from_peer_pid, state) do
    names = GaoBus.NameRegistry.list_names()
    {reply, state} = make_reply(msg, "as", [names], state)
    {reply, state}
  end

  defp handle_name_has_owner(msg, _from_peer_pid, state) do
    [name] = msg.body
    has_owner = GaoBus.NameRegistry.name_has_owner?(name)
    {reply, state} = make_reply(msg, "b", [has_owner], state)
    {reply, state}
  end

  defp handle_get_id(msg, _from_peer_pid, state) do
    id = GaoBus.Ids.bus_id()
    {reply, state} = make_reply(msg, "s", [id], state)
    {reply, state}
  end

  defp handle_list_activatable_names(msg, _from_peer_pid, state) do
    names = GaoBus.Policy.activatable_names(policy_snapshot(state))
    {reply, state} = make_reply(msg, "as", [names], state)
    {reply, state}
  end

  defp handle_add_match(msg, from_peer_pid, state) do
    [rule_string] = msg.body

    case GaoBus.MatchRules.parse(rule_string) do
      {:ok, %{eavesdrop: true}} ->
        context = %{credentials: credentials(state, from_peer_pid), control: :monitor}

        case GaoBus.Policy.authorize(policy_snapshot(state), :monitor, context) do
          {:allow, _} ->
            make_error(
              msg,
              "org.freedesktop.DBus.Error.NotSupported",
              "Monitoring is not implemented",
              state
            )

          {:deny, _} ->
            denied(msg, state)
        end

      _ ->
        add_match(msg, from_peer_pid, rule_string, state)
    end
  end

  defp add_match(msg, from_peer_pid, rule_string, state) do
    case GaoBus.MatchRules.add_match(from_peer_pid, rule_string) do
      :ok ->
        {reply, state} = make_reply(msg, nil, [], state)
        {reply, state}

      {:error, :limits_exceeded} ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.LimitsExceeded",
          "Match limit exceeded",
          state
        )

      {:error, :identity_unavailable} ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.Failed",
          "Match identity is unavailable",
          state
        )

      {:error, reason} ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.MatchRuleInvalid",
          "Invalid match rule: #{inspect(reason)}",
          state
        )
    end
  end

  defp handle_remove_match(msg, from_peer_pid, state) do
    [rule_string] = msg.body

    case GaoBus.MatchRules.remove_match(from_peer_pid, rule_string) do
      :ok ->
        {reply, state} = make_reply(msg, nil, [], state)
        {reply, state}

      {:error, error_name} when is_binary(error_name) ->
        make_error(msg, error_name, "Match rule not found", state)

      {:error, _reason} ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.MatchRuleInvalid",
          "Invalid match rule",
          state
        )
    end
  end

  defp handle_introspect(msg, _from_peer_pid, state) do
    interfaces = [
      ExDBus.Introspection.bus_interface(),
      ExDBus.Introspection.introspectable_interface(),
      ExDBus.Introspection.peer_interface()
    ]

    interfaces =
      if msg.path == "/org/freedesktop/DBus",
        do: interfaces ++ [ExDBus.Introspection.properties_interface()],
        else: interfaces

    children =
      Map.get(
        %{
          "/" => ["org/freedesktop/DBus"],
          "/org" => ["freedesktop/DBus"],
          "/org/freedesktop" => ["DBus"]
        },
        msg.path,
        []
      )

    xml =
      ExDBus.Introspection.to_xml(
        msg.path,
        interfaces,
        children
      )

    {reply, state} = make_reply(msg, "s", [xml], state)
    {reply, state}
  end

  defp handle_properties_get(msg, _from_peer_pid, state) do
    [interface_name, property_name] = msg.body

    cond do
      interface_name not in ["" | @implemented_interfaces] ->
        make_error(msg, "org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface", state)

      interface_name in ["", @bus_name] and property_name in ["Features", "Interfaces"] ->
        make_reply(msg, "v", [{"as", []}], state)

      true ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.UnknownProperty",
          "Unknown property: #{property_name}",
          state
        )
    end
  end

  defp handle_properties_get_all(msg, _from_peer_pid, state) do
    [interface_name] = msg.body

    cond do
      interface_name in ["", @bus_name] ->
        make_reply(msg, "a{sv}", [[{"Features", {"as", []}}, {"Interfaces", {"as", []}}]], state)

      interface_name in @implemented_interfaces ->
        make_reply(msg, "a{sv}", [[]], state)

      true ->
        make_error(msg, "org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface", state)
    end
  end

  defp handle_properties_set(msg, _from_peer_pid, state) do
    [interface_name, property_name, _value] = msg.body

    cond do
      interface_name not in ["" | @implemented_interfaces] ->
        make_error(msg, "org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface", state)

      interface_name in ["", @bus_name] and property_name in ["Features", "Interfaces"] ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.PropertyReadOnly",
          "Property '#{interface_name}.#{property_name}' cannot be set",
          state
        )

      true ->
        make_error(
          msg,
          "org.freedesktop.DBus.Error.UnknownProperty",
          "Unknown property: #{property_name}",
          state
        )
    end
  end

  # --- Reply helpers ---

  defp credentials(state, pid) do
    case state.peers[pid] do
      %{credentials: credentials} -> credentials
      _ -> %{}
    end
  end

  defp policy_snapshot(state),
    do: Map.get_lazy(state, :policy_snapshot, &GaoBus.Policy.snapshot/0)

  defp capability_own(credentials, name) do
    if Application.get_env(:gao_bus, :capability_restrictions, false),
      do: GaoBus.Policy.Capability.check_own(credentials, name),
      else: :allow
  end

  defp control_scope(%{interface: "org.freedesktop.DBus.Monitoring", member: "BecomeMonitor"}),
    do: {:monitor, :monitor}

  defp control_scope(%{member: "ReloadConfig"}), do: {:control, :reload}

  defp control_scope(%{member: "UpdateActivationEnvironment"}),
    do: {:control, :activation_environment}

  defp control_scope(%{member: "StartServiceByName"}), do: {:activate, :start_service}
  defp control_scope(_message), do: nil

  defp denied(message, state),
    do:
      make_error(
        message,
        "org.freedesktop.DBus.Error.AccessDenied",
        "Operation denied by bus policy",
        state
      )

  defp make_reply(msg, signature, body, state) do
    {serial, state} = next_serial(state)

    reply =
      Message.method_return(msg.serial,
        serial: serial,
        destination: msg.sender,
        sender: @bus_name,
        signature: signature,
        body: body
      )

    {reply, state}
  end

  defp make_error(msg, error_name, error_msg, state) do
    {serial, state} = next_serial(state)

    error =
      Message.error(error_name, msg.serial,
        serial: serial,
        destination: msg.sender,
        sender: @bus_name,
        signature: "s",
        body: [error_msg]
      )

    {error, state}
  end

  defp next_serial(state) do
    serial = state.next_serial
    next = if serial >= 0xFFFFFFFF, do: 1, else: serial + 1
    {serial, %{state | next_serial: next}}
  end
end
