defmodule GaoBus.Application do
  @moduledoc false

  use Application

  alias GaoBus.Config.Runtime

  @impl true
  def start(_type, _args) do
    profile = Application.get_env(:gao_bus, :profile, :system)
    lifecycle = Application.get_env(:gao_bus, :lifecycle, :embedded)
    inherited = Application.get_env(:gao_bus, :inherited_listener, false)

    cond do
      profile not in [:system, :session] ->
        {:error, {:unsupported_profile, profile}}

      profile == :system and Application.get_env(:gao_bus, :cluster, false) ->
        {:error, :unsupported_system_cluster}

      lifecycle not in [:embedded, :release] ->
        {:error, {:unsupported_lifecycle, lifecycle}}

      not is_boolean(inherited) ->
        {:error, :invalid_inherited_listener_mode}

      inherited and lifecycle != :release ->
        {:error, :inherited_listener_requires_release_lifecycle}

      lifecycle == :release and is_nil(Application.get_env(:gao_bus, :config_file)) ->
        {:error, :missing_configuration}

      true ->
        with {:ok, plan} <- load_configuration(profile) do
          start_core(plan, lifecycle, inherited)
        end
    end
  end

  defp load_configuration(profile) do
    case Application.get_env(:gao_bus, :config_file) do
      nil ->
        {:ok,
         %{
           policy_options: [],
           limits_options: [limits: Application.get_env(:gao_bus, :resource_limits, %{})],
           name_options: [],
           match_options: [],
           router_options: [],
           peer_supervisor_options: [],
           listener_options: [
             socket_path: Application.get_env(:gao_bus, :socket_path, "/tmp/gao_bus_socket")
           ]
         }}

      path when is_binary(path) ->
        identity = GaoBus.Unix.Native.identity()

        options =
          :gao_bus
          |> Application.get_env(:config_options, [])
          |> Keyword.put(:daemon_uid, identity.uid)

        with true <- identity.uid == identity.real_uid and identity.gid == identity.real_gid,
             {:ok, config} <- GaoBus.Config.load(path, options),
             {:ok, invocation} <- runtime_invocation(profile),
             {:ok, plan} <- Runtime.compile(config, invocation, identity),
             {:ok, _compiled} <- GaoBus.Policy.compile(config) do
          {:ok,
           Map.put(plan, :policy_options,
             rules: config,
             config_file: path,
             config_options: options
           )}
        else
          false -> {:error, {:invalid_configuration, :daemon_identity_mismatch}}
          {:error, reason} -> {:error, {:invalid_configuration, reason}}
        end

      _ ->
        {:error, {:invalid_configuration, :invalid_config_file}}
    end
  end

  defp runtime_invocation(profile) do
    case Application.get_env(:gao_bus, :runtime_invocation, %{}) do
      invocation when is_map(invocation) ->
        invocation =
          invocation
          |> Map.put(:profile, profile)
          |> Map.put_new(:safety_limits, Application.get_env(:gao_bus, :resource_limits, %{}))

        invocation =
          case Application.fetch_env(:gao_bus, :socket_path) do
            {:ok, path} -> Map.put(invocation, :socket_path, path)
            :error -> invocation
          end

        {:ok, invocation}

      _ ->
        {:error, :invalid_runtime_invocation}
    end
  end

  defp start_core(plan, lifecycle, inherited) do
    listener_options =
      if inherited,
        do: Keyword.put(plan.listener_options, :inherited, true),
        else: plan.listener_options

    children =
      [
        GaoBus.Ids,
        {Registry, keys: :unique, name: GaoBus.PeerRegistry},
        {GaoBus.Limits, plan.limits_options},
        {GaoBus.Policy, Keyword.put(plan.policy_options, :publication, :router)},
        {GaoBus.NameRegistry, plan.name_options},
        {GaoBus.MatchRules, plan.match_options},
        GaoBus.Policy.Capability,
        {GaoBus.Router, plan.router_options},
        {DynamicSupervisor, name: GaoBus.Activation.HelperSupervisor, strategy: :one_for_one},
        {GaoBus.Activation, Map.get(plan, :activation_options, [])},
        {GaoBus.PeerSupervisor, plan.peer_supervisor_options},
        {GaoBus.Listener, listener_options}
      ] ++ cluster_child()

    # A release cannot forget externally launched children or adopt fd3 again
    # after an authority epoch reset. Its permanent application ends the VM;
    # the service manager clears the complete cgroup before restarting it.
    restarts = if lifecycle == :release, do: 0, else: 3
    opts = [strategy: :one_for_all, name: GaoBus.Supervisor, max_restarts: restarts]

    case Supervisor.start_link(children, opts) do
      {:ok, supervisor} when lifecycle == :release ->
        with {:ok, _generation, _policy} <- GaoBus.Policy.snapshot(),
             :ok <- GaoBus.Readiness.notify(System.get_env("NOTIFY_SOCKET"), inherited) do
          {:ok, supervisor}
        else
          {:error, reason} ->
            Supervisor.stop(supervisor)
            {:error, {:readiness_failed, reason}}
        end

      result ->
        result
    end
  end

  defp cluster_child do
    if Application.get_env(:gao_bus, :cluster, false) do
      [GaoBus.Cluster]
    else
      []
    end
  end
end
