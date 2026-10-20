defmodule GaoBusTest.E2E.Context do
  @moduledoc """
  Per-scenario E2E context.
  """

  defstruct [
    :scenario_id,
    :backend_name,
    :backend_mod,
    :backend_state,
    :bus_address,
    :tmpdir,
    :artifacts_dir,
    :started_at,
    actors: %{},
    metadata: %{},
    commands: []
  ]

  def new(attrs) do
    backend_mod = Keyword.fetch!(attrs, :backend_mod)
    backend_state = Keyword.fetch!(attrs, :backend_state)
    scenario_id = Keyword.fetch!(attrs, :scenario_id)
    backend_name = Keyword.fetch!(attrs, :backend_name)
    tmpdir = Map.get(backend_state, :tmpdir)

    %__MODULE__{
      scenario_id: scenario_id,
      backend_name: backend_name,
      backend_mod: backend_mod,
      backend_state: backend_state,
      bus_address: backend_mod.address(backend_state),
      tmpdir: tmpdir,
      artifacts_dir: Keyword.get(attrs, :artifacts_dir),
      started_at: DateTime.utc_now(),
      metadata: Keyword.get(attrs, :metadata, %{})
    }
  end

  def put_actor(%__MODULE__{} = context, name, state) do
    remember_actor(context, name, state)
    %{context | actors: Map.put(context.actors, name, state)}
  end

  def remember_actor(context, name, state) do
    key = {__MODULE__, context.scenario_id, context.backend_name}
    Process.put(key, Map.put(Process.get(key, %{}), name, state))
    :ok
  end

  def actor_history(context) do
    Process.get({__MODULE__, context.scenario_id, context.backend_name}, context.actors)
  end

  def clear_actor_history(context) do
    Process.delete({__MODULE__, context.scenario_id, context.backend_name})
    :ok
  end

  def get_actor(%__MODULE__{} = context, name), do: Map.fetch(context.actors, name)

  def delete_actor(%__MODULE__{} = context, name) do
    %{context | actors: Map.delete(context.actors, name)}
  end

  def add_command(%__MODULE__{} = context, command_result) do
    %{context | commands: [command_result | context.commands]}
  end

  def stop_backend(%__MODULE__{backend_mod: mod, backend_state: state}) do
    mod.stop(state)
  end
end
