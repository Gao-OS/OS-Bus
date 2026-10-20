defmodule GaoBusTest.E2E.Actor.ElixirService do
  @moduledoc """
  Actor wrapper for GaoBusTest.E2ETestService.
  """

  alias GaoBusTest.E2E.{Context, Qualification}
  alias GaoBusTest.E2ETestService

  def bus_name, do: E2ETestService.bus_name()
  def object_path, do: E2ETestService.object_path()
  def interface, do: E2ETestService.interface()

  def start(%Context{} = context, _opts \\ []) do
    case E2ETestService.start(context.bus_address) do
      {:ok, pid} ->
        Qualification.actor(context, :elixir_service, %{pid: inspect(pid)})
        {:ok, Context.put_actor(context, :elixir_service, %{pid: pid})}

      {:error, {:already_started, pid}} ->
        Qualification.actor(context, :elixir_service, %{pid: inspect(pid)})
        {:ok, Context.put_actor(context, :elixir_service, %{pid: pid})}

      {:error, reason} ->
        {:error, reason, context}
    end
  end

  def stop(%Context{} = context) do
    E2ETestService.stop()
    {:ok, Context.delete_actor(context, :elixir_service)}
  end
end
