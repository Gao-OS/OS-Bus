defmodule GaoBus.PubSub do
  @moduledoc """
  PubSub integration for broadcasting bus events.

  Used by gao_bus_web LiveViews in the explicitly configured session profile.
  System and unspecified profiles never publish to optional UI subscribers.
  """

  @topic "gao_bus:events"

  @spec topic() :: String.t()
  def topic, do: @topic

  @spec subscribe() :: :ok
  def subscribe do
    case pubsub_name() do
      nil -> :ok
      name -> Phoenix.PubSub.subscribe(name, @topic)
    end
  end

  @spec broadcast(term()) :: :ok
  def broadcast(event) do
    case pubsub_name() do
      nil ->
        :ok

      name ->
        try do
          Phoenix.PubSub.broadcast(name, @topic, event)
        rescue
          _ -> :ok
        catch
          :exit, _ -> :ok
        end
    end
  end

  defp pubsub_name do
    name = Application.get_env(:gao_bus, :pubsub_name, GaoBusWeb.PubSub)

    if Application.get_env(:gao_bus, :profile) == :session and Process.whereis(name) do
      name
    else
      nil
    end
  end
end
