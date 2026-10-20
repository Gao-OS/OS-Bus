defmodule GaoBusTest.E2E.QualificationFormatter do
  @moduledoc "Retains unexpected ExUnit skips for selected required combinations."
  use GenServer

  alias GaoBusTest.E2E.Qualification

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    Qualification.metadata(:seed, Keyword.get(opts, :seed))
    {:ok, nil}
  end

  @impl true
  def handle_cast(
        {:test_finished, %ExUnit.Test{tags: %{e2e_id: _id} = tags, state: {:skipped, reason}}},
        state
      ) do
    Qualification.record_skip(tags, reason)
    {:noreply, state}
  end

  def handle_cast(_event, state), do: {:noreply, state}
end
