defmodule GaoBusTest.E2E.Selection do
  @moduledoc "Versioned applicability manifest for the original conformance scenarios."

  @version 1
  @rows [
    {"E2E-001", :smoke, :hello, [:ex_dbus]},
    {"E2E-002", :smoke, :bus, [:ex_dbus]},
    {"E2E-003", :smoke, :names, [:ex_dbus]},
    {"E2E-004", :smoke, :names, [:ex_dbus]},
    {"E2E-005", :release, :methods, [:ex_dbus, :glib_fixture]},
    {"E2E-006", :release, :methods, [:busctl, :elixir_service]},
    {"E2E-007", :release, :methods, [:gdbus, :elixir_service]},
    {"E2E-008", :release, :errors, [:ex_dbus, :elixir_service]},
    {"E2E-009", :release, :errors, [:ex_dbus, :glib_fixture]},
    {"E2E-010", :release, :signals, [:ex_dbus, :glib_fixture]},
    {"E2E-011", :release, :signals, [:ex_dbus, :glib_fixture]},
    {"E2E-012", :compat, :introspection, [:busctl, :elixir_service]},
    {"E2E-013", :compat, :properties, [:gdbus, :glib_fixture]},
    {"E2E-014", :compat, :properties, [:gdbus, :glib_fixture]},
    {"E2E-015", :stress, :concurrency, [:ex_dbus, :glib_fixture]},
    {"E2E-016", :release, :failure, [:ex_dbus, :glib_fixture]},
    {"E2E-017", :release, :failure, [:ex_dbus]},
    {"E2E-018", :release, :routing, [:ex_dbus]},
    {"E2E-019", :release, :bus, [:ex_dbus]},
    {"E2E-020", :release, :bus, [:ex_dbus]}
  ]

  def version, do: @version

  def scenarios do
    Enum.map(@rows, fn {id, gate, group, actors} ->
      %{e2e_id: id, gate: gate, group: group, actors: actors, backends: [:reference, :gao_bus]}
    end)
  end

  def select(backends, gate) do
    for scenario <- scenarios(),
        gate_selected?(scenario.gate, gate),
        backend <- backends,
        backend in scenario.backends do
      scenario
      |> Map.drop([:backends])
      |> Map.merge(%{backend: backend, profile: :session, status: :selected, actors_executed: []})
    end
  end

  def validate!(tags) do
    actual = Map.take(tags, [:e2e_id, :gate, :group, :actors, :backends])

    unless actual in scenarios() do
      raise ArgumentError,
            "scenario tags disagree with selection manifest v#{@version}: #{inspect(actual)}"
    end
  end

  def gate_selected?(_gate, :all), do: true
  def gate_selected?(gate, selected), do: rank(gate) <= rank(selected)

  defp rank(:smoke), do: 1
  defp rank(:release), do: 2
  defp rank(:compat), do: 3
  defp rank(:stress), do: 4
end
