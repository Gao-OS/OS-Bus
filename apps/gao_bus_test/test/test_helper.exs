ExUnit.start(exclude: [:interop, :e2e])

tag_present? = fn filters, tag ->
  Enum.any?(filters, fn
    ^tag -> true
    {^tag, true} -> true
    {^tag, _value} -> true
    _other -> false
  end)
end

config = ExUnit.configuration()
include = Keyword.get(config, :include, [])
exclude = Keyword.get(config, :exclude, [])

e2e_included? = tag_present?.(include, :e2e)
e2e_excluded? = tag_present?.(exclude, :e2e)
e2e_env? = System.get_env("E2E_BACKEND") != nil or System.get_env("E2E_GATE") != nil

if e2e_included? or (e2e_env? and not e2e_excluded?) do
  if GaoBusTest.E2E.Qualification.strict?() do
    expected =
      GaoBusTest.E2E.Selection.select(
        GaoBusTest.E2E.ScenarioCase.selected_backends(),
        GaoBusTest.E2E.ScenarioCase.selected_gate()
      )

    run_id = "#{System.system_time(:millisecond)}_#{System.unique_integer([:positive])}"
    dir = Path.join([Mix.Project.build_path(), "e2e_artifacts", "qualification", run_id])
    GaoBusTest.E2E.Qualification.start!(expected, dir)

    ExUnit.configure(
      formatters: ExUnit.configuration()[:formatters] ++ [GaoBusTest.E2E.QualificationFormatter]
    )

    ExUnit.after_suite(&GaoBusTest.E2E.Qualification.finish!/1)
  end

  GaoBusTest.E2E.ScenarioCase.prepare_backend_availability!()
end
