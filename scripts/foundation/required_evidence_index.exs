# Run with the pinned Elixir 1.17.3 executable and -pa _build/test/lib/jason/ebin.
# This entrypoint never invokes Mix, launches an actor, or contacts a bus.
System.get_env()
|> Map.keys()
|> Enum.filter(&String.starts_with?(&1, "DBUS_"))
|> Enum.each(&System.delete_env/1)

{opts, positional, invalid} =
  OptionParser.parse(System.argv(),
    strict: [
      root: :string,
      map: :string,
      profile: :string,
      output: :string,
      require_qualified: :boolean
    ]
  )

if invalid != [] or positional != [] or
     Enum.any?([:root, :map, :profile, :output], &is_nil(opts[&1])) do
  IO.puts(
    :stderr,
    "required: --root PATH --map PATH --profile core|network --output DIR [--require-qualified]"
  )

  System.halt(2)
end

root = Path.expand(opts[:root])

for file <- ["selection.ex", "qualification.ex", "foundation_evidence_index.ex"] do
  Code.require_file(Path.join(root, "apps/gao_bus_test/test/support/e2e/" <> file))
end

try do
  map_path = Path.expand(opts[:map])
  evidence_map = map_path |> File.read!() |> Jason.decode!()

  case GaoBusTest.E2E.FoundationEvidenceIndex.build(root, evidence_map, opts[:profile]) do
    {:ok, report} ->
      report =
        Map.put(report, :evidence_map_binding, %{
          path: map_path,
          sha256: GaoBusTest.E2E.FoundationEvidenceIndex.sha256(map_path)
        })

      {:ok, path} = GaoBusTest.E2E.Qualification.write_report(opts[:output], report)

      IO.puts(
        Jason.encode!(%{
          index_integrity: report.index_integrity,
          product_qualified: report.product_qualified,
          id_counts: report.id_counts,
          combination_counts: report.combination_counts,
          evidence_counts: report.evidence_counts,
          runtime_execution: report.runtime_execution,
          artifact: path
        })
      )

      if opts[:require_qualified] == true and not report.product_qualified, do: System.halt(1)

    {:error, reason} ->
      IO.puts(:stderr, "index integrity failed: " <> reason)
      System.halt(2)
  end
rescue
  error ->
    IO.puts(:stderr, "index integrity failed: " <> Exception.message(error))
    System.halt(2)
end
