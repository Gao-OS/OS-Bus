ExUnit.start()

for module <- [GaoBus.NameRegistry, GaoBus.Limits, Jason], do: Code.ensure_loaded!(module)
Code.require_file(Path.expand("../p08_fairness/collector.ex", __DIR__))

fixture_path = Path.join(__DIR__, "daemon.exs")
{:__block__, _, forms} = Code.string_to_quoted!(File.read!(fixture_path), file: fixture_path)

[fixture_module] =
  Enum.filter(forms, fn
    {:defmodule, _, [{:__aliases__, _, [:GaoBusFDQuotaFixture]}, _]} -> true
    _ -> false
  end)

# Compile the actual fixture module without executing its require_file or run calls.
Code.compile_quoted(fixture_module, fixture_path)

defmodule GaoBusFDQuotaSerializerTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO

  test "actual fixture emission preserves JSON null and ordinary nested values" do
    refute Process.whereis(GaoBus.Supervisor)

    value = %{
      event: "ready",
      config_file: nil,
      output: nil,
      xml: %{config_file: nil, loaded: false, includes: [nil, %{output: nil}]},
      enabled: true,
      count: 3,
      peer: "<0.123.0>",
      scopes: [:uid, :global],
      values: [nil, true, false, -7, "nil", :normal, "quoted \"value\"\nline"]
    }

    output = capture_io(fn -> assert :ok = GaoBusFDQuotaFixture.emit(value) end)
    assert ["FIXTURE " <> json, ""] = String.split(output, "\n")

    assert Jason.decode!(json) == %{
             "event" => "ready",
             "config_file" => nil,
             "output" => nil,
             "xml" => %{
               "config_file" => nil,
               "loaded" => false,
               "includes" => [nil, %{"output" => nil}]
             },
             "enabled" => true,
             "count" => 3,
             "peer" => "<0.123.0>",
             "scopes" => ["uid", "global"],
             "values" => [nil, true, false, -7, "nil", "normal", "quoted \"value\"\nline"]
           }

    refute Process.whereis(GaoBus.Supervisor)
  end
end
