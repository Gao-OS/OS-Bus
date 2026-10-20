Code.require_file(Path.join(__DIR__, "timing_sampler.ex"))
ExUnit.start()

defmodule GaoBusFairnessTimingSamplerTest do
  use ExUnit.Case, async: false
  alias GaoBusFairnessTimingSampler, as: Sampler

  test "sample ceiling and deadline both terminate admission, even when ticks lag" do
    start = 1_000_000_000

    admitted =
      for index <- 0..200, Sampler.due?(index, start, start + index * 50_000_000), do: index

    assert length(admitted) == 160
    assert List.last(admitted) == 159
    refute Sampler.due?(1, start, start + 8_000_000_000)
    refute Sampler.due?(160, start, start + 1)
  end

  test "argument-bearing stack values are omitted rather than serialized" do
    stack = [
      {Example, :unsafe, [String.duplicate("payload-secret", 8192)], []},
      {Example, :safe, 2, []}
    ]

    rows = Sampler.sanitize_stack(stack)
    assert Enum.at(rows, 0).arity == 1
    assert Enum.at(rows, 1).arity == 2
    refute inspect(rows) =~ "payload-secret"
    assert length(Sampler.sanitize_stack(List.duplicate({Example, :safe, 2, []}, 100))) == 12
  end

  test "actual supervised process sampling records only selected metadata and stops by DOWN" do
    path =
      Path.expand(
        "../../../test/reports/foundation/p08-fairness/timing-investigation/unit-sampler.jsonl",
        __DIR__
      )

    File.rm(path)
    sampler = start_supervised!({Sampler, path: path, targets: [{self(), "unit-test"}]})
    summary = Sampler.stop(sampler)
    rows = path |> File.read!() |> String.split("\n", trim: true) |> Enum.map(&:json.decode/1)
    assert hd(rows)["event"] == "sampler_start"
    assert List.last(rows)["event"] == "sampler_stop"
    assert summary.samples in 0..160

    process = Sampler.process_row(self(), "unit-test")

    persisted = :json.decode(IO.iodata_to_binary(:json.encode(process)))

    assert Enum.sort(Map.keys(persisted)) == [
             "label",
             "mailbox",
             "peer",
             "reductions",
             "stack",
             "status"
           ]

    assert is_integer(process.reductions) and process.reductions > 0
    assert is_integer(process.mailbox)
    assert process.stack != []
    assert Enum.all?(process.stack, &is_integer(&1.arity))
  end

  test "excess and duplicate targets cannot spawn an unbounded observer" do
    assert_raise RuntimeError, ~r/target bound/, fn ->
      Sampler.start("unused", List.duplicate({self(), "same"}, 16))
    end

    assert_raise RuntimeError, ~r/duplicate/, fn ->
      Sampler.start("unused", List.duplicate({self(), "same"}, 2))
    end
  end
end
