defmodule GaoBus.Policy.XMLGenerationTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Policy}

  test "a complete XML candidate publishes ordered policy and accounts in one generation" do
    start_supervised!({Policy, rules: candidate(:allow)})
    assert {:allow, 1} = Policy.authorize(:own, context())
    assert {:deny, :policy_denied} = Policy.authorize(:send, context())
    assert {:ok, 1, original} = Policy.snapshot()

    assert {:ok, 2} = Policy.reload(candidate(:deny))
    assert {:deny, :policy_denied} = Policy.authorize(:own, context())
    assert {:allow, 1} = Policy.authorize({:ok, 1, original}, :own, context())
  end

  test "invalid XML reload retains the last whole model" do
    start_supervised!({Policy, rules: candidate(:allow)})
    assert {:ok, 1, original} = Policy.snapshot()
    invalid = %{candidate(:deny) | policies: [block(:deny, %{"unknown" => "*"})]}
    assert {:error, %{file: "fixture.conf", line: 3}} = Policy.reload(invalid)
    assert {:ok, 1, ^original} = Policy.snapshot()
    assert {:allow, 1} = Policy.authorize(:own, context())
  end

  test "concurrent readers observe the model belonging to their reported generation" do
    start_supervised!({Policy, rules: candidate(:allow)})
    parent = self()
    gate = make_ref()

    reader =
      start_supervised!(
        {Task,
         fn ->
           send(parent, {:ready, gate})
           receive do: ({:run, ^gate} -> :ok)

           observations =
             for _ <- 1..2000 do
               assert {:ok, generation, model} = Policy.snapshot()
               {generation, Policy.authorize({:ok, generation, model}, :own, context())}
             end

           send(parent, {:observations, gate, observations})
         end},
        id: gate
      )

    assert_receive {:ready, ^gate}
    send(reader, {:run, gate})

    for generation <- 2..30 do
      effect = if rem(generation, 2) == 1, do: :allow, else: :deny
      assert {:ok, ^generation} = Policy.reload(candidate(effect))
    end

    assert_receive {:observations, ^gate, observations}, 5000

    for {generation, result} <- observations do
      if rem(generation, 2) == 1,
        do: assert(result == {:allow, generation}),
        else: assert(result == {:deny, :policy_denied})
    end
  end

  defp candidate(effect),
    do: %Config{
      policies: [block(effect, %{"own" => "org.test.Service"})],
      accounts: %{users: %{"service" => 42}, groups: %{"service" => 7}, memberships: %{42 => [7]}},
      daemon_uid: 4
    }

  defp block(effect, attrs),
    do: %{
      selector: :default,
      provenance: %{file: "fixture.conf", line: 2},
      rules: [%{effect: effect, attributes: attrs, provenance: %{file: "fixture.conf", line: 3}}]
    }

  defp context, do: %{credentials: %{uid: 42}, name: "org.test.Service"}
end
