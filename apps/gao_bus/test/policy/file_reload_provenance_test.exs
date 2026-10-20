defmodule GaoBus.Policy.FileReloadProvenanceTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Policy}

  @moduletag :tmp_dir
  @options [
    daemon_uid: 4,
    accounts: %{users: %{"messagebus" => 4}, groups: %{}, memberships: %{}}
  ]

  setup %{tmp_dir: dir} do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    root = Path.join(dir, "bus.conf")
    child = Path.join(dir, "runtime.conf")

    File.write!(
      root,
      "<busconfig>\n<type>system</type>\n<include>runtime.conf</include>\n<policy context='default'><allow own='org.test.Service'/></policy>\n</busconfig>"
    )

    File.write!(
      child,
      "<busconfig>\n<limit name='auth_timeout'>1</limit>\n<limit name='auth_timeout'>2</limit>\n</busconfig>"
    )

    assert {:ok, initial} = Config.load(root, @options)
    start_supervised!({Policy, rules: initial, config_file: root, config_options: @options})
    %{root: root, child: child, initial: initial}
  end

  test "changed effective nested limit refuses reload with its origin and preserves generation",
       context do
    assert {:ok, 1, model} = Policy.snapshot()

    File.write!(
      context.child,
      "<busconfig>\n<limit name='auth_timeout'>100</limit>\n<limit name='auth_timeout'>200</limit>\n</busconfig>"
    )

    origins = [
      origin(context.child, 3, "limit", 2, [include_origin(context.root, 3, "include", 1)])
    ]

    assert {:error, %{reason: :configuration_requires_restart, origins: ^origins}} =
             Policy.reload_file()

    assert {:ok, 1, ^model} = Policy.snapshot()

    assert {:allow, 1} =
             Policy.authorize(:own, %{credentials: %{uid: 4}, name: "org.test.Service"})
  end

  test "removed effective declarations report their old origins", context do
    assert {:ok, 1, model} = Policy.snapshot()
    File.write!(context.child, "<busconfig/>")

    origins = [
      origin(context.child, 3, "limit", 2, [include_origin(context.root, 3, "include", 1)])
    ]

    assert {:error, %{reason: :configuration_requires_restart, origins: ^origins}} =
             Policy.reload_file()

    assert {:ok, 1, ^model} = Policy.snapshot()
  end

  test "changed lists report every contributing declaration in expansion order", context do
    assert {:ok, 1, model} = Policy.snapshot()

    File.write!(
      context.child,
      "<busconfig>\n<limit name='auth_timeout'>2</limit>\n<listen>unix:path=/tmp/one</listen>\n<listen>unix:path=/tmp/two</listen>\n</busconfig>"
    )

    chain = [include_origin(context.root, 3, "include", 1)]

    origins = [
      origin(context.child, 3, "listen", 2, chain),
      origin(context.child, 4, "listen", 2, chain)
    ]

    assert {:error, %{reason: :configuration_requires_restart, origins: ^origins}} =
             Policy.reload_file()

    assert {:ok, 1, ^model} = Policy.snapshot()
  end

  test "shadowed source-only changes preserve runtime semantics and permit publication",
       context do
    File.write!(
      context.child,
      "<busconfig>\n<limit name='auth_timeout'>100</limit>\n<limit name='auth_timeout'>2</limit>\n</busconfig>"
    )

    assert {:ok, 2} = Policy.reload_file()
    assert {:ok, 2, _} = Policy.snapshot()
  end

  test "restart candidate mismatch supplies the same effective declaration evidence", context do
    File.write!(
      context.child,
      "<busconfig>\n<limit name='auth_timeout'>200</limit>\n</busconfig>"
    )

    origins = [
      origin(context.child, 2, "limit", 2, [include_origin(context.root, 3, "include", 1)])
    ]

    assert {:stop, %{reason: :configuration_requires_restart, origins: ^origins}} =
             Policy.init(
               rules: context.initial,
               config_file: context.root,
               config_options: @options
             )

    assert {:ok, 1, _} = Policy.snapshot()
  end

  test "restart mismatch without declaration metadata retains the original atom", context do
    File.write!(context.root, "<busconfig/>")

    assert {:stop, :configuration_requires_restart} =
             Policy.init(
               rules: %Config{daemon_uid: 0},
               config_file: context.root,
               config_options: @options
             )

    assert {:ok, 1, _} = Policy.snapshot()
  end

  defp include_origin(file, line, element, occurrence),
    do: %{file: file, line: line, element: element, occurrence: occurrence}

  defp origin(file, line, element, occurrence, chain),
    do: %{file: file, line: line, element: element, occurrence: occurrence, include_chain: chain}
end
