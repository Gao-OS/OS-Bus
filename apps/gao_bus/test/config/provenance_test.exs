defmodule GaoBus.Config.ProvenanceTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config
  alias GaoBus.Config.Runtime

  @moduletag :tmp_dir
  @accounts %{users: %{"root" => 0, "messagebus" => 4}, groups: %{}, memberships: %{}}

  test "ordered declarations retain shadowed values and actual repeated include chains", %{
    tmp_dir: dir
  } do
    root = Path.join(dir, "bus.conf")
    child = Path.join(dir, "child.conf")
    leaf = Path.join(dir, "leaf.conf")
    directory = Path.join(dir, "parts")
    File.mkdir!(directory)
    a = Path.join(directory, "a.conf")
    b = Path.join(directory, "b.conf")

    File.write!(root, """
    <busconfig>
      <user>root</user>
      <limit name='auth_timeout'>1</limit>
      <include>child.conf</include>
      <includedir>parts</includedir>
      <include>leaf.conf</include>
      <user>messagebus</user>
      <limit name='auth_timeout'>9</limit>
      <syslog/>
    </busconfig>
    """)

    File.write!(child, """
    <busconfig>
      <include>leaf.conf</include>
      <fork/>
    </busconfig>
    """)

    File.write!(leaf, """
    <busconfig>
      <auth>EXTERNAL</auth>
      <listen>unix:path=/tmp/provenance-bus</listen>
      <servicedir>services</servicedir>
      <policy context='default'>
        <allow own='org.example.Service'/>
      </policy>
    </busconfig>
    """)

    File.write!(a, "<busconfig>\n<limit name='auth_timeout'>5</limit>\n</busconfig>\n")
    File.write!(b, "<busconfig>\n<include>../leaf.conf</include>\n</busconfig>\n")
    File.write!(Path.join(directory, "ignored.txt"), "invalid XML")
    assert {:ok, config} = Config.load(root, accounts: @accounts)

    root_child = include_origin(root, 4, "include", 1)
    child_leaf = include_origin(child, 2, "include", 2)
    root_directory = include_origin(root, 5, "includedir", 1)
    b_leaf = include_origin(b, 2, "include", 5)
    root_leaf = include_origin(root, 6, "include", 1)

    expected =
      [
        directive(:setting, :user, "root", origin(root, 2, "user", 1)),
        directive(:limit, "auth_timeout", 1, origin(root, 3, "limit", 1))
      ] ++
        leaf_directives(leaf, 3, [root_child, child_leaf], dir) ++
        [
          directive(:setting, :fork, true, origin(child, 3, "fork", 2, [root_child])),
          directive(:limit, "auth_timeout", 5, origin(a, 2, "limit", 4, [root_directory]))
        ] ++
        leaf_directives(leaf, 6, [root_directory, b_leaf], dir) ++
        leaf_directives(leaf, 7, [root_leaf], dir) ++
        [
          directive(:setting, :user, "messagebus", origin(root, 7, "user", 1)),
          directive(:limit, "auth_timeout", 9, origin(root, 8, "limit", 1)),
          directive(:setting, :syslog, true, origin(root, 9, "syslog", 1))
        ]

    assert Map.get(config, :directives) == expected
    assert config.settings.user == 4
    assert config.daemon_uid == 4
    assert config.limits == %{"auth_timeout" => 9}
    assert config.settings.auth == ["EXTERNAL", "EXTERNAL", "EXTERNAL"]
    assert config.settings.servicedir == List.duplicate(Path.join(dir, "services"), 3)

    assert Enum.map(config.sources, & &1.occurrence) == Enum.to_list(1..7)

    assert Enum.map(config.sources, &Map.get(&1, :include_chain)) == [
             [],
             [root_child],
             [root_child, child_leaf],
             [root_directory],
             [root_directory],
             [root_directory, b_leaf],
             [root_leaf]
           ]

    for source <- config.sources do
      assert source.sha256 ==
               Base.encode16(:crypto.hash(:sha256, File.read!(source.file)), case: :lower)
    end

    for {policy, {occurrence, chain}} <-
          Enum.zip(config.policies, [
            {3, [root_child, child_leaf]},
            {6, [root_directory, b_leaf]},
            {7, [root_leaf]}
          ]) do
      assert policy.provenance == origin(leaf, 5, "policy", occurrence, chain)
      assert [%{provenance: rule_origin}] = policy.rules
      assert rule_origin == origin(leaf, 6, "allow", occurrence, chain)
    end
  end

  test "nested account resolution failures retain the declaration and include path", %{
    tmp_dir: dir
  } do
    root = Path.join(dir, "bus.conf")
    child = Path.join(dir, "child.conf")
    leaf = Path.join(dir, "leaf.conf")
    File.write!(root, "<busconfig>\n<include>child.conf</include>\n</busconfig>")
    File.write!(child, "<busconfig>\n<include>leaf.conf</include>\n</busconfig>")
    chain = [include_origin(root, 2, "include", 1), include_origin(child, 2, "include", 2)]

    for {xml, element, kind} <- [
          {"<user>missing</user>", "user", :users},
          {"<policy user='missing'><allow own='*'/></policy>", "policy", :users},
          {"<policy context='default'>\n<deny group='missing'/>\n</policy>", "deny", :groups}
        ] do
      File.write!(leaf, "<busconfig>\n#{xml}\n</busconfig>")
      line = if element == "deny", do: 3, else: 2
      assert {:error, error} = Config.load(root, accounts: @accounts, daemon_uid: 4)

      assert error ==
               Map.put(
                 origin(leaf, line, element, 3, chain),
                 :reason,
                 {:unknown_account, kind, "missing"}
               )
    end
  end

  test "runtime refusals identify effective scalars flags lists and finite limits", %{
    tmp_dir: dir
  } do
    root = Path.join(dir, "bus.conf")
    child = Path.join(dir, "child.conf")

    File.write!(
      root,
      "<busconfig>\n<type>system</type>\n<include>child.conf</include>\n</busconfig>"
    )

    chain = [include_origin(root, 3, "include", 1)]
    invocation = %{profile: :system, socket_path: "/tmp/provenance-runtime"}

    for {declarations, reason, elements} <- [
          {["<user>root</user>", "<user>messagebus</user>"], :daemon_uid_mismatch, [{3, "user"}]},
          {["<type>session</type>"], :configuration_profile_mismatch, [{2, "type"}]},
          {["<fork/>", "<fork/>"], {:unsupported_runtime_setting, :fork}, [{3, "fork"}]},
          {["<auth>EXTERNAL</auth>", "<auth>EXTERNAL</auth>"],
           {:unsupported_runtime_setting, :auth}, [{2, "auth"}, {3, "auth"}]},
          {[
             "<servicedir>one</servicedir>",
             "<servicehelper>helper</servicehelper>",
             "<servicedir>two</servicedir>"
           ], {:unimplemented_activation_settings, [:servicedir, :servicehelper]},
           [{2, "servicedir"}, {3, "servicehelper"}, {4, "servicedir"}]},
          {[
             "<limit name='max_message_size'>1</limit>",
             "<limit name='max_message_size'>0</limit>"
           ], {:unsupported_zero_limit, "max_message_size"}, [{3, "limit"}]},
          {["<limit name='max_message_size'>134217729</limit>"],
           {:unsupported_message_size, 134_217_729}, [{2, "limit"}]},
          {["<limit name='max_message_unix_fds'>254</limit>"],
           {:unsupported_message_fd_limit, 254}, [{2, "limit"}]},
          {["<limit name='service_start_timeout'>1</limit>"],
           {:unimplemented_runtime_limits, ["service_start_timeout"]}, [{2, "limit"}]},
          {["<limit name='auth_timeout'>2147483648</limit>"],
           {:invalid_runtime_limit, "auth_timeout"}, [{2, "limit"}]}
        ] do
      File.write!(child, "<busconfig>\n" <> Enum.join(declarations, "\n") <> "\n</busconfig>")
      assert {:ok, config} = Config.load(root, accounts: @accounts, daemon_uid: 4)
      uid = if reason == :daemon_uid_mismatch, do: 0, else: 4

      origins =
        Enum.map(elements, fn {line, element} -> origin(child, line, element, 2, chain) end)

      assert {:error, %{reason: ^reason, origins: ^origins}} =
               Runtime.compile(config, invocation, %{uid: uid})
    end
  end

  test "unsupported listener evidence includes every contributing declaration", %{tmp_dir: dir} do
    root = Path.join(dir, "bus.conf")

    File.write!(
      root,
      "<busconfig>\n<listen>unix:path=/tmp/one</listen>\n<listen>unix:path=/tmp/two</listen>\n</busconfig>"
    )

    assert {:ok, config} = Config.load(root, accounts: @accounts, daemon_uid: 4)
    origins = [origin(root, 2, "listen", 1), origin(root, 3, "listen", 1)]

    assert {:error, %{reason: {:unsupported_runtime_setting, :listen}, origins: ^origins}} =
             Runtime.compile(config, %{profile: :system}, %{uid: 4})
  end

  test "manual configurations without directive metadata retain flat refusal reasons" do
    assert {:error, :daemon_uid_mismatch} =
             Runtime.compile(%Config{daemon_uid: 4}, %{profile: :system}, %{uid: 0})
  end

  defp leaf_directives(file, occurrence, chain, dir) do
    [
      directive(:setting, :auth, "EXTERNAL", origin(file, 2, "auth", occurrence, chain)),
      directive(
        :setting,
        :listen,
        "unix:path=/tmp/provenance-bus",
        origin(file, 3, "listen", occurrence, chain)
      ),
      directive(
        :setting,
        :servicedir,
        Path.join(dir, "services"),
        origin(file, 4, "servicedir", occurrence, chain)
      )
    ]
  end

  defp directive(kind, name, value, provenance),
    do: %{kind: kind, name: name, value: value, provenance: provenance}

  defp include_origin(file, line, element, occurrence),
    do: %{file: file, line: line, element: element, occurrence: occurrence}

  defp origin(file, line, element, occurrence, chain \\ []),
    do: %{file: file, line: line, element: element, occurrence: occurrence, include_chain: chain}
end
