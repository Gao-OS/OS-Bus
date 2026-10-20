defmodule GaoBus.Config.CaptureIntegrationTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config
  alias GaoBus.Config.Accounts
  alias GaoBus.Policy.XML

  @moduletag :tmp_dir
  @capture GaoBus.Config.Capture
  @file_bytes 1_048_576
  @accounts %{users: %{"messagebus" => 4}, groups: %{}, memberships: %{4 => []}}
  @identity_keys [:device, :inode, :mode, :size, :mtime, :ctime]

  test "captured bytes and directory inventory remain immutable after paths change", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "body")
    bytes = "captured-body-before-replacement"
    File.write!(path, bytes)
    assert {:ok, listing, capture} = list(new_capture(), dir)
    assert {:ok, record, capture} = read(capture, path)
    assert record.path == path
    assert record.bytes == bytes
    assert record.bytes_read == byte_size(bytes)
    assert record.sha256 == hash(bytes)
    assert_file_evidence(record)
    assert record.directory.before == listing.identity.after
    before = summary(capture)

    File.rm!(path)
    File.write!(path, "different-file-body")
    File.write!(Path.join(dir, "new-name"), "new")
    assert {:ok, ^record, capture} = read(capture, Path.join(dir, "./body"))
    assert {:ok, ^listing, capture} = list(capture, dir)
    assert summary(capture) == before
    refute raw_bytes?(before)
    refute contains?(before, bytes)
    assert before.directory_attempts == 1
    assert before.file_attempts == 1
    assert before.entries == 1
    assert before.name_bytes == byte_size("body")
    assert before.bytes == byte_size(bytes)
    assert Map.has_key?(before, :directories)
    assert Map.has_key?(before, :files)
  end

  test "cached files still obey a smaller caller byte credit", %{tmp_dir: dir} do
    path = Path.join(dir, "body")
    File.write!(path, "exact")
    assert {:ok, record, capture} = read(new_capture(), path, 5)
    before = summary(capture)
    assert {:error, error, capture} = read(capture, path, 4)
    assert error.path == path
    refute Map.has_key?(error, :bytes)
    assert summary(capture) == before
    assert {:ok, ^record, capture} = read(capture, path, 5)
    assert summary(capture) == before
  end

  test "missing and nonregular file failures are cached without a second read", %{tmp_dir: dir} do
    missing = Path.join(dir, "missing")
    assert {:error, missing_error, capture} = read(new_capture(), missing)
    assert missing_error.path == missing
    assert missing_error.reason == :enoent
    assert Map.has_key?(missing_error, :operation)
    before = summary(capture)
    File.write!(missing, "appeared")
    assert {:error, ^missing_error, capture} = read(capture, missing)
    assert summary(capture) == before

    directory = Path.join(dir, "directory")
    File.mkdir!(directory)
    assert {:error, refused, capture} = read(new_capture(), directory)
    assert refused.reason == :not_regular_file
    File.rmdir!(directory)
    File.write!(directory, "now-regular")
    assert {:error, ^refused, _capture} = read(capture, directory)
  end

  test "missing directories are cached and known native errno remains usable", %{tmp_dir: dir} do
    missing = Path.join(dir, "missing")
    assert {:error, error, capture} = list(new_capture(), missing)
    assert error.path == missing
    assert error.reason == :enoent
    assert Map.has_key?(error, :operation)
    before = summary(capture)
    File.mkdir!(missing)
    assert {:error, ^error, capture} = list(capture, missing)
    assert summary(capture) == before

    file = Path.join(dir, "file")
    File.write!(file, "body")
    assert {:error, %{reason: :enotdir}, _capture} = list(new_capture(), file)
    assert {:error, %{reason: :enotdir}, _capture} = read(new_capture(), Path.join(file, "leaf"))
  end

  test "invalid paths are refused without retaining unbounded input", %{tmp_dir: dir} do
    for path <- [:invalid, "", <<0>>, :binary.copy("x", 4097)] do
      assert {:error, error, capture} = read(new_capture(), path)
      assert error.path == nil
      assert summary(capture).file_attempts == 0
      refute contains?(summary(capture), path)
    end

    for credit <- [-1, @file_bytes + 1, 1.5, :unbounded] do
      assert {:error, error, _capture} = read(new_capture(), Path.join(dir, "absent"), credit)
      assert error.reason == :invalid_budget
    end
  end

  test "zero and exact byte budgets admit complete regular files only", %{tmp_dir: dir} do
    empty = Path.join(dir, "empty")
    exact = Path.join(dir, "exact")
    File.write!(empty, "")
    File.write!(exact, "abc")
    assert {:ok, %{bytes: "", bytes_read: 0}, capture} = read(new_capture(), empty, 0)
    assert {:ok, %{bytes: "abc", bytes_read: 3}, _capture} = read(capture, exact, 3)
    assert {:error, error, _capture} = read(new_capture(), exact, 2)
    assert error.path == exact
    refute Map.has_key?(error, :bytes)
  end

  test "ignored siblings consume the actual per-directory entry limit", %{tmp_dir: dir} do
    directory = Path.join(dir, "parts")
    File.mkdir!(directory)
    for index <- 1..1025, do: File.write!(Path.join(directory, "ignored-#{index}.txt"), "")
    assert {:error, error, capture} = list(new_capture(), directory)
    assert error.path == directory
    refute Map.has_key?(error, :names)
    assert {:error, ^error, _capture} = list(capture, directory)

    root = Path.join(dir, "root.conf")
    File.write!(root, "<busconfig>\n<includedir>parts</includedir>\n</busconfig>")

    assert {:error, %{file: ^root, line: 2, element: "includedir"}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)
  end

  test "directory captures spend shared entry credit before another listing", %{tmp_dir: dir} do
    directories =
      for index <- 1..9 do
        directory = Path.join(dir, "entries-#{index}")
        File.mkdir!(directory)
        count = if index == 9, do: 1, else: 1024
        for entry <- 1..count, do: File.write!(Path.join(directory, "#{entry}.txt"), "")
        directory
      end

    capture =
      Enum.reduce(Enum.take(directories, 8), new_capture(), fn directory, capture ->
        assert {:ok, result, capture} = list(capture, directory)
        assert length(result.names) == 1024
        capture
      end)

    assert summary(capture).entries == 8192
    last = List.last(directories)
    assert {:error, error, capture} = list(capture, last)
    assert error.path == last
    refute Map.has_key?(error, :names)
    assert summary(capture).entries <= 8192
  end

  test "missing directory attempts cannot bypass the shared directory cap", %{tmp_dir: dir} do
    capture =
      Enum.reduce(1..64, new_capture(), fn index, capture ->
        assert {:error, %{reason: :enoent}, capture} =
                 list(capture, Path.join(dir, "absent-#{index}"))

        capture
      end)

    assert summary(capture).directory_attempts == 64
    assert {:error, error, capture} = list(capture, Path.join(dir, "absent-65"))
    refute error.reason == :enoent
    assert summary(capture).directory_attempts == 64
    assert {:error, %{reason: :enoent}, _capture} = list(capture, Path.join(dir, "absent-1"))
  end

  test "missing file attempts cannot bypass the shared file cap", %{tmp_dir: dir} do
    capture =
      Enum.reduce(1..1024, new_capture(), fn index, capture ->
        assert {:error, %{reason: :enoent}, capture} =
                 read(capture, Path.join(dir, "absent-#{index}"))

        capture
      end)

    assert summary(capture).file_attempts == 1024
    assert {:error, error, capture} = read(capture, Path.join(dir, "absent-1025"))
    refute error.reason == :enoent
    assert summary(capture).file_attempts == 1024
    assert {:error, %{reason: :enoent}, _capture} = read(capture, Path.join(dir, "absent-1"))
  end

  test "captured bodies share a finite total byte credit", %{tmp_dir: dir} do
    bytes = :binary.copy("x", @file_bytes)
    for index <- 1..16, do: File.write!(Path.join(dir, "body-#{index}"), bytes)
    overflow = Path.join(dir, "overflow")
    File.write!(overflow, "x")

    capture =
      Enum.reduce(1..16, new_capture(), fn index, capture ->
        assert {:ok, %{bytes_read: @file_bytes}, capture} =
                 read(capture, Path.join(dir, "body-#{index}"))

        capture
      end)

    assert summary(capture).bytes == 16_777_216
    assert {:error, error, capture} = read(capture, overflow)
    assert error.path == overflow
    refute Map.has_key?(error, :bytes)
    assert summary(capture).bytes == 16_777_216
    refute raw_bytes?(summary(capture))
  end

  test "trusted cross-directory and absolute leaf links bind captured content", %{tmp_dir: dir} do
    target = Path.join(dir, "target")
    File.mkdir!(target)
    path = Path.join(target, "body")
    File.write!(path, "trusted-cross-directory-body")
    alias_directory = Path.join(dir, "alias")
    File.ln_s!(target, alias_directory)
    link = Path.join(target, "link")
    File.ln_s!(path, link)

    assert {:ok, record, _capture} = read(new_capture(), Path.join(alias_directory, "link"))
    assert record.bytes == "trusted-cross-directory-body"
    assert record.path == Path.join(alias_directory, "link")
    assert_file_evidence(record)
  end

  test "FIFOs refuse as actual nonregular files without reading partial content", %{tmp_dir: dir} do
    path = Path.join(dir, "fifo")
    assert {"", 0} = System.cmd("mkfifo", [path])
    assert {:error, %{reason: :not_regular_file}, _capture} = read(new_capture(), path)

    assert {:error, %{reason: :not_regular_file}} =
             Config.load(path, accounts: @accounts, daemon_uid: 4)

    assert {:error, %{file: ^path, reason: :not_regular_file}} =
             Accounts.load(passwd: path, group: path)
  end

  test "invalid UTF-8 directory entries refuse a complete inventory", %{tmp_dir: dir} do
    File.write!(Path.join(dir, <<255>>), "raw-name")
    assert {:error, error, _capture} = list(new_capture(), dir)
    refute Map.has_key?(error, :names)
  end

  test "maximum UTF-8 leaf names debit filename bytes rather than character counts", %{
    tmp_dir: dir
  } do
    name = :binary.copy("é", 127) <> "x"
    assert byte_size(name) == 255
    path = Path.join(dir, name)
    File.write!(path, "body")
    assert {:ok, %{names: [^name]}, capture} = list(new_capture(), dir)
    assert summary(capture).name_bytes == 255
    assert {:ok, %{bytes: "body"}, _capture} = read(capture, path)
  end

  test "account and XML parsers refuse invalid UTF-8 even inside ignored comments", %{
    tmp_dir: dir
  } do
    {passwd, group} = account_files(dir)
    File.write!(passwd, <<"# ", 255, "\nmessagebus:x:4:4::/:/bin/false\n">>)
    assert {:error, %{file: ^passwd}} = Accounts.load(passwd: passwd, group: group)
    root = Path.join(dir, "root.conf")
    File.write!(root, <<"<busconfig><!--", 255, "--></busconfig>">>)

    assert {:error, %{file: ^root, reason: :invalid_encoding}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)
  end

  test "captured account sources share one immutable file inventory", %{tmp_dir: dir} do
    {passwd, group} = account_files(dir)

    assert {:ok, accounts, capture} =
             apply(Accounts, :load_captured, [[passwd: passwd, group: group], new_capture()])

    assert accounts.memberships[4] == [4, 88]
    assert {:ok, %{uid: 4, gid: 4, groups: [4, 88]}} = Accounts.bind_user(accounts, "messagebus")

    for {kind, path} <- [passwd: passwd, group: group] do
      source = accounts.sources[kind]
      assert {:ok, record, _capture} = read(capture, path)
      assert source.identity == record.identity.before
      assert source.directory == record.directory
      assert source.syscall_attempts == record.syscall_attempts
      assert source.sha256 == record.sha256
      assert source.bytes == record.bytes_read
      assert Enum.sort(Map.keys(source.identity)) == Enum.sort(@identity_keys)
    end

    before = summary(capture)
    File.write!(passwd, "messagebus:x:5:5::/:/bin/false\n")
    File.write!(group, "different:x:99:messagebus\n")

    assert {:ok, ^accounts, capture} =
             apply(Accounts, :load_captured, [[passwd: passwd, group: group], capture])

    assert summary(capture) == before
  end

  test "supplied accounts do not invent captured file evidence", %{tmp_dir: _dir} do
    capture = new_capture()

    assert {:ok, snapshot, capture} =
             apply(Accounts, :load_captured, [[accounts: @accounts], capture])

    assert snapshot == @accounts
    assert Map.get(snapshot, :sources) == nil
    assert summary(capture).file_attempts == 0
    assert summary(capture).directory_attempts == 0
  end

  test "Config sources retain anchored read evidence and distinct include occurrences", %{
    tmp_dir: dir
  } do
    {passwd, group} = account_files(dir)
    root = Path.join(dir, "root.conf")
    child = Path.join(dir, "child.conf")

    File.write!(
      child,
      "<busconfig>\n<policy context='default'>\n<allow own='org.test.Service'/>\n</policy>\n</busconfig>"
    )

    File.write!(
      root,
      "<busconfig>\n<user>messagebus</user>\n<include>child.conf</include>\n<include>child.conf</include>\n</busconfig>"
    )

    assert {:ok, config} = Config.load(root, passwd: passwd, group: group)
    capture = Map.fetch!(config, :captures)
    assert Enum.map(config.sources, & &1.occurrence) == [1, 2, 3]
    assert summary(capture).file_attempts == 4

    for source <- config.sources do
      assert {:ok, record, _capture} = read(capture, source.file)
      assert source.identity == record.identity.before
      assert source.directory == record.directory
      assert source.bytes_read == record.bytes_read
      assert source.syscall_attempts == record.syscall_attempts
      assert source.sha256 == record.sha256
    end

    assert {:ok, compiled} =
             XML.compile(config.policies, daemon_uid: 4, memberships: config.accounts.memberships)

    assert Enum.map(compiled.blocks, & &1.provenance) ==
             Enum.map(config.policies, & &1.provenance)

    for {block, original} <- Enum.zip(compiled.blocks, config.policies) do
      assert Enum.map(block.rules, & &1.provenance) == Enum.map(original.rules, & &1.provenance)
    end

    assert XML.authorize(compiled, :own, %{credentials: %{uid: 4}, name: "org.test.Service"}) ==
             :allow
  end

  test "repeated cached XML still consumes expansion byte and occurrence budgets", %{tmp_dir: dir} do
    leaf = Path.join(dir, "leaf.conf")
    root = Path.join(dir, "root.conf")
    File.write!(leaf, "<busconfig>" <> :binary.copy(" ", 1_000_000) <> "</busconfig>")

    File.write!(
      root,
      "<busconfig>" <> :binary.copy("<include>leaf.conf</include>", 9) <> "</busconfig>"
    )

    assert {:error, %{reason: :config_bytes_exceeded}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)

    File.write!(leaf, "<busconfig/>")

    File.write!(
      root,
      "<busconfig>" <> :binary.copy("<include>leaf.conf</include>", 1024) <> "</busconfig>"
    )

    assert {:error, %{reason: :include_count_exceeded}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)
  end

  test "nested missing reads preserve the including directive's complete origin", %{tmp_dir: dir} do
    root = Path.join(dir, "root.conf")
    child = Path.join(dir, "child.conf")
    File.write!(root, "<busconfig>\n<include>child.conf</include>\n</busconfig>")
    File.write!(child, "<busconfig>\n<include>missing.conf</include>\n</busconfig>")
    assert {:error, error} = Config.load(root, accounts: @accounts, daemon_uid: 4)

    expected = %{
      file: child,
      line: 2,
      element: "include",
      occurrence: 2,
      include_chain: [%{file: root, line: 2, element: "include", occurrence: 1}]
    }

    assert Map.take(error, Map.keys(expected)) == expected
    assert error.reason == {:file_error, :enoent}

    File.write!(
      child,
      "<busconfig>\n<include ignore_missing='yes'>missing.conf</include>\n</busconfig>"
    )

    assert {:ok, _config} = Config.load(root, accounts: @accounts, daemon_uid: 4)
    File.write!(Path.join(dir, "missing.conf"), "<busconfig>")

    assert {:error, %{reason: {:invalid_xml, _}}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)
  end

  test "symlink aliases still detect active include cycles using captured device and inode", %{
    tmp_dir: dir
  } do
    root = Path.join(dir, "root.conf")
    File.write!(root, "<busconfig>\n<include>alias.conf</include>\n</busconfig>")
    File.ln_s!(root, Path.join(dir, "alias.conf"))

    assert {:error, %{file: ^root, line: 2, element: "include", reason: :include_cycle}} =
             Config.load(root, accounts: @accounts, daemon_uid: 4)
  end

  test "compiler errors retain complete valid nested rule origins", %{tmp_dir: dir} do
    origin = %{
      file: Path.join(dir, "leaf.conf"),
      line: 7,
      element: "allow",
      occurrence: 2,
      include_chain: [
        %{file: Path.join(dir, "root.conf"), line: 3, element: "include", occurrence: 1}
      ]
    }

    block = %{
      selector: :default,
      rules: [%{effect: :allow, attributes: %{"invalid" => "*"}, provenance: origin}]
    }

    assert {:error, error} = XML.compile([block], daemon_uid: 4, memberships: %{4 => []})
    assert Map.take(error, Map.keys(origin)) == origin
    assert error.reason == :invalid_rule_attributes
  end

  test "complete bounded origins survive class sorting and authorize identically", %{tmp_dir: dir} do
    origin = full_origin(dir)
    mandatory = %{origin | element: "policy", occurrence: 2}
    default = %{origin | element: "policy", occurrence: 1}
    rule = %{effect: :allow, attributes: %{"own" => "org.test.Service"}, provenance: origin}

    blocks = [
      %{selector: :mandatory, rules: [rule], provenance: mandatory},
      %{selector: :default, rules: [rule], provenance: default}
    ]

    assert {:ok, compiled} = XML.compile(blocks, daemon_uid: 4, memberships: %{4 => []})
    assert Enum.map(compiled.blocks, & &1.selector) == [:default, :mandatory]
    assert Enum.map(compiled.blocks, & &1.provenance) == [default, mandatory]
    assert Enum.all?(compiled.blocks, fn block -> hd(block.rules).provenance == origin end)

    assert :allow =
             XML.authorize(compiled, :own, %{credentials: %{uid: 4}, name: "org.test.Service"})

    largest = %{
      origin
      | file: :binary.copy("x", 4096),
        line: 1_048_577,
        occurrence: 1024,
        element: :binary.copy("e", 255),
        include_chain: List.duplicate(Map.delete(origin, :include_chain), 32)
    }

    assert {:ok, bounded} =
             XML.compile([%{selector: :default, rules: [%{rule | provenance: largest}]}],
               daemon_uid: 4,
               memberships: %{4 => []}
             )

    assert hd(hd(bounded.blocks).rules).provenance == largest
  end

  test "malformed and oversized successful origins are refused without retaining unknown fields",
       %{tmp_dir: dir} do
    origin = full_origin(dir)

    for invalid <- [
          nil,
          [],
          "not-an-origin",
          Map.put(origin, :reason, :allow),
          Map.put(origin, :unknown, "retained-input"),
          Map.delete(origin, :file),
          %{origin | file: :binary.copy("x", 4097)},
          %{origin | file: <<255>>},
          %{origin | line: 0},
          %{origin | line: 1_048_578},
          %{origin | occurrence: 0},
          %{origin | occurrence: 1025},
          %{origin | element: :binary.copy("e", 256)},
          %{origin | include_chain: List.duplicate(Map.delete(origin, :include_chain), 33)},
          %{origin | include_chain: [origin]},
          %{origin | include_chain: [%{file: "root.conf", line: 1}]}
        ] do
      valid_rule = %{effect: :allow, attributes: %{"own" => "*"}}
      block = %{selector: :default, rules: [valid_rule], provenance: invalid}

      assert {:error, %{reason: :invalid_provenance}} =
               XML.compile([block], daemon_uid: 4, memberships: %{4 => []})

      block = %{selector: :default, rules: [Map.put(valid_rule, :provenance, invalid)]}

      assert {:error, %{reason: :invalid_provenance}} =
               XML.compile([block], daemon_uid: 4, memberships: %{4 => []})
    end
  end

  test "absent and legacy origins remain supported and semantic errors keep their original reason",
       %{tmp_dir: dir} do
    legacy = %{file: Path.join(dir, "legacy.conf"), line: 2}
    rule = %{effect: :allow, attributes: %{"own" => "*"}}

    assert {:ok, without} =
             XML.compile([%{selector: :default, rules: [rule]}],
               daemon_uid: 4,
               memberships: %{4 => []}
             )

    assert :allow =
             XML.authorize(without, :own, %{credentials: %{uid: 4}, name: "org.test.Service"})

    with_legacy = %{
      selector: :default,
      rules: [Map.put(rule, :provenance, legacy)],
      provenance: legacy
    }

    assert {:ok, compiled} = XML.compile([with_legacy], daemon_uid: 4, memberships: %{4 => []})
    assert hd(compiled.blocks).provenance == legacy
    assert hd(hd(compiled.blocks).rules).provenance == legacy

    for invalid <- [nil, [], "invalid", %{reason: :allow, element: "allow"}] do
      assert {:error, %{reason: :invalid_selector, element: "policy"}} =
               XML.compile([%{selector: :unknown, rules: [], provenance: invalid}],
                 daemon_uid: 4,
                 memberships: %{4 => []}
               )

      bad_rule = %{effect: :allow, attributes: %{"unknown" => "*"}, provenance: invalid}

      assert {:error, %{reason: :invalid_rule_attributes, element: "policy"}} =
               XML.compile([%{selector: :default, rules: [bad_rule]}],
                 daemon_uid: 4,
                 memberships: %{4 => []}
               )
    end
  end

  defp new_capture, do: apply(@capture, :new, [])
  defp list(capture, path), do: apply(@capture, :list, [capture, path])

  defp read(capture, path, bytes \\ @file_bytes),
    do: apply(@capture, :read, [capture, path, bytes])

  defp summary(capture), do: apply(@capture, :summary, [capture])
  defp hash(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp full_origin(dir) do
    %{
      file: Path.join(dir, "leaf.conf"),
      line: 7,
      element: "allow",
      occurrence: 2,
      include_chain: [
        %{file: Path.join(dir, "root.conf"), line: 3, element: "include", occurrence: 1}
      ]
    }
  end

  defp account_files(dir) do
    passwd = Path.join(dir, "passwd")
    group = Path.join(dir, "group")
    File.write!(passwd, "messagebus:x:4:4::/:/bin/false\n")
    File.write!(group, "messagebus:x:4:\nmonitor:x:88:messagebus\n")
    {passwd, group}
  end

  defp assert_file_evidence(record) do
    assert record.identity.before == record.identity.after
    assert record.identity.after == record.identity.path
    assert record.bytes_read == record.identity.before.size
    assert Enum.sort(Map.keys(record.identity.before)) == Enum.sort(@identity_keys)
    assert record.directory.before == record.directory.after
    assert record.directory.after == record.directory.path
    assert record.syscall_attempts >= 1
    assert record.syscall_attempts <= div(@file_bytes, 4096) + 4
  end

  defp raw_bytes?(map) when is_map(map) do
    (Map.has_key?(map, :bytes) and is_binary(map.bytes)) or
      Enum.any?(Map.values(map), &raw_bytes?/1)
  end

  defp raw_bytes?(list) when is_list(list), do: Enum.any?(list, &raw_bytes?/1)
  defp raw_bytes?(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> raw_bytes?()
  defp raw_bytes?(_), do: false

  defp contains?(value, expected) when value == expected, do: true

  defp contains?(map, expected) when is_map(map),
    do: Enum.any?(Map.values(map), &contains?(&1, expected))

  defp contains?(list, expected) when is_list(list), do: Enum.any?(list, &contains?(&1, expected))

  defp contains?(tuple, expected) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> contains?(expected)

  defp contains?(_, _), do: false
end
