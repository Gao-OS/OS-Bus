defmodule GaoBus.Config.ServiceDiscoveryTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config

  @moduletag :tmp_dir
  @name "org.example.Service"
  @path "/trusted/services/org.example.Service.service"
  @directory_origin %{
    file: "/trusted/bus.conf",
    line: 9,
    element: "servicedir",
    occurrence: 2,
    include_chain: [%{file: "/trusted/root.conf", line: 3, element: "include", occurrence: 1}]
  }
  @origin %{
    file: @path,
    line: 1,
    element: "D-BUS Service",
    occurrence: 7,
    include_chain: @directory_origin.include_chain,
    directory_index: 2,
    directory_origin: @directory_origin
  }
  @root %{
    name: "root",
    uid: 0,
    gid: 0,
    groups: [0],
    provenance: %{file: "/trusted/passwd", line: 1}
  }
  @service %{
    name: "service",
    uid: 28,
    gid: 100,
    groups: [88, 100],
    provenance: %{file: "/trusted/passwd", line: 3}
  }
  @accounts %{
    users: %{"root" => 0, "service" => 28},
    groups: %{"root" => 0, "monitor" => 88, "service" => 100},
    memberships: %{0 => [0], 28 => [88, 100]},
    user_records: %{"root" => @root, "service" => @service}
  }

  test "pure parsing binds the supplied named primary GID and retains full physical origins" do
    bytes =
      "# comment\n[D-BUS Service]\nName=#{@name}\nExec=/missing/program arg\nUser=service\nSystemdService=absent.service"

    assert {:ok, entry} = parse(bytes)
    assert entry.name == @name
    assert entry.exec == "/missing/program arg"
    assert entry.argv == ["/missing/program", "arg"]
    assert entry.user == "service"
    assert entry.account == @service
    assert entry.account.gid == 100
    assert entry.account.groups == [88, 100]
    assert entry.systemd_service == "absent.service"
    assert entry.provenance == source_origin(2, "D-BUS Service")

    assert entry.field_origins == %{
             name: source_origin(3, "Name"),
             exec: source_origin(4, "Exec"),
             user: source_origin(5, "User"),
             systemd_service: source_origin(6, "SystemdService")
           }
  end

  test "LF CRLF and a final line without EOL preserve line numbers" do
    bytes = "# comment\n \t\r\f\n[D-BUS Service]\nName = #{@name}\nExec = false\nUser = root"

    for content <- [bytes, bytes <> "\n", String.replace(bytes, "\n", "\r\n")] do
      assert {:ok, entry} = parse(content)
      assert entry.argv == ["false"]
      assert entry.systemd_service == nil
      assert entry.field_origins.user == source_origin(6, "User")
    end
  end

  test "first matching group and first matching keys win without merging later groups" do
    bytes =
      "[Other]\nName=org.example.Other\n[D-BUS Service]\nName=#{@name}\nName=org.example.Later\nExec=false\nExec=/later\nUser=root\n[D-BUS Service]\nName=org.example.Last\nExec=/last\nUser=service"

    assert {:ok, entry} = parse(bytes)
    assert entry.name == @name
    assert entry.argv == ["false"]
    assert entry.account == @root
    assert entry.provenance == source_origin(3, "D-BUS Service")
    assert entry.field_origins.name == source_origin(4, "Name")
    assert entry.field_origins.exec == source_origin(6, "Exec")

    bytes = "[D-BUS Service]\nName=#{@name}\nUser=root\n[D-BUS Service]\nExec=false"
    assert_parse_error(bytes)
  end

  test "unknown keys and groups are ignored semantically but still parsed" do
    assert {:ok, entry} = parse(service() <> "\nUnknown-1=valid\\svalue\n[Other]\nKey=ignored")
    assert entry.name == @name

    for suffix <- ["\nUnknown=bad\\q", "\n[Other]\nKey=bad\\q", "\nUnknown=trailing\\"] do
      assert_parse_error(service() <> suffix)
    end
  end

  test "locale declarations skip the complete line after a valid base key" do
    bytes =
      "[D-BUS Service]\nName[broken\nExec[locale]=bad\\q\nUser[locale]anything\nName=#{@name}\nExec=false\nUser=root"

    assert {:ok, entry} = parse(bytes)
    assert entry.name == @name
    assert entry.field_origins.name == source_origin(5, "Name")
    assert_parse_error("[D-BUS Service]\nName[en]=#{@name}\nExec=false\nUser=root")
  end

  test "desktop syntax is column sensitive and only hash in column zero is a comment" do
    for invalid <- [
          " [D-BUS Service]",
          "[D-BUS Service] ",
          "[D-BUS Service]#comment",
          "[]",
          "[D-BUS [Service]]",
          "[D-BUS\tService]",
          " # comment",
          "; comment",
          " Name=#{@name}",
          "Name\t=#{@name}",
          "Bad_key=value",
          "=value"
        ] do
      assert_parse_error(invalid <> "\n" <> service())
    end

    assert_parse_error(String.replace(service(), "[D-BUS Service]", "[d-bus service]"))
    assert_parse_error(String.replace(service(), "Name=", "name="))
  end

  test "UTF8 and NUL validation covers comments unknown values and fields" do
    for bytes <- [<<255>> <> service(), "#\0comment\n" <> service(), service() <> "\nUnknown=\0"] do
      assert_parse_error(bytes)
    end

    assert {:ok, entry} = parse(service(~S(/missing/program "café")))
    assert entry.argv == ["/missing/program", "café"]
  end

  test "Name Exec and system User must be present and names must be requestable" do
    for field <- ["Name", "Exec", "User"] do
      bytes =
        service()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, field <> "="))
        |> Enum.join("\n")

      assert_parse_error(bytes)
    end

    for name <- [
          "",
          ":1.4",
          "org.freedesktop.DBus",
          "single",
          "org.2Invalid",
          "org.example.Bad/Name"
        ] do
      assert_parse_error(service("false", "root", name), "/trusted/services/#{name}.service")
    end

    assert_parse_error(service("false", ""))
  end

  test "canonical filename is an explicit supported profile restriction" do
    assert_parse_error(service(), "/trusted/services/alias.service")
    assert_parse_error(service(), "/trusted/services/#{@name}.SERVICE")
    name = "org." <> String.duplicate("a", 243)
    assert byte_size(name) == 247

    assert {:ok, entry} =
             parse(service("false", "root", name), "/trusted/services/#{name}.service")

    assert entry.name == name
    name = name <> "a"
    assert_parse_error(service("false", "root", name), "/trusted/services/#{name}.service")
  end

  test "empty and relative Exec are retained literally without an executable probe" do
    for {exec, argv} <- [
          {"", [""]},
          {"false", ["false"]},
          {"relative/program arg", ["relative/program", "arg"]},
          {"/absent/program", ["/absent/program"]}
        ] do
      assert {:ok, entry} = parse(service(exec))
      assert entry.exec == exec
      assert entry.argv == argv
    end
  end

  test "SystemdService is optional nonempty metadata and does not require a unit" do
    assert {:ok, entry} = parse(service() <> "\nSystemdService=does-not-exist.service")
    assert entry.systemd_service == "does-not-exist.service"
    assert {:ok, entry} = parse(service())
    assert entry.systemd_service == nil
    assert_parse_error(service() <> "\nSystemdService=")
  end

  test "requested AppArmor mediation is refused with the security field's origin" do
    for label <- ["", "requested.profile"] do
      assert {:error, error} = parse(service() <> "\nAssumedAppArmorLabel=" <> label)
      assert error.reason == :unsupported_security_field
      assert error.element == "AssumedAppArmorLabel"
      assert error.line == 5
      assert error.directory_origin == @directory_origin
    end
  end

  test "unknown User preserves its physical field and directory origins" do
    assert {:error, error} = parse(service("false", "missing"))
    assert error.reason == {:unknown_account, :users, "missing"}

    assert Map.take(error, [:file, :line, :element, :occurrence, :include_chain]) ==
             source_origin(4, "User")

    assert error.directory_origin == @directory_origin
    assert error.directory_index == 2
  end

  test "numeric UID binding requires a unique complete named record" do
    assert {:ok, entry} = parse(service("false", "28"))
    assert entry.user == "28"
    assert entry.account == @service

    aliases = %{
      @accounts
      | users: Map.put(@accounts.users, "alias", 28),
        user_records: Map.put(@accounts.user_records, "alias", %{@service | name: "alias"})
    }

    assert {:error, %{reason: :ambiguous_account_uid}} =
             parse(service("false", "28"), @path, aliases)

    assert {:error, %{reason: :unknown_account_uid}} = parse(service("false", "29"))
    legacy = Map.delete(@accounts, :user_records)

    assert {:error, %{reason: :account_identity_unavailable}} =
             parse(service("false", "service"), @path, legacy)
  end

  test "pinned two-stage desktop unescape and argv vectors retain exact arguments" do
    vectors = [
      {~S(/usr/bin/demo "two words" 'three words' pre"mid"'post' ""),
       ["/usr/bin/demo", "two words", "three words", "premidpost", ""]},
      {~S(/usr/bin/demo one\stwo), ["/usr/bin/demo", "one", "two"]},
      {~S(/usr/bin/demo one\\ two), ["/usr/bin/demo", "one two"]},
      {~S(/usr/bin/demo "a\\qb"), ["/usr/bin/demo", ~S(a\qb)]},
      {~S(/usr/bin/demo "\\$HOME" "$HOME" *.service %f ; `literal` ~user),
       ["/usr/bin/demo", "$HOME", "$HOME", "*.service", "%f", ";", "`literal`", "~user"]},
      {~S(/usr/bin/demo "a\\"b"), ["/usr/bin/demo", "a\"b"]},
      {~S(/usr/bin/demo a\nb), ["/usr/bin/demo", "a", "b"]},
      {~S(/usr/bin/demo a\tb), ["/usr/bin/demo", "a", "b"]},
      {~S(/usr/bin/demo '#literal'), ["/usr/bin/demo", "#literal"]}
    ]

    for {raw_exec, expected} <- vectors do
      assert {:ok, entry} = parse(service(raw_exec))
      assert entry.argv == expected
    end
  end

  test "pinned argv trailing whitespace and comment behavior is not generic shell splitting" do
    for {exec, expected} <- [
          {"/usr/bin/demo arg ", ["/usr/bin/demo", "arg", ""]},
          {"/usr/bin/demo arg\t", ["/usr/bin/demo", "arg", ""]},
          {"/usr/bin/demo arg#discard", ["/usr/bin/demo", "arg"]},
          {"/usr/bin/demo #comment", ["/usr/bin/demo", ""]},
          {~S(/usr/bin/demo "#literal"), ["/usr/bin/demo", "#literal"]}
        ] do
      assert {:ok, entry} = parse(service(exec))
      assert entry.argv == expected
    end
  end

  test "bad desktop escapes unclosed shell quotes and terminal hash fail with Exec origins" do
    for exec <- [
          ~S(/usr/bin/demo bad\q),
          "/usr/bin/demo trailing\\",
          ~S(/usr/bin/demo "unterminated),
          ~S(/usr/bin/demo 'unterminated),
          "/usr/bin/demo trailing\\\\",
          "/usr/bin/demo arg#"
        ] do
      error = assert_parse_error(service(exec))
      assert error.line == 3
      assert error.element == "Exec"
    end
  end

  test "physical line and argv item bounds accept exact credit then refuse one over" do
    bytes = service() <> "\n#" <> String.duplicate("x", 4095)
    assert {:ok, _} = parse(bytes)
    assert_parse_error(bytes <> "x")
    exec = Enum.join(List.duplicate("x", 256), " ")
    assert {:ok, entry} = parse(service(exec))
    assert length(entry.argv) == 256
    assert_parse_error(service(exec <> " x"))
    assert_parse_error(service(String.duplicate("x", 4097)))
    assert_parse_error(service() <> "\n" <> String.duplicate("K", 4097) <> "=value")
    assert_parse_error(service() <> "\nSystemdService=" <> String.duplicate("x", 4097))
  end

  test "4096 physical lines are accepted and comment lines still charge work" do
    bytes = service() <> String.duplicate("\n#", 4092)
    assert {:ok, _} = parse(bytes)
    assert_parse_error(bytes <> "\n#")
  end

  test "64 sections are accepted and ignored or duplicate sections still charge work" do
    for section <- ["[Other]", "[D-BUS Service]"] do
      bytes = service() <> String.duplicate("\n" <> section, 63)
      assert {:ok, _} = parse(bytes)
      assert_parse_error(bytes <> "\n" <> section)
    end
  end

  test "64 declarations are accepted and unknown duplicate locale declarations all charge" do
    for declaration <- ["Unknown=ignored", "Name=org.example.Ignored", "Name[broken"] do
      bytes = service() <> String.duplicate("\n" <> declaration, 61)
      assert {:ok, entry} = parse(bytes)
      assert entry.name == @name
      assert_parse_error(bytes <> "\n" <> declaration)
    end
  end

  test "128KiB actual service bytes are accepted and one more byte is refused" do
    bytes = pad_comments(service(), 131_072)
    assert byte_size(bytes) == 131_072
    assert {:ok, _} = parse(bytes)
    assert_parse_error(bytes <> "x")
  end

  test "real directory order selects the first file and retains later shadowed metadata", %{
    tmp_dir: dir
  } do
    first = mkdir(dir, "first")
    second = mkdir(dir, "second")
    first_bytes = service("false", "service") <> "\nSystemdService=absent.service"
    first_path = write_service(first, @name, first_bytes)
    second_path = write_service(second, @name, service("relative/program", "root"))
    other = "org.example.Another"
    write_service(first, other, service("false", "root", other))
    config = config([first, second])
    assert {:ok, inventory, _capture} = discover(config)
    assert Enum.map(inventory.directories, & &1.path) == [first, second]
    assert Enum.map(inventory.directories, & &1.index) == [1, 2]
    assert Enum.map(inventory.directories, & &1.status) == [:present, :present]

    assert Enum.map(inventory.directories, & &1.origin) ==
             Enum.map(config.directives, & &1.provenance)

    assert map_size(inventory.selected) == 2
    assert length(inventory.occurrences) == 3
    effective = inventory.selected[@name]
    assert effective.path == first_path
    assert effective.disposition == :effective
    assert effective.directory_index == 1
    assert effective.directory_origin == Enum.at(config.directives, 0).provenance
    assert effective.argv == ["false"]
    assert effective.account == @service
    assert effective.systemd_service == "absent.service"
    assert effective in inventory.occurrences
    assert_capture(effective.capture, first_bytes)
    shadowed = Enum.find(inventory.occurrences, &(&1.path == second_path))
    assert shadowed.disposition == :shadowed
    assert shadowed.directory_index == 2
    assert shadowed.directory_origin == Enum.at(config.directives, 1).provenance
    assert shadowed.argv == ["relative/program"]
    assert shadowed.account == @root
  end

  test "absolute trusted leaf links retain opened regular file evidence", %{tmp_dir: dir} do
    directory = mkdir(dir, "services")
    target = Path.join(dir, "stored.service")
    bytes = service()
    File.write!(target, bytes)
    path = Path.join(directory, @name <> ".service")
    File.ln_s!(target, path)
    assert {:ok, inventory, _} = discover(config([directory]))
    assert inventory.selected[@name].path == path
    assert_capture(inventory.selected[@name].capture, bytes)
  end

  test "missing directories and ignored siblings remain visible without parsing siblings", %{
    tmp_dir: dir
  } do
    missing = Path.join(dir, "missing")
    directory = mkdir(dir, "services")
    File.write!(Path.join(directory, "broken.txt"), <<255>>)
    File.write!(Path.join(directory, "uppercase.SERVICE"), "not a service")
    write_service(directory, @name, service())
    assert {:ok, inventory, _} = discover(config([missing, directory]))
    assert Enum.map(inventory.directories, & &1.status) == [:missing, :present]
    assert length(inventory.occurrences) == 1
    assert inventory.selected[@name].directory_index == 2
  end

  test "a malformed shadowed file refuses the complete candidate with its directory context", %{
    tmp_dir: dir
  } do
    first = mkdir(dir, "first")
    second = mkdir(dir, "second")
    write_service(first, @name, service())
    path = write_service(second, @name, service("false", "missing"))
    config = config([first, second])
    assert {:error, error} = discover(config)
    assert error.file == path
    assert error.line == 4
    assert error.element == "User"
    assert error.reason == {:unknown_account, :users, "missing"}
    assert error.directory_index == 2
    assert error.directory_origin == Enum.at(config.directives, 1).provenance
  end

  test "same directory aliases cannot bypass canonical filename refusal", %{tmp_dir: dir} do
    write_service(dir, @name, service())
    alias_path = Path.join(dir, "org.example.Alias.service")
    File.write!(alias_path, service())
    assert {:error, error} = discover(config([dir]))
    assert error.file == alias_path
    assert Map.has_key?(error, :reason)
  end

  test "repeated directory occurrences reuse capture but retain separate selection origins", %{
    tmp_dir: dir
  } do
    path = write_service(dir, @name, service())
    config = config([dir, dir])
    assert {:ok, inventory, captured} = discover(config)
    assert [first, second] = inventory.occurrences
    assert first.path == path
    assert second.path == path
    assert first.disposition == :effective
    assert second.disposition == :shadowed
    assert first.directory_index == 1
    assert second.directory_index == 2
    refute first.directory_origin == second.directory_origin
    assert first.capture == second.capture
    assert inventory.selected[@name] == first

    File.write!(path, service("changed", "root"))
    assert {:ok, reused, recaptured} = discover(config, captured)
    assert reused == inventory
    assert recaptured == captured
    assert {:ok, fresh, _} = discover(config)
    assert fresh.selected[@name].argv == ["changed"]
  end

  test "cached missing directory remains missing in the same capture", %{tmp_dir: dir} do
    missing = Path.join(dir, "missing")
    config = config([missing])
    assert {:ok, inventory, captured} = discover(config)
    assert [%{status: :missing}] = inventory.directories
    File.mkdir!(missing)
    write_service(missing, @name, service())
    assert {:ok, reused, _} = discover(config, captured)
    assert reused == inventory
    assert reused.selected == %{}
    assert {:ok, fresh, _} = discover(config)
    assert Map.has_key?(fresh.selected, @name)
  end

  test "64 configured directory occurrences including missing and cached paths are bounded", %{
    tmp_dir: dir
  } do
    missing = Path.join(dir, "missing")
    assert {:ok, inventory, _} = discover(config(List.duplicate(missing, 64)))
    assert length(inventory.directories) == 64
    assert Enum.all?(inventory.directories, &(&1.status == :missing))
    assert {:error, error} = discover(config(List.duplicate(missing, 65)))
    assert Map.has_key?(error, :reason)
    assert error.directory_origin.file == Path.join(dir, "bus.conf")
  end

  test "ignored siblings debit complete listing credit before suffix filtering", %{tmp_dir: dir} do
    for index <- 1..1024, do: File.write!(Path.join(dir, "ignored#{index}.txt"), "")
    assert {:ok, inventory, _} = discover(config([dir]))
    assert inventory.selected == %{}
    File.write!(Path.join(dir, "one-more.txt"), "")
    config = config([dir])
    assert {:error, error} = discover(config)
    assert error.directory_origin == hd(config.directives).provenance
  end

  test "8192 traversed names debit repeated directory occurrences even when capture is cached", %{
    tmp_dir: dir
  } do
    for index <- 1..1024, do: File.write!(Path.join(dir, "ignored#{index}.txt"), "")
    assert {:ok, inventory, _} = discover(config(List.duplicate(dir, 8)))
    assert inventory.occurrences == []
    assert {:error, error} = discover(config(List.duplicate(dir, 9)))
    assert Map.has_key?(error, :reason)
  end

  test "1024 service occurrences charge cache hits separately from distinct file reads", %{
    tmp_dir: dir
  } do
    for index <- 1..16 do
      name = "org.example.Service#{index}"
      write_service(dir, name, service("false", "root", name))
    end

    assert {:ok, inventory, _} = discover(config(List.duplicate(dir, 64)))
    assert length(inventory.occurrences) == 1024
    assert map_size(inventory.selected) == 16
    assert Enum.count(inventory.occurrences, &(&1.disposition == :effective)) == 16
    name = "org.example.Service17"
    write_service(dir, name, service("false", "root", name))
    assert {:error, error} = discover(config(List.duplicate(dir, 61)))
    assert Map.has_key?(error, :reason)
  end

  test "real service reader refuses actual bytes over 128KiB and nonregular inputs", %{
    tmp_dir: dir
  } do
    path = write_service(dir, @name, pad_comments(service(), 131_072))
    assert {:ok, inventory, _} = discover(config([dir]))
    assert inventory.selected[@name].name == @name
    File.write!(path, pad_comments(service(), 131_072) <> "x")
    assert {:error, error} = discover(config([dir]))
    assert error.file == path
    File.rm!(path)
    File.mkdir!(path)
    assert {:error, error} = discover(config([dir]))
    assert error.file == path
  end

  defp parse(bytes, path \\ @path, accounts \\ @accounts) do
    origin = %{@origin | file: path}
    apply(GaoBus.Config.Services, :parse, [bytes, path, origin, accounts])
  end

  defp assert_parse_error(bytes, path \\ @path) do
    assert {:error, error} = parse(bytes, path)
    assert is_map(error)
    assert Map.has_key?(error, :reason)
    assert error.file == path
    assert is_integer(error.line)
    assert error.line >= 1
    assert is_binary(error.element)
    assert error.occurrence == @origin.occurrence
    assert error.include_chain == @origin.include_chain
    error
  end

  defp service(exec \\ "false", user \\ "root", name \\ @name),
    do: "[D-BUS Service]\nName=#{name}\nExec=#{exec}\nUser=#{user}"

  defp source_origin(line, element),
    do: %{
      file: @path,
      line: line,
      element: element,
      occurrence: @origin.occurrence,
      include_chain: @origin.include_chain
    }

  defp config(directories) do
    directives =
      directories
      |> Enum.with_index(1)
      |> Enum.map(fn {directory, index} ->
        %{
          kind: :setting,
          name: :servicedir,
          value: directory,
          provenance: %{
            file: Path.join(Path.dirname(directory), "bus.conf"),
            line: index + 1,
            element: "servicedir",
            occurrence: 1,
            include_chain: []
          }
        }
      end)

    %Config{
      settings: %{type: :system, servicedir: directories},
      accounts: @accounts,
      directives: directives
    }
  end

  defp discover(config), do: discover(config, apply(GaoBus.Config.Capture, :new, []))
  defp discover(config, capture), do: apply(GaoBus.Config.Services, :discover, [config, capture])

  defp mkdir(parent, name) do
    directory = Path.join(parent, name)
    File.mkdir!(directory)
    directory
  end

  defp write_service(directory, name, bytes) do
    path = Path.join(directory, name <> ".service")
    File.write!(path, bytes)
    path
  end

  defp assert_capture(capture, bytes) do
    assert capture.bytes == bytes
    assert capture.sha256 == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    assert is_integer(capture.read_attempts)
    assert capture.read_attempts >= 1
    assert is_map(capture.directory)
    assert opened_identity?(capture.identity)
  end

  defp opened_identity?(
         %{ctime: _, device: device, inode: inode, mode: mode, mtime: _, size: size} = identity
       ),
       do:
         Enum.sort(Map.keys(identity)) == [:ctime, :device, :inode, :mode, :mtime, :size] and
           is_integer(device) and is_integer(inode) and is_integer(mode) and is_integer(size)

  defp opened_identity?(value) when is_map(value),
    do: Enum.any?(Map.values(value), &opened_identity?/1)

  defp opened_identity?(_), do: false

  defp pad_comments(bytes, size) do
    remaining = size - byte_size(bytes)
    full = div(remaining, 4096)
    rest = rem(remaining, 4096)
    comments = String.duplicate("\n#" <> String.duplicate("x", 4094), full)

    tail =
      if rest >= 2,
        do: "\n#" <> String.duplicate("x", rest - 2),
        else: String.duplicate("\n", rest)

    bytes <> comments <> tail
  end
end
