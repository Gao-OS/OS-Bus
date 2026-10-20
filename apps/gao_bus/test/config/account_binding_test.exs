defmodule GaoBus.Config.AccountBindingTest do
  use ExUnit.Case, async: true
  alias GaoBus.Config.Accounts
  @moduletag :tmp_dir

  test "service binding retains primary GID separately from lower supplementary GIDs", context do
    {passwd, group} = files(context, service_passwd(), "monitor:x:88:service\n")
    assert {:ok, snapshot} = Accounts.load(passwd: passwd, group: group)
    assert {:ok, [88, 100]} = Accounts.group_ids(snapshot, 28)

    assert {:ok, %{name: "service", uid: 28, gid: 100, groups: [88, 100]}} =
             Accounts.bind_user(snapshot, "service")

    assert {:ok, record} = Accounts.bind_user(snapshot, "28")
    assert record == snapshot.user_records["service"]
  end

  test "captured account sources retain exact byte hashes and named passwd line", context do
    passwd_bytes = "# local accounts\n\n" <> service_passwd()
    group_bytes = "# local groups\nmonitor:x:88:service\n"
    {passwd, group} = files(context, passwd_bytes, group_bytes)
    assert {:ok, snapshot} = Accounts.load(passwd: passwd, group: group)

    assert {:ok, %{provenance: %{file: ^passwd, line: 3}}} =
             Accounts.bind_user(snapshot, "service")

    for {kind, path, bytes} <- [{:passwd, passwd, passwd_bytes}, {:group, group, group_bytes}] do
      assert %{kind: :local_file, file: ^path, bytes: size, sha256: hash, identity: identity} =
               snapshot.sources[kind]

      assert size == byte_size(bytes)
      assert hash == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
      assert %{inode: inode, size: ^size} = identity
      assert is_integer(inode)
    end
  end

  test "UID aliases bind their named primary GID and named groups", context do
    passwd_bytes = service_passwd() <> "alias:x:28:200::/var/empty:/bin/false\n"
    group_bytes = "monitor:x:88:service\naudit:x:99:alias\n"
    {passwd, group} = files(context, passwd_bytes, group_bytes)
    assert {:ok, snapshot} = Accounts.load(passwd: passwd, group: group)
    assert {:ok, [88, 99, 100, 200]} = Accounts.group_ids(snapshot, 28)

    assert {:ok, %{name: "service", uid: 28, gid: 100, groups: [88, 100]}} =
             Accounts.bind_user(snapshot, "service")

    assert {:ok, %{name: "alias", uid: 28, gid: 200, groups: [99, 200]}} =
             Accounts.bind_user(snapshot, "alias")

    assert {:error, :ambiguous_account_uid} = Accounts.bind_user(snapshot, "28")
    assert {:ok, 28} = Accounts.resolve(snapshot, :users, "28")
  end

  test "unknown numeric binding fails while numeric policy ACL resolution stays valid", context do
    {passwd, group} = files(context, service_passwd(), "monitor:x:88:service\n")
    assert {:ok, snapshot} = Accounts.load(passwd: passwd, group: group)
    assert {:error, :unknown_account_uid} = Accounts.bind_user(snapshot, "29")

    assert {:error, {:unknown_account, :users, "missing"}} =
             Accounts.bind_user(snapshot, "missing")

    assert {:ok, 29} = Accounts.resolve(snapshot, :users, "29")
    assert {:ok, 300} = Accounts.resolve(snapshot, :groups, "300")
  end

  test "legacy supplied policy snapshots cannot invent a service identity" do
    assert {:ok, snapshot} = Accounts.load(accounts: legacy_snapshot())
    assert {:ok, 28} = Accounts.resolve(snapshot, :users, "service")
    assert {:ok, [88, 100]} = Accounts.group_ids(snapshot, 28)
    assert {:error, :account_identity_unavailable} = Accounts.bind_user(snapshot, "service")
    assert {:error, :account_identity_unavailable} = Accounts.bind_user(snapshot, "28")
    assert Map.get(snapshot, :sources) == nil
  end

  test "supplied identity records validate without inventing captured file evidence" do
    record = %{name: "service", uid: 28, gid: 100, groups: [100, 88, 100], provenance: nil}
    supplied = Map.put(legacy_snapshot(), :user_records, %{"service" => record})
    assert {:ok, snapshot} = Accounts.load(accounts: supplied)

    assert {:ok, %{name: "service", uid: 28, gid: 100, groups: [88, 100], provenance: nil}} =
             Accounts.bind_user(snapshot, "service")

    assert Map.get(snapshot, :sources) == nil
  end

  test "inconsistent supplied identity records are rejected" do
    record = %{name: "service", uid: 28, gid: 100, groups: [88, 100], provenance: nil}

    for records <- [
          nil,
          %{"service" => Map.delete(record, :gid)},
          %{"service" => %{record | name: "other"}},
          %{"service" => %{record | uid: 29}},
          %{"service" => %{record | gid: -1}},
          %{"service" => %{record | gid: 0xFFFFFFFF}},
          %{"service" => %{record | groups: [88]}},
          %{"service" => %{record | groups: [88, 100, 200]}},
          %{"service" => %{record | groups: [100, "88"]}},
          %{"service" => %{record | groups: :unknown}},
          %{"other" => %{record | name: "other"}},
          %{"service" => %{record | provenance: %{file: "passwd", line: 0}}}
        ] do
      assert {:error, %{file: "<accounts>", line: 1, reason: :invalid_account_snapshot}} =
               Accounts.load(accounts: Map.put(legacy_snapshot(), :user_records, records))
    end
  end

  test "captured binding and fingerprints remain immutable after account files change", context do
    {passwd, group} = files(context, service_passwd(), "monitor:x:88:service\n")
    assert {:ok, snapshot} = Accounts.load(passwd: passwd, group: group)
    assert {:ok, before} = Accounts.bind_user(snapshot, "service")
    sources = snapshot.sources
    File.write!(passwd, "service:x:29:200::/var/empty:/bin/false\n")
    File.write!(group, "audit:x:99:service\n")
    assert {:ok, ^before} = Accounts.bind_user(snapshot, "service")
    assert snapshot.sources == sources

    assert {:ok, changed} = Accounts.load(passwd: passwd, group: group)

    assert {:ok, %{uid: 29, gid: 200, groups: [99, 200]}} =
             Accounts.bind_user(changed, "service")

    refute changed.sources == sources
  end

  test "nonregular account inputs and oversized group bytes retain finite failures", context do
    {passwd, group} = files(context, service_passwd(), "")

    assert {:error, %{file: file, line: 1, reason: :not_regular_file}} =
             Accounts.load(passwd: context.tmp_dir, group: group)

    assert file == context.tmp_dir
    File.write!(group, :binary.copy("x", 1_048_577))

    assert {:error, %{file: ^group, line: 1, reason: :account_file_too_large}} =
             Accounts.load(passwd: passwd, group: group)
  end

  test "malformed named records retain their actual passwd line", context do
    {passwd, group} = files(context, "# comment\n\nservice:x:28:bad::/var/empty:/bin/false\n", "")

    assert {:error, %{file: ^passwd, line: 3, reason: :invalid_account_entry}} =
             Accounts.load(passwd: passwd, group: group)
  end

  test "supplied account and identity group bounds remain finite" do
    records = Map.new(0..65_536, fn id -> {"user#{id}", id} end)
    oversized = %{users: records, groups: %{}, memberships: %{}}

    assert {:error, %{reason: :invalid_account_snapshot}} = Accounts.load(accounts: oversized)

    record = %{
      name: "service",
      uid: 28,
      gid: 100,
      groups: List.duplicate(100, 65_537),
      provenance: nil
    }

    assert {:error, %{reason: :invalid_account_snapshot}} =
             Accounts.load(
               accounts: Map.put(legacy_snapshot(), :user_records, %{"service" => record})
             )
  end

  defp service_passwd, do: "service:x:28:100::/var/empty:/bin/false\n"

  defp legacy_snapshot do
    %{users: %{"service" => 28}, groups: %{"monitor" => 88}, memberships: %{28 => [88, 100]}}
  end

  defp files(%{tmp_dir: dir}, passwd_bytes, group_bytes) do
    passwd = Path.join(dir, "passwd")
    group = Path.join(dir, "group")
    File.write!(passwd, passwd_bytes)
    File.write!(group, group_bytes)
    {passwd, group}
  end
end
