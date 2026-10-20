defmodule GaoBus.Config.AccountsTest do
  use ExUnit.Case, async: true
  alias GaoBus.Config.Accounts
  @moduletag :tmp_dir

  test "finite local account files preserve primary and supplementary membership", %{tmp_dir: dir} do
    passwd = Path.join(dir, "passwd")
    group = Path.join(dir, "group")

    File.write!(
      passwd,
      "root:x:0:0:root:/root:/bin/sh\nservice:x:28:100::/var/empty:/bin/false\n"
    )

    File.write!(group, "root:x:0:\nusers:x:100:service\nmonitor:x:88:service,root\n")

    assert {:ok,
            %{
              users: %{"root" => 0, "service" => 28},
              groups: %{"root" => 0, "users" => 100, "monitor" => 88},
              memberships: %{0 => [0, 88], 28 => [88, 100]}
            }} = Accounts.load(passwd: passwd, group: group)
  end

  test "malformed accounts fail with file and line provenance", %{tmp_dir: dir} do
    passwd = Path.join(dir, "passwd")
    group = Path.join(dir, "group")
    File.write!(passwd, "service:x:not-a-uid:100::/var/empty:/bin/false\n")
    File.write!(group, "users:x:100:\n")

    assert {:error, %{file: ^passwd, line: 1, element: "accounts", reason: _}} =
             Accounts.load(passwd: passwd, group: group)
  end

  test "injected account data is validated instead of guessed" do
    for snapshot <- [
          %{users: %{"service" => nil}, groups: %{}, memberships: %{}},
          %{users: %{}, groups: %{"users" => -1}, memberships: %{}},
          %{users: %{}, groups: %{}, memberships: %{28 => ["root"]}}
        ] do
      assert {:error, %{element: "accounts", reason: :invalid_account_snapshot}} =
               Accounts.load(accounts: snapshot)
    end
  end

  test "account file reads have a finite size ceiling", %{tmp_dir: dir} do
    passwd = Path.join(dir, "passwd")
    File.write!(passwd, :binary.copy("x", 1_048_577))

    assert {:error, %{file: ^passwd, reason: :account_file_too_large}} =
             Accounts.load(passwd: passwd, group: "/missing/group")
  end

  test "group queries use account membership and reject unknown UIDs" do
    snapshot = %{
      users: %{"service" => 28},
      groups: %{"users" => 100},
      memberships: %{28 => [100]}
    }

    assert {:ok, [100]} = Accounts.group_ids(snapshot, 28)
    assert {:error, :unknown_account_uid} = Accounts.group_ids(snapshot, 29)

    assert {:error, :unknown_account_uid} =
             Accounts.group_ids(%{snapshot | memberships: %{29 => [100]}}, 29)
  end

  test "absent membership data is unavailable instead of an empty trusted group set" do
    snapshot = %{users: %{"service" => 28}, groups: %{}, memberships: %{}}
    assert {:error, :account_groups_unavailable} = Accounts.group_ids(snapshot, 28)
  end
end
