defmodule GaoBus.Unix.IdentityTest do
  use ExUnit.Case, async: true

  test "daemon identity records real and effective IDs from the running kernel process" do
    pid = System.pid() |> String.to_integer()
    status = File.read!("/proc/#{pid}/status")
    [real_uid, effective_uid, _, _] = ids(status, "Uid")
    [real_gid, effective_gid, _, _] = ids(status, "Gid")

    assert Map.take(GaoBus.Unix.Native.identity(), [:pid, :uid, :gid, :real_uid, :real_gid]) == %{
             pid: pid,
             uid: effective_uid,
             gid: effective_gid,
             real_uid: real_uid,
             real_gid: real_gid
           }
  end

  defp ids(status, name) do
    status
    |> String.split("\n")
    |> Enum.find(&String.starts_with?(&1, name <> ":"))
    |> String.split()
    |> tl()
    |> Enum.map(&String.to_integer/1)
  end
end
