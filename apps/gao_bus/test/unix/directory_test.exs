defmodule GaoBus.Unix.DirectoryTest do
  use ExUnit.Case, async: false

  alias GaoBus.Unix.{Directory, Native}

  @moduletag :tmp_dir

  test "empty directories succeed with default, maximum and zero budgets", %{tmp_dir: path} do
    assert {:ok, result} = Directory.list(path)
    assert_complete(result, [], 1024)

    for {entries, bytes} <- [{1024, 262_144}, {0, 0}, {0, 262_144}, {1024, 0}] do
      assert {:ok, result} = Native.list_dir_bounded(path, entries, bytes)
      assert_complete(result, [], entries)
      assert {:ok, result} = Directory.list(path, entries, bytes)
      assert_complete(result, [], entries)
    end
  end

  test "returns a complete sorted list at the exact entry budget and refuses one extra entry",
       %{tmp_dir: path} do
    names = ["z.service", "a.service", "middle.service"]
    Enum.each(names, &File.write!(Path.join(path, &1), ""))

    assert {:ok, result} = Native.list_dir_bounded(path, 3, 262_144)
    assert_complete(result, names, 3)
    assert {:ok, result} = Directory.list(path, 3)
    assert_complete(result, names, 3)
    assert result.names == Enum.sort(names)

    File.write!(Path.join(path, "extra.service"), "")
    assert {:error, :entry_limit} = Native.list_dir_bounded(path, 3, 262_144)
    assert {:error, %{reason: :entry_limit, path: ^path}} = Directory.list(path, 3)
  end

  test "charges hidden names, unrelated suffixes, directories and dangling links",
       %{tmp_dir: path} do
    names = [".hidden", "unrelated.txt", "valid.service", "subdir", "dangling"]
    Enum.each(Enum.take(names, 3), &File.write!(Path.join(path, &1), ""))
    File.mkdir!(Path.join(path, "subdir"))
    File.write!(Path.join([path, "subdir", "nested.service"]), "")
    File.ln_s!(Path.join(path, "missing-target"), Path.join(path, "dangling"))
    bytes = name_bytes(names)

    assert {:ok, result} = Native.list_dir_bounded(path, 5, bytes)
    assert_complete(result, names, 5)
    assert {:ok, result} = Directory.list(path, 5, bytes)
    assert_complete(result, names, 5)
    assert result.names == Enum.sort(names)

    assert {:error, :entry_limit} = Native.list_dir_bounded(path, 4, bytes)
    assert {:error, %{reason: :entry_limit, path: ^path}} = Directory.list(path, 4, bytes)
    assert {:error, :name_byte_limit} = Native.list_dir_bounded(path, 5, bytes - 1)

    assert {:error, %{reason: :name_byte_limit, path: ^path}} =
             Directory.list(path, 5, bytes - 1)
  end

  test "name budgets count UTF-8 bytes and refuse even one byte above the budget",
       %{tmp_dir: path} do
    names = ["é.service", "界"]
    Enum.each(names, &File.write!(Path.join(path, &1), ""))
    bytes = name_bytes(names)
    assert bytes > Enum.sum(Enum.map(names, &String.length/1))

    assert {:ok, result} = Native.list_dir_bounded(path, 2, bytes)
    assert_complete(result, names, 2)
    assert {:ok, result} = Directory.list(path, 2, bytes)
    assert_complete(result, names, 2)

    assert {:error, :name_byte_limit} = Native.list_dir_bounded(path, 2, bytes - 1)

    assert {:error, %{reason: :name_byte_limit, path: ^path}} =
             Directory.list(path, 2, bytes - 1)
  end

  test "zero entry or byte budgets refuse a nonempty directory", %{tmp_dir: path} do
    File.write!(Path.join(path, "a"), "")

    assert {:error, :entry_limit} = Native.list_dir_bounded(path, 0, 1)
    assert {:error, %{reason: :entry_limit, path: ^path}} = Directory.list(path, 0, 1)
    assert {:error, :name_byte_limit} = Native.list_dir_bounded(path, 1, 0)
    assert {:error, %{reason: :name_byte_limit, path: ^path}} = Directory.list(path, 1, 0)
  end

  test "accepts a maximum-length filename without truncating it", %{tmp_dir: path} do
    name = String.duplicate("a", 255)
    File.write!(Path.join(path, name), "")

    assert {:ok, result} = Native.list_dir_bounded(path, 1, 255)
    assert_complete(result, [name], 1)
    assert {:ok, result} = Directory.list(path, 1, 255)
    assert_complete(result, [name], 1)
  end

  test "accumulates complete results and budgets across multiple scratch batches",
       %{tmp_dir: path} do
    names =
      Enum.map(1..200, fn index ->
        String.pad_leading(Integer.to_string(index), 3, "0") <> String.duplicate("x", 197)
      end)

    Enum.each(names, &File.write!(Path.join(path, &1), ""))
    bytes = name_bytes(names)
    assert bytes > 32_768

    for result <- [Native.list_dir_bounded(path, 200, bytes), Directory.list(path, 200, bytes)] do
      assert {:ok, result} = result
      assert_complete(result, names, 200)
      assert result.syscall_attempts >= 3
    end

    assert {:error, :entry_limit} = Native.list_dir_bounded(path, 199, bytes)
    assert {:error, %{reason: :entry_limit, path: ^path}} = Directory.list(path, 199, bytes)
    assert {:error, :name_byte_limit} = Native.list_dir_bounded(path, 200, bytes - 1)

    assert {:error, %{reason: :name_byte_limit, path: ^path}} =
             Directory.list(path, 200, bytes - 1)
  end

  test "invalid paths are refused by both boundaries without retaining them" do
    for path <- [nil, :directory, [], "", "before\0after", String.duplicate("a", 4097)] do
      assert {:error, :invalid_path} = Native.list_dir_bounded(path, 1024, 262_144)
      assert {:error, %{reason: :invalid_path, path: nil}} = Directory.list(path)
    end
  end

  test "invalid budgets are refused before attempting to open a missing path", %{tmp_dir: dir} do
    path = Path.join(dir, "missing")

    for budget <- [-1, 1.0, nil, "1", 1025, :erlang.bsl(1, 80)] do
      assert {:error, :invalid_budget} = Native.list_dir_bounded(path, budget, 262_144)
      assert {:error, %{reason: :invalid_budget, path: ^path}} = Directory.list(path, budget)
    end

    for budget <- [-1, 1.0, nil, "1", 262_145, :erlang.bsl(1, 80)] do
      assert {:error, :invalid_budget} = Native.list_dir_bounded(path, 1024, budget)

      assert {:error, %{reason: :invalid_budget, path: ^path}} =
               Directory.list(path, 1024, budget)
    end
  end

  test "filesystem errors preserve the errno and the bounded original path", %{tmp_dir: dir} do
    missing = Path.join(dir, "missing")
    file = Path.join(dir, "regular-file")
    File.write!(file, "")

    for {path, errno} <- [{missing, 2}, {file, 20}, {String.duplicate("a", 4096), 36}] do
      assert {:error, {:errno, ^errno}} = Native.list_dir_bounded(path, 1024, 262_144)
      assert {:error, %{reason: {:errno, ^errno}, path: ^path}} = Directory.list(path)
    end
  end

  test "native names retain invalid UTF-8 and the checked wrapper refuses them explicitly",
       %{tmp_dir: path} do
    name = <<255, ".service">>
    filename = path <> "/" <> name
    File.write!(filename, "")
    on_exit(fn -> File.rm!(filename) end)

    assert {:ok, result} = Native.list_dir_bounded(path, 1, byte_size(name))
    assert_complete(result, [name], 1)
    refute String.valid?(hd(result.names))

    assert {:error, %{reason: {:invalid_name_encoding, ^name}, path: ^path}} =
             Directory.list(path, 1, byte_size(name))
  end

  test "trusted directory symlinks enumerate the target and report its real metadata",
       %{tmp_dir: dir} do
    target = Path.join(dir, "target")
    path = Path.join(dir, "directory-link")
    File.mkdir!(target)
    File.write!(Path.join(target, "one.service"), "")
    File.ln_s!(target, path)
    stat = File.stat!(target, time: :posix)

    for result <- [Native.list_dir_bounded(path, 1, 11), Directory.list(path, 1, 11)] do
      assert {:ok, result} = result
      assert_complete(result, ["one.service"], 1)
      assert result.identity.before == result.identity.after
      assert result.identity.after == result.identity.path

      for metadata <- Map.values(result.identity) do
        assert metadata.device == stat.major_device
        assert metadata.inode == stat.inode
        assert metadata.mode == stat.mode
        assert metadata.size == stat.size
        assert_timestamp(metadata.mtime, stat.mtime)
        assert_timestamp(metadata.ctime, stat.ctime)
      end
    end
  end

  test "repeated successes and both budget overflows recover the actual BEAM FD count",
       %{tmp_dir: path} do
    File.write!(Path.join(path, "a"), "")
    assert {:ok, _} = Native.list_dir_bounded(path, 1, 1)
    assert {:ok, _} = Directory.list(path, 1, 1)
    _ = fd_count()
    before_count = fd_count()

    for _ <- 1..64 do
      assert {:ok, _} = Native.list_dir_bounded(path, 1, 1)
      assert {:error, :entry_limit} = Native.list_dir_bounded(path, 0, 1)
      assert {:error, :name_byte_limit} = Native.list_dir_bounded(path, 1, 0)
      assert {:ok, _} = Directory.list(path, 1, 1)
      assert {:error, %{reason: :entry_limit, path: ^path}} = Directory.list(path, 0, 1)
      assert {:error, %{reason: :name_byte_limit, path: ^path}} = Directory.list(path, 1, 0)
    end

    assert fd_count() == before_count
  end

  defp assert_complete(result, names, entry_budget) do
    assert Enum.sort(result.names) == Enum.sort(names)
    assert result.examined == length(names)
    assert result.name_bytes == name_bytes(names)
    assert is_integer(result.raw_records)
    assert result.raw_records >= result.examined
    assert result.raw_records <= entry_budget + 3
    assert is_integer(result.syscall_attempts)
    assert result.syscall_attempts >= 1
    assert result.syscall_attempts <= entry_budget + 4
  end

  defp assert_timestamp({seconds, nanoseconds}, expected_seconds) do
    assert seconds == expected_seconds
    assert is_integer(nanoseconds)
    assert nanoseconds >= 0
    assert nanoseconds < 1_000_000_000
  end

  defp name_bytes(names), do: Enum.sum(Enum.map(names, &byte_size/1))

  defp fd_count, do: length(File.ls!("/proc/#{System.pid()}/fd"))
end
