defmodule GaoBus.Unix.FileReaderTest do
  use ExUnit.Case, async: false

  alias GaoBus.Unix.{Directory, FileReader, Native}

  @moduletag :tmp_dir
  @max_bytes 1_048_576

  test "empty regular files accept zero, default and maximum budgets", %{tmp_dir: directory} do
    name = "empty.service"
    File.write!(Path.join(directory, name), "")
    expected = directory_identity(directory)

    assert {:ok, result} = FileReader.read(directory, name, expected)
    assert_file(result, directory, name, expected, "", @max_bytes)

    for budget <- [0, @max_bytes] do
      assert {:ok, result} = Native.read_file_at_bounded(directory, name, expected, budget)
      assert_file(result, directory, name, expected, "", budget)
      assert {:ok, result} = FileReader.read(directory, name, expected, budget)
      assert_file(result, directory, name, expected, "", budget)
      assert result.path == Path.join(directory, name)
    end
  end

  test "exact byte budgets preserve raw contents and refuse overflow without a prefix",
       %{tmp_dir: directory} do
    name = "raw.service"
    bytes = <<0, 255, 128, 10, 195, 169>>
    File.write!(Path.join(directory, name), bytes)
    expected = directory_identity(directory)

    assert {:ok, result} =
             Native.read_file_at_bounded(directory, name, expected, byte_size(bytes))

    assert_file(result, directory, name, expected, bytes, byte_size(bytes))

    assert {:ok, result} = FileReader.read(directory, name, expected, byte_size(bytes))
    assert_file(result, directory, name, expected, bytes, byte_size(bytes))
    assert result.path == Path.join(directory, name)

    for budget <- [0, byte_size(bytes) - 1] do
      assert_refusal(directory, name, expected, budget, :file_byte_limit)
    end
  end

  test "maximum-sized files read completely across many requests and default refuses one extra byte",
       %{tmp_dir: directory} do
    name = "maximum.service"
    bytes = :binary.copy(<<0, 255, 65, 10>>, div(@max_bytes, 4))
    File.write!(Path.join(directory, name), bytes)
    expected = directory_identity(directory)

    assert {:ok, result} = Native.read_file_at_bounded(directory, name, expected, @max_bytes)
    assert_file(result, directory, name, expected, bytes, @max_bytes)
    assert result.syscall_attempts > 1
    assert {:ok, result} = FileReader.read(directory, name, expected)
    assert_file(result, directory, name, expected, bytes, @max_bytes)

    File.write!(Path.join(directory, name), bytes <> "!")
    assert_refusal(directory, name, expected, @max_bytes, :file_byte_limit)
    path = Path.join(directory, name)

    assert {:error, %{reason: :file_byte_limit, path: ^path}} =
             FileReader.read(directory, name, expected)
  end

  test "a maximum-length leaf name is accepted without truncation", %{tmp_dir: directory} do
    name = String.duplicate("n", 255)
    File.write!(Path.join(directory, name), "complete")
    expected = directory_identity(directory)
    assert {:ok, result} = Native.read_file_at_bounded(directory, name, expected, 8)
    assert_file(result, directory, name, expected, "complete", 8)
    assert {:ok, result} = FileReader.read(directory, name, expected, 8)
    assert_file(result, directory, name, expected, "complete", 8)
  end

  test "invalid directories are refused without retaining invalid input", %{tmp_dir: directory} do
    expected = directory_identity(directory)

    for invalid <- [nil, :directory, [], 1, "", "before\0after", String.duplicate("d", 4097)] do
      assert {:error, :invalid_path} = Native.read_file_at_bounded(invalid, "a", expected, 1)

      assert {:error, %{reason: :invalid_path, path: nil}} =
               FileReader.read(invalid, "a", expected, 1)
    end
  end

  test "invalid leaf names cannot select another path and are not retained", %{tmp_dir: directory} do
    expected = directory_identity(directory)

    for invalid <- [
          nil,
          :name,
          [],
          1,
          "",
          ".",
          "..",
          "/absolute",
          "a/b",
          "a\0b",
          String.duplicate("n", 256)
        ] do
      assert {:error, :invalid_name} =
               Native.read_file_at_bounded(directory, invalid, expected, 1)

      assert {:error, %{reason: :invalid_name, path: nil}} =
               FileReader.read(directory, invalid, expected, 1)
    end
  end

  test "native raw leaf names remain readable while the checked wrapper refuses invalid UTF-8",
       %{tmp_dir: directory} do
    name = <<255, ".service">>
    filename = directory <> "/" <> name
    File.write!(filename, "raw-name-content")
    on_exit(fn -> File.rm!(filename) end)

    # Checked enumeration refuses this name; raw enumeration supplies the same
    # six-field directory identity for this raw-name fixture.
    assert {:ok, enumeration} = Native.list_dir_bounded(directory, 1, byte_size(name))
    expected = enumeration.identity.after
    assert {:ok, result} = Native.read_file_at_bounded(directory, name, expected, 16)
    assert_file(result, directory, name, expected, "raw-name-content", 16)

    assert {:error, %{reason: :invalid_name, path: nil}} =
             FileReader.read(directory, name, expected, 16)
  end

  test "invalid byte budgets are refused before opening a missing leaf", %{tmp_dir: directory} do
    expected = directory_identity(directory)

    for budget <- [-1, 1.0, nil, "1", @max_bytes + 1, :erlang.bsl(1, 80)] do
      assert_refusal(directory, "missing", expected, budget, :invalid_budget)
    end
  end

  test "identity requires exactly six correctly typed fields and directory mode",
       %{tmp_dir: directory} do
    expected = directory_identity(directory)
    oversized = :erlang.bsl(1, 80)

    invalid_fields =
      for field <- [:device, :inode, :mode, :size], value <- [-1, 1.0, nil, "1", oversized] do
        Map.put(expected, field, value)
      end

    invalid =
      [nil, [], :identity, %{}, Map.put(expected, :extra, 0)] ++
        Enum.map(Map.keys(expected), &Map.delete(expected, &1)) ++ invalid_fields

    invalid =
      invalid ++
        [
          Map.put(expected, :device, :erlang.bsl(1, 64)),
          Map.put(expected, :inode, :erlang.bsl(1, 64)),
          Map.put(expected, :mode, :erlang.bsl(1, 32)),
          Map.put(expected, :mode, 0o100644),
          Map.put(expected, :size, :erlang.bsl(1, 63))
        ]

    for identity <- invalid do
      assert_refusal(directory, "missing", identity, 1, :invalid_identity)
    end
  end

  test "both timestamp fields require signed seconds and bounded integer nanoseconds",
       %{tmp_dir: directory} do
    expected = directory_identity(directory)
    overflow = :erlang.bsl(1, 63)

    for field <- [:mtime, :ctime],
        timestamp <- [
          nil,
          [],
          1,
          {1},
          {1, 0, 0},
          {1.0, 0},
          {nil, 0},
          {overflow, 0},
          {-overflow - 1, 0},
          {1, -1},
          {1, 1_000_000_000},
          {1, 0.0},
          {1, nil}
        ] do
      assert_refusal(
        directory,
        "missing",
        Map.put(expected, field, timestamp),
        1,
        :invalid_identity
      )
    end

    for field <- [:mtime, :ctime], nanoseconds <- [0, 999_999_999] do
      identity = Map.put(expected, field, {-1, nanoseconds})
      assert_refusal(directory, "missing", identity, 1, :directory_changed)
    end
  end

  test "missing paths and non-directory anchors preserve filesystem errors", %{tmp_dir: directory} do
    file = Path.join(directory, "file")
    File.write!(file, "")
    File.ln_s!("missing-target", Path.join(directory, "dangling"))
    File.ln_s!("loop", Path.join(directory, "loop"))
    expected = directory_identity(directory)
    assert_refusal(directory, "missing", expected, 1, {:errno, 2})
    assert_refusal(directory, "dangling", expected, 1, {:errno, 2})
    assert_refusal(directory, "loop", expected, 1, {:errno, 40})
    assert_refusal(Path.join(directory, "absent"), "file", expected, 1, {:errno, 2})
    assert_refusal(file, "leaf", expected, 1, {:errno, 20})
  end

  test "directories and FIFOs are refused as nonregular files", %{tmp_dir: directory} do
    File.mkdir!(Path.join(directory, "subdir"))
    assert {"", 0} = System.cmd("mkfifo", [Path.join(directory, "fifo")])
    File.ln_s!("subdir", Path.join(directory, "directory-link"))
    File.ln_s!("fifo", Path.join(directory, "fifo-link"))
    expected = directory_identity(directory)

    for name <- ["subdir", "directory-link", "fifo", "fifo-link"] do
      assert_refusal(directory, name, expected, @max_bytes, :not_regular_file)
    end
  end

  test "regular proc cmdline with nonempty bytes and reported zero size refuses the mismatch" do
    directory = "/proc/self"
    name = "cmdline"
    stat = File.stat!(Path.join(directory, name), time: :posix)
    assert stat.type == :regular
    assert stat.size == 0
    bytes = File.read!(Path.join(directory, name))
    refute bytes == ""
    assert byte_size(bytes) <= @max_bytes
    expected = directory_identity(directory)
    assert_refusal(directory, name, expected, @max_bytes, :file_changed)
  end

  test "trusted directory and relative or absolute cross-root leaf symlinks preserve exact bytes",
       %{tmp_dir: directory} do
    source = Path.join(directory, "source")
    target = Path.join(directory, "other-root")
    anchor = Path.join(directory, "directory-link")
    File.mkdir!(source)
    File.mkdir!(target)
    File.write!(Path.join(target, "service"), "trusted-cross-root")
    File.ln_s!("../other-root/service", Path.join(source, "relative.service"))
    File.ln_s!(Path.join(target, "service"), Path.join(source, "absolute.service"))
    File.ln_s!(source, anchor)
    expected = directory_identity(anchor)

    for name <- ["relative.service", "absolute.service"] do
      assert {:ok, result} = Native.read_file_at_bounded(anchor, name, expected, 18)
      assert_file(result, anchor, name, expected, "trusted-cross-root", 18)
      assert {:ok, result} = FileReader.read(anchor, name, expected, 18)
      assert_file(result, anchor, name, expected, "trusted-cross-root", 18)
      assert result.path == Path.join(anchor, name)
    end
  end

  test "same-count directory replacement refuses the stale enumeration identity",
       %{tmp_dir: directory} do
    source = Path.join(directory, "source")
    replacement = Path.join(directory, "replacement")
    File.mkdir!(source)
    File.mkdir!(replacement)
    File.write!(Path.join(source, "service"), "old")
    File.write!(Path.join(replacement, "service"), "new")
    expected = directory_identity(source)
    File.rename!(source, Path.join(directory, "retired"))
    File.rename!(replacement, source)
    current = directory_identity(source)
    refute current.inode == expected.inode
    assert_refusal(source, "service", expected, 3, :directory_changed)
    assert {:ok, result} = FileReader.read(source, "service", current, 3)
    assert_file(result, source, "service", current, "new", 3)
  end

  test "same-count leaf replacement refuses observed stale directory metadata",
       %{tmp_dir: directory} do
    source = Path.join(directory, "source")
    File.mkdir!(source)
    File.write!(Path.join(source, "service"), "old")
    File.write!(Path.join(directory, "replacement"), "new")
    File.touch!(source, 1_000_000_000)
    assert {:ok, before} = Directory.list(source)
    File.rename!(Path.join(directory, "replacement"), Path.join(source, "service"))
    assert {:ok, after_read} = Directory.list(source)
    assert before.names == after_read.names
    refute before.identity.after.mtime == after_read.identity.after.mtime
    assert_refusal(source, "service", before.identity.after, 3, :directory_changed)
    assert {:ok, result} = FileReader.read(source, "service", after_read.identity.after, 3)
    assert_file(result, source, "service", after_read.identity.after, "new", 3)
  end

  test "repeated successes and terminal refusals recover the actual BEAM FD count",
       %{tmp_dir: directory} do
    File.write!(Path.join(directory, "service"), "bytes")
    File.mkdir!(Path.join(directory, "subdir"))
    assert {"", 0} = System.cmd("mkfifo", [Path.join(directory, "fifo")])
    expected = directory_identity(directory)
    stale = Map.update!(expected, :inode, &(&1 + 1))
    assert {:ok, _} = Native.read_file_at_bounded(directory, "service", expected, 5)
    assert {:ok, _} = FileReader.read(directory, "service", expected, 5)
    _ = fd_count()
    before_count = fd_count()

    for _ <- 1..32 do
      assert {:ok, _} = Native.read_file_at_bounded(directory, "service", expected, 5)
      assert {:ok, _} = FileReader.read(directory, "service", expected, 5)
      assert_refusal(directory, "service", expected, 4, :file_byte_limit)
      assert_refusal(directory, "service", stale, 5, :directory_changed)
      assert_refusal(directory, "subdir", expected, 5, :not_regular_file)
      assert_refusal(directory, "fifo", expected, 5, :not_regular_file)
      assert_refusal(directory, "missing", expected, 5, {:errno, 2})
    end

    assert fd_count() == before_count
  end

  defp directory_identity(directory) do
    assert {:ok, result} = Directory.list(directory)
    result.identity.after
  end

  defp assert_refusal(directory, name, expected, budget, reason) do
    path = Path.join(directory, name)
    assert {:error, ^reason} = Native.read_file_at_bounded(directory, name, expected, budget)

    assert {:error, %{reason: ^reason, path: ^path}} =
             FileReader.read(directory, name, expected, budget)
  end

  defp assert_file(result, directory, name, expected, bytes, budget) do
    assert result.bytes == bytes
    assert result.bytes_read == byte_size(bytes)
    assert result.syscall_attempts >= 1
    assert result.syscall_attempts <= div(budget, 4096) + 4
    assert result.directory == %{before: expected, after: expected, path: expected}
    assert result.identity.before == result.identity.after
    assert result.identity.after == result.identity.path
    assert result.bytes_read == result.identity.before.size
    metadata = result.identity.before
    assert Enum.sort(Map.keys(metadata)) == [:ctime, :device, :inode, :mode, :mtime, :size]
    stat = File.stat!(directory <> "/" <> name, time: :posix)
    assert stat.type == :regular
    assert metadata.device == stat.major_device
    assert metadata.inode == stat.inode
    assert metadata.mode == stat.mode
    assert metadata.size == stat.size
    assert_timestamp(metadata.mtime, stat.mtime)
    assert_timestamp(metadata.ctime, stat.ctime)
  end

  defp assert_timestamp({seconds, nanoseconds}, expected_seconds) do
    assert seconds == expected_seconds
    assert is_integer(nanoseconds)
    assert nanoseconds >= 0 and nanoseconds < 1_000_000_000
  end

  defp fd_count, do: length(File.ls!("/proc/#{System.pid()}/fd"))
end
