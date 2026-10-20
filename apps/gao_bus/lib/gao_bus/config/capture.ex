defmodule GaoBus.Config.Capture do
  @moduledoc """
  One bounded, immutable cache of configuration directory and file observations.

  Shared captures provide coherent consumer inputs, not a cross-file filesystem
  transaction. Failed directory enumeration has no partial counters, so its
  reserved credit is retained separately from successfully observed entries.
  """

  alias GaoBus.Unix.{Directory, FileReader}

  defstruct directories: %{},
            files: %{},
            directory_attempts: 0,
            file_attempts: 0,
            entries: 0,
            name_bytes: 0,
            reserved_entries: 0,
            reserved_name_bytes: 0,
            bytes: 0

  @directory_limit 64
  @entry_limit 8192
  @name_byte_limit 2_097_152
  @file_limit 1024
  @byte_limit 16_777_216
  @file_bytes 1_048_576

  def new, do: %__MODULE__{}

  def list(%__MODULE__{} = capture, path) do
    case normalize(path) do
      {:ok, path} ->
        case Map.fetch(capture.directories, path) do
          {:ok, result} -> reply(result, capture)
          :error -> list_new(capture, path)
        end

      :error ->
        {:error, error(nil, :list, :invalid_path), capture}
    end
  end

  def read(%__MODULE__{} = capture, path, bytes \\ @file_bytes) do
    case normalize(path) do
      {:ok, path} ->
        if is_integer(bytes) and bytes in 0..@file_bytes do
          case Map.fetch(capture.files, path) do
            {:ok, {:ok, record}} when record.bytes_read > bytes ->
              {:error, error(path, :read, :file_byte_limit), capture}

            {:ok, result} ->
              reply(result, capture)

            :error ->
              read_new(capture, path, bytes)
          end
        else
          {:error, error(path, :read, :invalid_budget), capture}
        end

      :error ->
        {:error, error(nil, :read, :invalid_path), capture}
    end
  end

  def summary(%__MODULE__{} = capture) do
    %{
      directory_attempts: capture.directory_attempts,
      file_attempts: capture.file_attempts,
      entries: capture.entries,
      name_bytes: capture.name_bytes,
      reserved_entries: capture.reserved_entries,
      reserved_name_bytes: capture.reserved_name_bytes,
      bytes: capture.bytes,
      directories: capture.directories,
      files:
        Map.new(capture.files, fn
          {path, {:ok, record}} -> {path, {:ok, Map.delete(record, :bytes)}}
          {path, failure} -> {path, failure}
        end)
    }
  end

  defp list_new(capture, path) when capture.directory_attempts >= @directory_limit,
    do: {:error, error(path, :list, :capture_directory_limit), capture}

  defp list_new(capture, path) do
    entries = min(1024, @entry_limit - capture.entries - capture.reserved_entries)
    name_bytes = min(262_144, @name_byte_limit - capture.name_bytes - capture.reserved_name_bytes)
    capture = %{capture | directory_attempts: capture.directory_attempts + 1}

    {result, capture} =
      case Directory.list(path, entries, name_bytes) do
        {:ok, record} ->
          record = Map.put(record, :path, path)

          {{:ok, record},
           %{
             capture
             | entries: capture.entries + record.examined,
               name_bytes: capture.name_bytes + record.name_bytes
           }}

        {:error, %{reason: reason}} ->
          # Directory's numeric errno does not identify the failing syscall.
          # Even ENOENT can occur in its final pathname check after enumeration.
          capture = %{
            capture
            | reserved_entries: capture.reserved_entries + entries,
              reserved_name_bytes: capture.reserved_name_bytes + name_bytes
          }

          {{:error, error(path, :list, reason)}, capture}
      end

    capture = %{capture | directories: Map.put(capture.directories, path, result)}
    reply(result, capture)
  end

  defp read_new(capture, path, _bytes) when capture.file_attempts >= @file_limit,
    do: {:error, error(path, :read, :capture_file_limit), capture}

  defp read_new(capture, path, bytes) do
    capture = %{capture | file_attempts: capture.file_attempts + 1}

    {result, capture} =
      case list(capture, Path.dirname(path)) do
        {:ok, directory, capture} ->
          credit = min(bytes, @byte_limit - capture.bytes)

          case FileReader.read(
                 Path.dirname(path),
                 Path.basename(path),
                 directory.identity.after,
                 credit
               ) do
            {:ok, record} ->
              # The native result can retain a credit+1 backing allocation.
              # Cache compact bytes so the shared retained-byte cap stays real.
              record = %{record | bytes: :binary.copy(record.bytes)}

              record =
                record
                |> Map.put(
                  :sha256,
                  Base.encode16(:crypto.hash(:sha256, record.bytes), case: :lower)
                )
                |> Map.put(:read_attempts, record.syscall_attempts)

              {{:ok, record}, %{capture | bytes: capture.bytes + record.bytes_read}}

            {:error, %{reason: reason}} ->
              {{:error, error(path, :read, reason)}, capture}
          end

        {:error, failure, capture} ->
          {{:error, %{failure | path: path, operation: :read}}, capture}
      end

    capture = %{capture | files: Map.put(capture.files, path, result)}
    reply(result, capture)
  end

  defp normalize(path) when is_binary(path) and byte_size(path) in 1..4096 do
    if String.valid?(path) and :binary.match(path, <<0>>) == :nomatch do
      expanded = Path.expand(path)
      if byte_size(expanded) <= 4096, do: {:ok, expanded}, else: :error
    else
      :error
    end
  end

  defp normalize(_path), do: :error

  defp error(path, operation, native_reason) do
    reason =
      case native_reason do
        {:errno, 2} -> :enoent
        {:errno, 13} -> :eacces
        {:errno, 20} -> :enotdir
        reason -> reason
      end

    %{path: path, operation: operation, reason: reason, native_reason: native_reason}
  end

  defp reply({:ok, record}, capture), do: {:ok, record, capture}
  defp reply({:error, reason}, capture), do: {:error, reason, capture}
end
