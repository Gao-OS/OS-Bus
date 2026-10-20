defmodule GaoBus.Unix.FileReader do
  @moduledoc """
  Reads a bounded regular file relative to a verified Linux directory.

  Pass the directory's `Directory.list/3` result's `identity.after` metadata.
  Trusted directory and leaf symlinks are followed. Names must be valid UTF-8;
  file contents remain raw bytes. Identity checks detect observed changes,
  without providing an atomic snapshot or a hard filesystem timeout.
  """

  alias GaoBus.Unix.Native

  @max_bytes 1_048_576
  @max_path_bytes 4096
  @max_name_bytes 255

  @spec read(term(), term(), term(), term()) :: {:ok, map()} | {:error, map()}
  def read(directory, name, expected_directory, bytes \\ @max_bytes) do
    cond do
      not valid_path?(directory) ->
        {:error, %{reason: :invalid_path, path: nil}}

      not valid_name?(name) ->
        {:error, %{reason: :invalid_name, path: nil}}

      true ->
        path = Path.join(directory, name)

        case Native.read_file_at_bounded(directory, name, expected_directory, bytes) do
          {:ok, result} -> {:ok, Map.put(result, :path, path)}
          {:error, reason} -> {:error, %{reason: reason, path: path}}
        end
    end
  end

  defp valid_path?(path)
       when is_binary(path) and byte_size(path) > 0 and byte_size(path) <= @max_path_bytes,
       do: :binary.match(path, <<0>>) == :nomatch

  defp valid_path?(_path), do: false

  defp valid_name?(name)
       when is_binary(name) and byte_size(name) > 0 and byte_size(name) <= @max_name_bytes,
       do:
         name not in [".", ".."] and :binary.match(name, [<<0>>, "/"]) == :nomatch and
           String.valid?(name)

  defp valid_name?(_name), do: false
end
