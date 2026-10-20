defmodule GaoBus.Unix.Directory do
  @moduledoc """
  Lists a complete bounded Linux directory, refusing invalid UTF-8 filenames.

  All non-dot entries consume the caller's entry and filename-byte budgets.
  Metadata comparisons detect observed changes; they do not provide an atomic
  snapshot or anchor subsequent opens of the returned names.
  """

  alias GaoBus.Unix.Native

  @max_entries 1024
  @max_name_bytes 262_144
  @max_path_bytes 4096

  @spec list(term(), term(), term()) :: {:ok, map()} | {:error, map()}
  def list(path, entries \\ @max_entries, name_bytes \\ @max_name_bytes) do
    cond do
      not valid_path?(path) ->
        {:error, %{reason: :invalid_path, path: nil}}

      not valid_budget?(entries, @max_entries) or
          not valid_budget?(name_bytes, @max_name_bytes) ->
        {:error, %{reason: :invalid_budget, path: path}}

      true ->
        with {:ok, result} <- Native.list_dir_bounded(path, entries, name_bytes),
             :ok <- valid_names(result.names) do
          {:ok, %{result | names: Enum.sort(result.names)}}
        else
          {:error, reason} -> {:error, %{reason: reason, path: path}}
        end
    end
  end

  defp valid_path?(path)
       when is_binary(path) and byte_size(path) > 0 and byte_size(path) <= @max_path_bytes,
       do: :binary.match(path, <<0>>) == :nomatch

  defp valid_path?(_path), do: false

  defp valid_budget?(budget, maximum),
    do: is_integer(budget) and budget >= 0 and budget <= maximum

  defp valid_names(names) do
    case Enum.find(names, &(not String.valid?(&1))) do
      nil -> :ok
      name -> {:error, {:invalid_name_encoding, name}}
    end
  end
end
