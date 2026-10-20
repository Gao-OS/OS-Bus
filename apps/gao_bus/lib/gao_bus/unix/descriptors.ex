defmodule GaoBus.Unix.Descriptors do
  @moduledoc false
  alias ExDBus.Wire.Types

  # The codec has already checked value/type shape. Resource indices must also
  # refer to this frame's actual ancillary bundle, including inside variants.
  def valid?(message, handles, negotiated?, max_fds \\ 16) do
    count = message.unix_fds || 0

    count == length(handles) and count <= max_fds and (count == 0 or negotiated?) and
      case Types.parse_types(message.signature || "") do
        {:ok, types} -> values_valid?(types, message.body, count)
        {:error, _} -> false
      end
  end

  defp values_valid?([], [], _count), do: true

  defp values_valid?([type | types], [value | values], count),
    do: value_valid?(type, value, count) and values_valid?(types, values, count)

  defp values_valid?(_, _, _count), do: false

  defp value_valid?(:unix_fd, index, count),
    do: is_integer(index) and index >= 0 and index < count

  defp value_valid?({:array, type}, values, count),
    do: Enum.all?(values, &value_valid?(type, &1, count))

  defp value_valid?({:struct, types}, values, count),
    do: values_valid?(types, Tuple.to_list(values), count)

  defp value_valid?({:dict_entry, key, value}, {k, v}, count),
    do: value_valid?(key, k, count) and value_valid?(value, v, count)

  defp value_valid?(:variant, {signature, value}, count) do
    case Types.parse_signature(signature) do
      {:ok, type} -> value_valid?(type, value, count)
      {:error, _} -> false
    end
  end

  defp value_valid?(_type, _value, _count), do: true
end
