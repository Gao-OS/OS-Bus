defmodule ExDBus.Wire.Decoder do
  @moduledoc """
  Decode D-Bus wire protocol binary format to Elixir terms.

  The inverse of `ExDBus.Wire.Encoder`. Uses binary pattern matching for decoding,
  consuming correct alignment padding before each value.

  All decode functions return `{:ok, value, rest, new_offset}` internally,
  where `rest` is the remaining binary and `new_offset` tracks position
  for alignment calculations.

  Finite doubles are Elixir floats. Nonfinite IEEE 754 values use
  `{:ieee754, unsigned_64_bits}`, preserving infinity signs and NaN payloads.
  """

  alias ExDBus.Wire.Types

  @doc """
  Decode a single value from a D-Bus wire format binary.

  Returns `{:ok, value, rest}` or `{:error, reason}`.

  ## Examples

      iex> ExDBus.Wire.Decoder.decode(<<42, 0, 0, 0>>, :int32)
      {:ok, 42, <<>>}

      iex> ExDBus.Wire.Decoder.decode(<<5, 0, 0, 0, "hello", 0>>, :string)
      {:ok, "hello", <<>>}
  """
  @spec decode(
          binary(),
          ExDBus.Wire.Types.dbus_type() | String.t(),
          ExDBus.Wire.Types.endianness()
        ) ::
          {:ok, term(), binary()} | {:error, term()}
  def decode(binary, type, endianness \\ :little) do
    with {:ok, type} <- normalize_type(type) do
      case decode_impl(binary, type, endianness, 0, 0) do
        {:ok, value, rest, _offset} -> {:ok, value, rest}
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  Decode a value at a specific offset (for internal use and message decoding).

  Returns `{:ok, value, rest, new_offset}` or `{:error, reason}`.
  """
  @spec decode_at(
          binary(),
          ExDBus.Wire.Types.dbus_type() | String.t(),
          ExDBus.Wire.Types.endianness(),
          non_neg_integer()
        ) :: {:ok, term(), binary(), non_neg_integer()} | {:error, term()}
  def decode_at(binary, type, endianness, offset) do
    with {:ok, type} <- normalize_type(type) do
      decode_impl(binary, type, endianness, offset, 0)
    end
  end

  defp normalize_type(type) when is_binary(type), do: Types.parse_signature(type)

  defp normalize_type(type) do
    type |> Types.serialize_signature() |> Types.parse_signature()
  rescue
    FunctionClauseError -> {:error, {:invalid_type, type}}
  end

  # Skip alignment padding bytes
  defp consume_padding(binary, offset, alignment) do
    padding = rem(alignment - rem(offset, alignment), alignment)

    case binary do
      <<pad::binary-size(padding), rest::binary>> ->
        if pad == :binary.copy(<<0>>, padding) do
          {:ok, rest, offset + padding}
        else
          {:error, :nonzero_padding}
        end

      _ ->
        {:error, {:insufficient_data_for_padding, byte_size(binary), padding}}
    end
  end

  # Consume alignment padding before array elements (struct/dict_entry need 8-byte alignment)
  defp consume_array_element_padding(binary, offset, elem_align) when elem_align > 4 do
    consume_padding(binary, offset, elem_align)
  end

  defp consume_array_element_padding(binary, offset, _elem_align) do
    {:ok, binary, offset}
  end

  # --- Basic types ---

  defp decode_impl(_binary, type, _endianness, _offset, depth)
       when depth >= 64 and (type == :variant or is_tuple(type)),
       do: {:error, :container_depth_exceeded}

  defp decode_impl(binary, :byte, _endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 1) do
      case rest do
        <<value::unsigned-integer-size(8), rest2::binary>> ->
          {:ok, value, rest2, offset + 1}

        _ ->
          {:error, {:insufficient_data, :byte}}
      end
    end
  end

  defp decode_impl(binary, :boolean, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4) do
      case decode_raw_uint32(rest, endianness) do
        {:ok, 0, rest2} -> {:ok, false, rest2, offset + 4}
        {:ok, 1, rest2} -> {:ok, true, rest2, offset + 4}
        {:ok, v, _rest2} -> {:error, {:invalid_boolean, v}}
        error -> error
      end
    end
  end

  defp decode_impl(binary, :int16, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 2) do
      case {endianness, rest} do
        {:little, <<value::signed-integer-size(16)-little, rest2::binary>>} ->
          {:ok, value, rest2, offset + 2}

        {:big, <<value::signed-integer-size(16)-big, rest2::binary>>} ->
          {:ok, value, rest2, offset + 2}

        _ ->
          {:error, {:insufficient_data, :int16}}
      end
    end
  end

  defp decode_impl(binary, :uint16, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 2) do
      case {endianness, rest} do
        {:little, <<value::unsigned-integer-size(16)-little, rest2::binary>>} ->
          {:ok, value, rest2, offset + 2}

        {:big, <<value::unsigned-integer-size(16)-big, rest2::binary>>} ->
          {:ok, value, rest2, offset + 2}

        _ ->
          {:error, {:insufficient_data, :uint16}}
      end
    end
  end

  defp decode_impl(binary, :int32, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4) do
      case {endianness, rest} do
        {:little, <<value::signed-integer-size(32)-little, rest2::binary>>} ->
          {:ok, value, rest2, offset + 4}

        {:big, <<value::signed-integer-size(32)-big, rest2::binary>>} ->
          {:ok, value, rest2, offset + 4}

        _ ->
          {:error, {:insufficient_data, :int32}}
      end
    end
  end

  defp decode_impl(binary, :uint32, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4) do
      decode_raw_uint32_with_offset(rest, endianness, offset)
    end
  end

  defp decode_impl(binary, :int64, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 8) do
      case {endianness, rest} do
        {:little, <<value::signed-integer-size(64)-little, rest2::binary>>} ->
          {:ok, value, rest2, offset + 8}

        {:big, <<value::signed-integer-size(64)-big, rest2::binary>>} ->
          {:ok, value, rest2, offset + 8}

        _ ->
          {:error, {:insufficient_data, :int64}}
      end
    end
  end

  defp decode_impl(binary, :uint64, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 8) do
      case {endianness, rest} do
        {:little, <<value::unsigned-integer-size(64)-little, rest2::binary>>} ->
          {:ok, value, rest2, offset + 8}

        {:big, <<value::unsigned-integer-size(64)-big, rest2::binary>>} ->
          {:ok, value, rest2, offset + 8}

        _ ->
          {:error, {:insufficient_data, :uint64}}
      end
    end
  end

  defp decode_impl(binary, :double, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 8) do
      case {endianness, rest} do
        {:little, <<bits::unsigned-64-little, rest2::binary>>} ->
          {:ok, decode_double(bits), rest2, offset + 8}

        {:big, <<bits::unsigned-64-big, rest2::binary>>} ->
          {:ok, decode_double(bits), rest2, offset + 8}

        _ ->
          {:error, {:insufficient_data, :double}}
      end
    end
  end

  defp decode_impl(binary, :string, endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4),
         {:ok, len, rest2} <- decode_raw_uint32(rest, endianness) do
      offset = offset + 4

      case rest2 do
        <<str::binary-size(len), 0, rest3::binary>> ->
          if Types.valid?(:string, str) do
            {:ok, str, rest3, offset + len + 1}
          else
            {:error, :invalid_string}
          end

        <<_str::binary-size(len), _not_nul, _::binary>> ->
          {:error, :invalid_string_terminator}

        _ ->
          {:error, {:insufficient_data, :string}}
      end
    end
  end

  defp decode_impl(binary, :object_path, endianness, offset, _depth) do
    with {:ok, path, rest, new_offset} <- decode_impl(binary, :string, endianness, offset, 0) do
      if Types.valid?(:object_path, path) do
        {:ok, path, rest, new_offset}
      else
        {:error, :invalid_object_path}
      end
    end
  end

  defp decode_impl(binary, :signature, _endianness, offset, _depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 1),
         <<len::unsigned-integer-size(8), rest2::binary>> <- rest,
         offset = offset + 1,
         <<sig::binary-size(len), 0, rest3::binary>> <- rest2 do
      case Types.parse_types(sig) do
        {:ok, _types} -> {:ok, sig, rest3, offset + len + 1}
        {:error, reason} -> {:error, {:invalid_signature, reason}}
      end
    else
      {:error, _} = err -> err
      _ -> {:error, {:insufficient_data, :signature}}
    end
  end

  defp decode_impl(binary, :unix_fd, endianness, offset, _depth) do
    # Same wire format as uint32
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4) do
      decode_raw_uint32_with_offset(rest, endianness, offset)
    end
  end

  # --- Container types ---

  defp decode_impl(binary, :variant, endianness, offset, depth) do
    # Decode signature first
    with {:ok, sig_str, rest, offset} <-
           decode_impl(binary, :signature, endianness, offset, depth),
         {:ok, val_type} <- Types.parse_signature(sig_str),
         {:ok, value, rest2, offset} <- decode_impl(rest, val_type, endianness, offset, depth + 1) do
      {:ok, {sig_str, value}, rest2, offset}
    end
  end

  defp decode_impl(binary, {:array, elem_type}, endianness, offset, depth) do
    with {:ok, rest, offset} <- consume_padding(binary, offset, 4),
         {:ok, array_len, rest} <- decode_raw_uint32(rest, endianness),
         true <- array_len <= 67_108_864 or {:error, {:array_too_large, array_len}},
         {:ok, rest, offset} <-
           consume_array_element_padding(rest, offset + 4, Types.alignment(elem_type)),
         <<elements::binary-size(array_len), tail::binary>> <- rest,
         {:ok, values, <<>>, new_offset} <-
           decode_array_elements(elements, elem_type, endianness, offset, depth + 1, []) do
      {:ok, values, tail, new_offset}
    else
      {:error, _} = error -> error
      _ -> {:error, {:insufficient_data, :array}}
    end
  end

  defp decode_impl(binary, {:struct, types}, endianness, offset, depth) do
    # Struct starts with 8-byte alignment
    with {:ok, rest, offset} <- consume_padding(binary, offset, 8) do
      decode_struct_members(rest, types, endianness, offset, depth + 1, [])
    end
  end

  defp decode_impl(binary, {:dict_entry, key_type, val_type}, endianness, offset, depth) do
    # Dict entry starts with 8-byte alignment
    with {:ok, rest, offset} <- consume_padding(binary, offset, 8),
         {:ok, key, rest2, offset} <- decode_impl(rest, key_type, endianness, offset, depth + 1),
         {:ok, val, rest3, offset} <- decode_impl(rest2, val_type, endianness, offset, depth + 1) do
      {:ok, {key, val}, rest3, offset}
    end
  end

  # --- Array element helpers ---

  defp decode_array_elements(<<>>, _elem_type, _endianness, offset, _depth, acc),
    do: {:ok, Enum.reverse(acc), <<>>, offset}

  defp decode_array_elements(binary, elem_type, endianness, offset, depth, acc) do
    case decode_impl(binary, elem_type, endianness, offset, depth) do
      {:ok, value, rest, new_offset} when new_offset > offset ->
        decode_array_elements(rest, elem_type, endianness, new_offset, depth, [value | acc])

      {:ok, _value, _rest, _offset} ->
        {:error, :nonprogressing_array_element}

      {:error, reason} ->
        {:error, {:invalid_array_element, reason}}
    end
  end

  # --- Struct member helpers ---

  defp decode_struct_members(binary, [], _endianness, offset, _depth, acc) do
    {:ok, List.to_tuple(Enum.reverse(acc)), binary, offset}
  end

  defp decode_struct_members(binary, [type | types], endianness, offset, depth, acc) do
    case decode_impl(binary, type, endianness, offset, depth) do
      {:ok, value, rest, new_offset} ->
        decode_struct_members(rest, types, endianness, new_offset, depth, [value | acc])

      error ->
        error
    end
  end

  # --- Raw decode helpers (without offset tracking, for internal use) ---

  defp decode_double(bits) do
    if Types.valid?(:double, {:ieee754, bits}) do
      {:ieee754, bits}
    else
      <<value::float-64>> = <<bits::unsigned-64>>
      value
    end
  end

  defp decode_raw_uint32(binary, :little) do
    case binary do
      <<value::unsigned-integer-size(32)-little, rest::binary>> -> {:ok, value, rest}
      _ -> {:error, {:insufficient_data, :uint32}}
    end
  end

  defp decode_raw_uint32(binary, :big) do
    case binary do
      <<value::unsigned-integer-size(32)-big, rest::binary>> -> {:ok, value, rest}
      _ -> {:error, {:insufficient_data, :uint32}}
    end
  end

  defp decode_raw_uint32_with_offset(binary, endianness, offset) do
    case decode_raw_uint32(binary, endianness) do
      {:ok, value, rest} -> {:ok, value, rest, offset + 4}
      error -> error
    end
  end
end
