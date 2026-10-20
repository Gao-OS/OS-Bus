defmodule ExDBus.Wire.Encoder do
  @moduledoc """
  Encode Elixir terms to D-Bus wire protocol binary format.

  Uses iolist accumulation for zero-copy performance.
  Handles all alignment rules correctly as per the D-Bus spec.

  Endianness: :little (default) or :big
  """

  alias ExDBus.Wire.Types

  @doc """
  Encode a single value to D-Bus wire format.

  Returns an iolist that should be flattened to binary via IO.iodata_to_binary/1.

  ## Examples

      iex> ExDBus.Wire.Encoder.encode(42, :int32) |> IO.iodata_to_binary()
      <<42, 0, 0, 0>>

      iex> ExDBus.Wire.Encoder.encode("hello", :string) |> IO.iodata_to_binary()
      <<5, 0, 0, 0, 104, 101, 108, 108, 111, 0>>
  """
  @spec encode(term(), ExDBus.Wire.Types.dbus_type() | String.t(), ExDBus.Wire.Types.endianness()) ::
          iodata()
  def encode(value, type, endianness \\ :little) do
    type = normalize_type(type)
    encode_impl(value, type, endianness, 0, 0)
  end

  @doc """
  Encode a value at a specific byte offset (for correct alignment in messages).

  Returns `{iolist, new_offset}` where new_offset is the position after encoding.
  """
  @spec encode_at(
          term(),
          ExDBus.Wire.Types.dbus_type() | String.t(),
          ExDBus.Wire.Types.endianness(),
          non_neg_integer()
        ) :: {iodata(), non_neg_integer()}
  def encode_at(value, type, endianness, offset) do
    type = normalize_type(type)
    iolist = encode_impl(value, type, endianness, offset, 0)
    binary = IO.iodata_to_binary(iolist)
    {iolist, offset + byte_size(binary)}
  end

  defp normalize_type(type) when is_binary(type) do
    case Types.parse_signature(type) do
      {:ok, parsed} -> parsed
      {:error, _} -> raise ArgumentError, "Invalid type signature: #{type}"
    end
  end

  defp normalize_type(type) do
    type |> Types.serialize_signature() |> normalize_type()
  rescue
    FunctionClauseError -> raise ArgumentError, "Invalid type: #{inspect(type)}"
  end

  defp align(offset, target_alignment) do
    padding = rem(target_alignment - rem(offset, target_alignment), target_alignment)
    {<<0::size(padding)-unit(8)>>, padding}
  end

  # Variants introduce signatures dynamically, so static signature validation
  # alone cannot enforce the total container depth.
  defp encode_impl(_value, type, _endianness, _offset, depth)
       when depth >= 64 and (type == :variant or is_tuple(type)),
       do: raise(ArgumentError, "Container depth exceeds 64")

  # --- All encode_impl/5 clauses grouped together ---

  defp encode_impl(value, :byte, _endianness, offset, _depth) do
    Types.valid?(:byte, value) || raise ArgumentError, "Invalid byte: #{inspect(value)}"
    {pad, _} = align(offset, 1)
    [pad, <<value::unsigned-integer-size(8)>>]
  end

  defp encode_impl(value, :boolean, endianness, offset, _depth) do
    Types.valid?(:boolean, value) || raise ArgumentError, "Invalid boolean: #{inspect(value)}"
    {pad, _} = align(offset, 4)
    val_int = if value, do: 1, else: 0
    [pad, encode_uint32(val_int, endianness)]
  end

  defp encode_impl(value, :int16, endianness, offset, _depth) do
    Types.valid?(:int16, value) || raise ArgumentError, "Invalid int16: #{inspect(value)}"
    {pad, _} = align(offset, 2)
    [pad, encode_int16(value, endianness)]
  end

  defp encode_impl(value, :uint16, endianness, offset, _depth) do
    Types.valid?(:uint16, value) || raise ArgumentError, "Invalid uint16: #{inspect(value)}"
    {pad, _} = align(offset, 2)
    [pad, encode_uint16(value, endianness)]
  end

  defp encode_impl(value, :int32, endianness, offset, _depth) do
    Types.valid?(:int32, value) || raise ArgumentError, "Invalid int32: #{inspect(value)}"
    {pad, _} = align(offset, 4)
    [pad, encode_int32(value, endianness)]
  end

  defp encode_impl(value, :uint32, endianness, offset, _depth) do
    Types.valid?(:uint32, value) || raise ArgumentError, "Invalid uint32: #{inspect(value)}"
    {pad, _} = align(offset, 4)
    [pad, encode_uint32(value, endianness)]
  end

  defp encode_impl(value, :int64, endianness, offset, _depth) do
    Types.valid?(:int64, value) || raise ArgumentError, "Invalid int64: #{inspect(value)}"
    {pad, _} = align(offset, 8)
    [pad, encode_int64(value, endianness)]
  end

  defp encode_impl(value, :uint64, endianness, offset, _depth) do
    Types.valid?(:uint64, value) || raise ArgumentError, "Invalid uint64: #{inspect(value)}"
    {pad, _} = align(offset, 8)
    [pad, encode_uint64(value, endianness)]
  end

  defp encode_impl(value, :double, endianness, offset, _depth) do
    Types.valid?(:double, value) || raise ArgumentError, "Invalid double: #{inspect(value)}"
    {pad, _} = align(offset, 8)

    encoded =
      case value do
        {:ieee754, bits} -> encode_uint64(bits, endianness)
        value -> encode_double(if(is_integer(value), do: value / 1.0, else: value), endianness)
      end

    [pad, encoded]
  end

  defp encode_impl(value, :string, endianness, offset, _depth) do
    Types.valid?(:string, value) || raise ArgumentError, "Invalid string: #{inspect(value)}"
    {pad, _} = align(offset, 4)
    len = byte_size(value)
    [pad, encode_uint32(len, endianness), value, <<0>>]
  end

  defp encode_impl(value, :object_path, endianness, offset, _depth) do
    Types.valid?(:object_path, value) ||
      raise ArgumentError, "Invalid object_path: #{inspect(value)}"

    {pad, _} = align(offset, 4)
    len = byte_size(value)
    [pad, encode_uint32(len, endianness), value, <<0>>]
  end

  defp encode_impl(value, :signature, _endianness, offset, _depth) do
    Types.valid?(:signature, value) || raise ArgumentError, "Invalid signature: #{inspect(value)}"
    {pad, _} = align(offset, 1)
    len = byte_size(value)
    [pad, <<len::unsigned-integer-size(8)>>, value, <<0>>]
  end

  defp encode_impl(value, :unix_fd, endianness, offset, _depth) do
    Types.valid?(:unix_fd, value) || raise ArgumentError, "Invalid unix_fd: #{inspect(value)}"
    {pad, _} = align(offset, 4)
    [pad, encode_uint32(value, endianness)]
  end

  defp encode_impl(value, :variant, endianness, offset, depth) do
    Types.valid?(:variant, value) || raise ArgumentError, "Invalid variant: #{inspect(value)}"
    {sig_str, val} = value
    {pad, pad_len} = align(offset, 1)
    sig_len = byte_size(sig_str)
    sig_encoded = [<<sig_len::unsigned-integer-size(8)>>, sig_str, <<0>>]
    val_type = normalize_type(sig_str)
    val_offset = offset + pad_len + 1 + sig_len + 1
    val_encoded = encode_impl(val, val_type, endianness, val_offset, depth + 1)
    [pad, sig_encoded, val_encoded]
  end

  defp encode_impl(value, {:array, elem_type}, endianness, offset, depth) do
    is_list(value) || raise ArgumentError, "Array value must be a list, got: #{inspect(value)}"
    {pad, pad_len} = align(offset, 4)

    # Per D-Bus spec: array body starts at the next alignment boundary for the element type
    # after the length prefix. This padding is NOT included in the array length.
    length_prefix_offset = offset + pad_len + 4
    elem_align = Types.alignment(elem_type)
    {elem_pad, elem_pad_len} = align(length_prefix_offset, elem_align)

    elem_start_offset = length_prefix_offset + elem_pad_len

    elements_iolist =
      encode_array_elements(value, elem_type, endianness, elem_start_offset, depth + 1)

    elements_binary = IO.iodata_to_binary(elements_iolist)
    array_len = byte_size(elements_binary)
    if array_len > 67_108_864, do: raise(ArgumentError, "Array exceeds 64 MiB")

    [pad, encode_uint32(array_len, endianness), elem_pad, elements_iolist]
  end

  defp encode_impl(value, {:struct, types}, endianness, offset, depth) do
    is_tuple(value) || raise ArgumentError, "Struct value must be a tuple, got: #{inspect(value)}"
    {pad, pad_len} = align(offset, 8)
    values_list = Tuple.to_list(value)
    if length(values_list) != length(types), do: raise(ArgumentError, "Struct arity mismatch")
    result = encode_struct_members(values_list, types, endianness, offset + pad_len, depth + 1)
    [pad, result]
  end

  defp encode_impl(value, {:dict_entry, key_type, val_type}, endianness, offset, depth) do
    (is_tuple(value) and tuple_size(value) == 2) ||
      raise ArgumentError, "Dict entry must be a 2-tuple, got: #{inspect(value)}"

    {pad, pad_len} = align(offset, 8)
    {key, val} = value
    key_encoded = encode_impl(key, key_type, endianness, offset + pad_len, depth + 1)
    key_binary = IO.iodata_to_binary(key_encoded)
    key_len = byte_size(key_binary)
    val_encoded = encode_impl(val, val_type, endianness, offset + pad_len + key_len, depth + 1)
    [pad, key_encoded, val_encoded]
  end

  # --- Helper functions ---

  defp encode_array_elements([], _elem_type, _endianness, _offset, _depth), do: []

  defp encode_array_elements([head | tail], elem_type, endianness, offset, depth) do
    encoded_head = encode_impl(head, elem_type, endianness, offset, depth)
    head_binary = IO.iodata_to_binary(encoded_head)
    new_offset = offset + byte_size(head_binary)
    encoded_tail = encode_array_elements(tail, elem_type, endianness, new_offset, depth)
    [encoded_head, encoded_tail]
  end

  defp encode_struct_members([], [], _endianness, _offset, _depth), do: []

  defp encode_struct_members([value | values], [type | types], endianness, offset, depth) do
    encoded = encode_impl(value, type, endianness, offset, depth)
    encoded_binary = IO.iodata_to_binary(encoded)
    new_offset = offset + byte_size(encoded_binary)
    rest = encode_struct_members(values, types, endianness, new_offset, depth)
    [encoded, rest]
  end

  defp encode_int16(value, :little), do: <<value::signed-integer-size(16)-little>>
  defp encode_int16(value, :big), do: <<value::signed-integer-size(16)-big>>

  defp encode_uint16(value, :little), do: <<value::unsigned-integer-size(16)-little>>
  defp encode_uint16(value, :big), do: <<value::unsigned-integer-size(16)-big>>

  defp encode_int32(value, :little), do: <<value::signed-integer-size(32)-little>>
  defp encode_int32(value, :big), do: <<value::signed-integer-size(32)-big>>

  defp encode_uint32(value, :little), do: <<value::unsigned-integer-size(32)-little>>
  defp encode_uint32(value, :big), do: <<value::unsigned-integer-size(32)-big>>

  defp encode_int64(value, :little), do: <<value::signed-integer-size(64)-little>>
  defp encode_int64(value, :big), do: <<value::signed-integer-size(64)-big>>

  defp encode_uint64(value, :little), do: <<value::unsigned-integer-size(64)-little>>
  defp encode_uint64(value, :big), do: <<value::unsigned-integer-size(64)-big>>

  defp encode_double(value, :little), do: <<value::float-size(64)-little>>
  defp encode_double(value, :big), do: <<value::float-size(64)-big>>
end
