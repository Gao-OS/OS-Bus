defmodule ExDBus.Wire.Types do
  @moduledoc """
  D-Bus type system: signature parsing, validation, and Elixir type mapping.

  D-Bus wire protocol uses type signatures like "a{sv}" (array of dict entries with string keys and variant values).
  This module parses and validates signatures, mapping them to internal type representations.

  Type mapping:
    y → byte        (0..255)
    b → boolean     (true/false)
    n → int16       (integer)
    q → uint16      (integer)
    i → int32       (integer)
    u → uint32      (integer)
    x → int64       (integer)
    t → uint64      (integer)
    d → double      (float, or {:ieee754, unsigned_64_bits} for nonfinite values)
    s → string      (String.t())
    o → object_path (String.t(), validated)
    g → signature   (String.t(), validated)
    a → array       (list)
    ( ) → struct    (tuple)
    { } → dict_entry (2-tuple, usually in arrays forming maps)
    v → variant     ({signature, value})
    h → unix_fd     (integer, file descriptor number)
  """

  @type basic_type ::
          :byte
          | :boolean
          | :int16
          | :uint16
          | :int32
          | :uint32
          | :int64
          | :uint64
          | :double
          | :string
          | :object_path
          | :signature
          | :unix_fd
          | :variant

  @type dbus_type ::
          basic_type()
          | {:array, dbus_type()}
          | {:struct, [dbus_type()]}
          | {:dict_entry, dbus_type(), dbus_type()}

  @type endianness :: :little | :big

  @type double_value :: float() | {:ieee754, non_neg_integer()}

  @doc """
  Parse a D-Bus type signature string into an AST.

  Returns `{:ok, type}` or `{:error, reason}`.

  ## Examples

      iex> ExDBus.Wire.Types.parse_signature("i")
      {:ok, :int32}

      iex> ExDBus.Wire.Types.parse_signature("as")
      {:ok, {:array, :string}}

      iex> ExDBus.Wire.Types.parse_signature("a{sv}")
      {:ok, {:array, {:dict_entry, :string, :variant}}}

      iex> ExDBus.Wire.Types.parse_signature("(isi)")
      {:ok, {:struct, [:int32, :string, :int32]}}
  """
  @spec parse_signature(String.t()) :: {:ok, dbus_type()} | {:error, term()}
  def parse_signature(sig) when is_binary(sig) do
    case parse_types(sig) do
      {:ok, [type]} -> {:ok, type}
      {:ok, []} -> {:error, :empty_signature}
      {:ok, _types} -> {:error, :multiple_complete_types}
      error -> error
    end
  end

  # Depth is tracked separately for arrays and structs, as required by the spec.
  defp parse_signature_impl("a" <> _rest, {32, _structs}, _dict?),
    do: {:error, :array_depth_exceeded}

  defp parse_signature_impl("a" <> rest, {arrays, structs}, _dict?) do
    with {:ok, type, rest} <- parse_signature_impl(rest, {arrays + 1, structs}, true) do
      {:ok, {:array, type}, rest}
    end
  end

  defp parse_signature_impl("(" <> _rest, {_arrays, 32}, _dict?),
    do: {:error, :struct_depth_exceeded}

  defp parse_signature_impl("(" <> rest, {arrays, structs}, _dict?) do
    with {:ok, types, rest} <- parse_struct_members(rest, {arrays, structs + 1}, []) do
      {:ok, {:struct, types}, rest}
    end
  end

  defp parse_signature_impl("{" <> _rest, _depth, false),
    do: {:error, :dict_entry_outside_array}

  defp parse_signature_impl("{" <> _rest, {_arrays, 32}, true),
    do: {:error, :struct_depth_exceeded}

  defp parse_signature_impl("{" <> rest, {arrays, structs}, true) do
    depth = {arrays, structs + 1}

    with {:ok, key, rest} <- parse_signature_impl(rest, depth, false),
         true <- is_atom(key) and key != :variant,
         {:ok, value, rest} <- parse_signature_impl(rest, depth, false),
         "}" <> rest <- rest do
      {:ok, {:dict_entry, key, value}, rest}
    else
      false -> {:error, :invalid_dict_key_type}
      {:error, _} = error -> error
      _ -> {:error, :expected_closing_brace}
    end
  end

  defp parse_signature_impl("y" <> rest, _depth, _dict?), do: {:ok, :byte, rest}
  defp parse_signature_impl("b" <> rest, _depth, _dict?), do: {:ok, :boolean, rest}
  defp parse_signature_impl("n" <> rest, _depth, _dict?), do: {:ok, :int16, rest}
  defp parse_signature_impl("q" <> rest, _depth, _dict?), do: {:ok, :uint16, rest}
  defp parse_signature_impl("i" <> rest, _depth, _dict?), do: {:ok, :int32, rest}
  defp parse_signature_impl("u" <> rest, _depth, _dict?), do: {:ok, :uint32, rest}
  defp parse_signature_impl("x" <> rest, _depth, _dict?), do: {:ok, :int64, rest}
  defp parse_signature_impl("t" <> rest, _depth, _dict?), do: {:ok, :uint64, rest}
  defp parse_signature_impl("d" <> rest, _depth, _dict?), do: {:ok, :double, rest}
  defp parse_signature_impl("s" <> rest, _depth, _dict?), do: {:ok, :string, rest}
  defp parse_signature_impl("o" <> rest, _depth, _dict?), do: {:ok, :object_path, rest}
  defp parse_signature_impl("g" <> rest, _depth, _dict?), do: {:ok, :signature, rest}
  defp parse_signature_impl("h" <> rest, _depth, _dict?), do: {:ok, :unix_fd, rest}
  defp parse_signature_impl("v" <> rest, _depth, _dict?), do: {:ok, :variant, rest}

  defp parse_signature_impl("", _depth, _dict?), do: {:error, :empty_signature}
  defp parse_signature_impl(sig, _depth, _dict?), do: {:error, {:invalid_type_code, sig}}

  defp parse_struct_members(")" <> _rest, _depth, []), do: {:error, :empty_struct}
  defp parse_struct_members(")" <> rest, _depth, acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_struct_members(sig, depth, acc) do
    with {:ok, type, rest} <- parse_signature_impl(sig, depth, false) do
      parse_struct_members(rest, depth, [type | acc])
    end
  end

  @doc """
  Serialize a type AST back to a signature string.

  ## Examples

      iex> ExDBus.Wire.Types.serialize_signature(:int32)
      "i"

      iex> ExDBus.Wire.Types.serialize_signature({:array, :string})
      "as"

      iex> ExDBus.Wire.Types.serialize_signature({:array, {:dict_entry, :string, :variant}})
      "a{sv}"

      iex> ExDBus.Wire.Types.serialize_signature({:struct, [:int32, :string, :int32]})
      "(isi)"
  """
  @spec serialize_signature(dbus_type()) :: String.t()
  def serialize_signature(type) do
    serialize_impl(type)
  end

  defp serialize_impl(:byte), do: "y"
  defp serialize_impl(:boolean), do: "b"
  defp serialize_impl(:int16), do: "n"
  defp serialize_impl(:uint16), do: "q"
  defp serialize_impl(:int32), do: "i"
  defp serialize_impl(:uint32), do: "u"
  defp serialize_impl(:int64), do: "x"
  defp serialize_impl(:uint64), do: "t"
  defp serialize_impl(:double), do: "d"
  defp serialize_impl(:string), do: "s"
  defp serialize_impl(:object_path), do: "o"
  defp serialize_impl(:signature), do: "g"
  defp serialize_impl(:unix_fd), do: "h"
  defp serialize_impl(:variant), do: "v"

  defp serialize_impl({:array, elem_type}) do
    "a" <> serialize_impl(elem_type)
  end

  defp serialize_impl({:dict_entry, key_type, val_type}) do
    "{" <> serialize_impl(key_type) <> serialize_impl(val_type) <> "}"
  end

  defp serialize_impl({:struct, types}) do
    "(" <> Enum.map_join(types, &serialize_impl/1) <> ")"
  end

  @doc """
  Alignment requirement in bytes for a given type in the wire format.

  ## Examples

      iex> ExDBus.Wire.Types.alignment(:byte)
      1

      iex> ExDBus.Wire.Types.alignment(:int32)
      4

      iex> ExDBus.Wire.Types.alignment({:struct, [:int32, :string]})
      8

      iex> ExDBus.Wire.Types.alignment({:array, :int32})
      4
  """
  @spec alignment(dbus_type()) :: pos_integer()
  def alignment(:byte), do: 1
  def alignment(:boolean), do: 4
  def alignment(:int16), do: 2
  def alignment(:uint16), do: 2
  def alignment(:int32), do: 4
  def alignment(:uint32), do: 4
  def alignment(:int64), do: 8
  def alignment(:uint64), do: 8
  def alignment(:double), do: 8
  def alignment(:string), do: 4
  def alignment(:object_path), do: 4
  def alignment(:signature), do: 1
  def alignment(:unix_fd), do: 4
  def alignment(:variant), do: 1
  def alignment({:array, _elem_type}), do: 4
  def alignment({:struct, _types}), do: 8
  def alignment({:dict_entry, _key, _val}), do: 8

  @doc """
  Check if a value matches the expected type (basic validation).

  For container types (array, struct, variant), this does shallow validation only.
  Deep validation happens during encoding when each element is processed.

  ## Examples

      iex> ExDBus.Wire.Types.valid?(:int32, 42)
      true

      iex> ExDBus.Wire.Types.valid?(:string, "hello")
      true

      iex> ExDBus.Wire.Types.valid?(:int32, "not an int")
      false

      iex> ExDBus.Wire.Types.valid?({:array, :int32}, [1, 2, 3])
      true

      iex> ExDBus.Wire.Types.valid?(:variant, {"i", 42})
      true
  """
  @spec valid?(dbus_type(), term()) :: boolean()
  def valid?(:byte, v), do: is_integer(v) and v >= 0 and v <= 255
  def valid?(:boolean, v), do: is_boolean(v)
  def valid?(:int16, v), do: is_integer(v) and v >= -32_768 and v <= 32_767
  def valid?(:uint16, v), do: is_integer(v) and v >= 0 and v <= 65_535
  def valid?(:int32, v), do: is_integer(v) and v >= -2_147_483_648 and v <= 2_147_483_647
  def valid?(:uint32, v), do: is_integer(v) and v >= 0 and v <= 4_294_967_295

  def valid?(:int64, v),
    do: is_integer(v) and v >= -9_223_372_036_854_775_808 and v <= 9_223_372_036_854_775_807

  def valid?(:uint64, v), do: is_integer(v) and v >= 0 and v <= 18_446_744_073_709_551_615

  def valid?(:double, {:ieee754, bits}),
    do: valid?(:uint64, bits) and Bitwise.band(bits, 0x7FF0000000000000) == 0x7FF0000000000000

  def valid?(:double, v),
    do: is_float(v) or (is_integer(v) and v >= -2_147_483_648 and v <= 2_147_483_647)

  def valid?(:string, v),
    do: is_binary(v) and String.valid?(v) and :binary.match(v, <<0>>) == :nomatch

  def valid?(:object_path, v), do: is_binary(v) and valid_object_path?(v)
  def valid?(:signature, v), do: is_binary(v) and valid_signature?(v)
  def valid?(:unix_fd, v), do: valid?(:uint32, v)
  def valid?({:array, _elem_type}, v), do: is_list(v)
  def valid?({:struct, _types}, v), do: is_tuple(v)
  def valid?({:dict_entry, _key_type, _val_type}, v), do: is_tuple(v) and tuple_size(v) == 2
  def valid?(:variant, v), do: is_tuple(v) and tuple_size(v) == 2
  def valid?(_, _), do: false

  @doc """
  Parse a D-Bus signature string containing one or more complete types.

  Unlike `parse_signature/1` which expects exactly one type, this function
  parses signatures used for method argument lists (e.g., "sis" = [string, int32, string]).

  ## Examples

      iex> ExDBus.Wire.Types.parse_types("sis")
      {:ok, [:string, :int32, :string]}

      iex> ExDBus.Wire.Types.parse_types("i")
      {:ok, [:int32]}

      iex> ExDBus.Wire.Types.parse_types("")
      {:ok, []}

      iex> ExDBus.Wire.Types.parse_types("a{sv}i")
      {:ok, [{:array, {:dict_entry, :string, :variant}}, :int32]}
  """
  @spec parse_types(String.t()) :: {:ok, [dbus_type()]} | {:error, term()}
  def parse_types(sig) when byte_size(sig) > 255, do: {:error, :signature_too_long}

  def parse_types(""), do: {:ok, []}

  def parse_types(sig) when is_binary(sig) do
    case parse_types_impl(sig, []) do
      {:ok, types} -> {:ok, Enum.reverse(types)}
      error -> error
    end
  end

  defp parse_types_impl("", acc), do: {:ok, acc}

  defp parse_types_impl(sig, acc) do
    case parse_signature_impl(sig, {0, 0}, false) do
      {:ok, type, rest} -> parse_types_impl(rest, [type | acc])
      error -> error
    end
  end

  defp valid_signature?(v) do
    v == "" or match?({:ok, _}, parse_signature(v)) or match?({:ok, _}, parse_types(v))
  end

  defp valid_object_path?(path) do
    String.match?(path, ~r/\A\/(?:[a-zA-Z0-9_]+(?:\/[a-zA-Z0-9_]+)*)?\z/)
  end
end
