defmodule ExDBus.Message do
  @moduledoc """
  D-Bus message struct and marshalling.

  A D-Bus message consists of a fixed header, header fields array, and body.

  ## Header format

      byte        endianness ('l' = little, 'B' = big)
      byte        message_type (1=method_call, 2=method_return, 3=error, 4=signal)
      byte        flags (0x1=no_reply_expected, 0x2=no_auto_start)
      byte        protocol_version (1)
      uint32      body_length
      uint32      serial
      array       header_fields (typed key-value pairs)
      padding     align to 8 bytes

  ## Header field codes

      1 = PATH         (object_path, required for method_call/signal)
      2 = INTERFACE    (string)
      3 = MEMBER       (string, required for method_call/signal)
      4 = ERROR_NAME   (string, required for error)
      5 = REPLY_SERIAL (uint32, required for method_return/error)
      6 = DESTINATION  (string)
      7 = SENDER       (string)
      8 = SIGNATURE    (signature, body type signature)
      9 = UNIX_FDS     (uint32)
  """

  alias ExDBus.Wire.{Decoder, Encoder, Types}

  @protocol_version 1

  # Message types
  @type_method_call 1
  @type_method_return 2
  @type_error 3
  @type_signal 4

  # Header field codes
  @field_path 1
  @field_interface 2
  @field_member 3
  @field_error_name 4
  @field_reply_serial 5
  @field_destination 6
  @field_sender 7
  @field_signature 8
  @field_unix_fds 9

  defstruct [
    :type,
    :serial,
    flags: 0,
    path: nil,
    interface: nil,
    member: nil,
    error_name: nil,
    reply_serial: nil,
    destination: nil,
    sender: nil,
    signature: nil,
    unix_fds: nil,
    fds: [],
    body: []
  ]

  @type message_type :: :method_call | :method_return | :error | :signal | {:unknown, byte()}
  @type t :: %__MODULE__{
          type: message_type(),
          serial: non_neg_integer(),
          flags: non_neg_integer(),
          path: String.t() | nil,
          interface: String.t() | nil,
          member: String.t() | nil,
          error_name: String.t() | nil,
          reply_serial: non_neg_integer() | nil,
          destination: String.t() | nil,
          sender: String.t() | nil,
          signature: String.t() | nil,
          unix_fds: non_neg_integer() | nil,
          fds: [non_neg_integer()],
          body: list()
        }

  @doc """
  Create a method_call message.
  """
  @spec method_call(String.t(), String.t() | nil, String.t(), keyword()) :: t()
  def method_call(path, interface, member, opts \\ []) do
    %__MODULE__{
      type: :method_call,
      serial: Keyword.get(opts, :serial, 0),
      flags: Keyword.get(opts, :flags, 0),
      path: path,
      interface: interface,
      member: member,
      destination: Keyword.get(opts, :destination),
      signature: Keyword.get(opts, :signature),
      body: Keyword.get(opts, :body, [])
    }
  end

  @doc """
  Create a method_return message.
  """
  @spec method_return(non_neg_integer(), keyword()) :: t()
  def method_return(reply_serial, opts \\ []) do
    %__MODULE__{
      type: :method_return,
      serial: Keyword.get(opts, :serial, 0),
      flags: Keyword.get(opts, :flags, 0),
      reply_serial: reply_serial,
      destination: Keyword.get(opts, :destination),
      sender: Keyword.get(opts, :sender),
      signature: Keyword.get(opts, :signature),
      body: Keyword.get(opts, :body, [])
    }
  end

  @doc """
  Create an error message.
  """
  @spec error(String.t(), non_neg_integer(), keyword()) :: t()
  def error(error_name, reply_serial, opts \\ []) do
    %__MODULE__{
      type: :error,
      serial: Keyword.get(opts, :serial, 0),
      flags: Keyword.get(opts, :flags, 0),
      error_name: error_name,
      reply_serial: reply_serial,
      destination: Keyword.get(opts, :destination),
      sender: Keyword.get(opts, :sender),
      signature: Keyword.get(opts, :signature),
      body: Keyword.get(opts, :body, [])
    }
  end

  @doc """
  Create a signal message.
  """
  @spec signal(String.t(), String.t(), String.t(), keyword()) :: t()
  def signal(path, interface, member, opts \\ []) do
    %__MODULE__{
      type: :signal,
      serial: Keyword.get(opts, :serial, 0),
      flags: Keyword.get(opts, :flags, 0),
      path: path,
      interface: interface,
      member: member,
      destination: Keyword.get(opts, :destination),
      signature: Keyword.get(opts, :signature),
      body: Keyword.get(opts, :body, [])
    }
  end

  @doc """
  Encode a message struct to D-Bus wire format binary.

  Returns iodata suitable for sending over a transport.
  """
  @spec encode_message(t(), ExDBus.Wire.Types.endianness()) :: binary()
  def encode_message(%__MODULE__{} = msg, endianness \\ :little) do
    validate_encoding!(msg)
    endian_byte = endianness_to_byte(endianness)
    type_byte = type_to_byte(msg.type)

    # Encode body first to know body_length (body is at offset 0 relative to body start)
    body_binary = encode_body(msg.body, msg.signature, endianness)
    body_length = byte_size(body_binary)

    # Fixed header: endianness(1) + type(1) + flags(1) + version(1) + body_len(4) + serial(4) = 12 bytes
    fixed_header = [
      <<endian_byte::8>>,
      <<type_byte::8>>,
      <<msg.flags::8>>,
      <<@protocol_version::8>>,
      encode_uint32(body_length, endianness),
      encode_uint32(msg.serial, endianness)
    ]

    # Encode header fields array at offset 12 (after fixed header)
    # This ensures alignment is calculated relative to message start
    fields = build_header_fields(msg)

    {fields_iodata, offset_after_fields} =
      Encoder.encode_at(fields, {:array, {:struct, [:byte, :variant]}}, endianness, 12)

    fields_binary = IO.iodata_to_binary(fields_iodata)

    # Align body to 8-byte boundary
    body_padding_len = rem(8 - rem(offset_after_fields, 8), 8)
    body_padding = <<0::size(body_padding_len)-unit(8)>>

    if 12 + byte_size(fields_binary) + body_padding_len + body_length > 134_217_728,
      do: raise(ArgumentError, "Message exceeds 128 MiB")

    IO.iodata_to_binary([fixed_header, fields_binary, body_padding, body_binary])
  end

  @doc """
  Decode a D-Bus message from binary data.

  Returns `{:ok, message, rest}` or `{:error, reason}`. Only
  `:insufficient_data` means the stream needs more bytes; all other errors
  are terminal. Well-formed extension message types are returned as
  `{:unknown, byte}` and must be ignored by the receiver.
  """
  @spec decode_message(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def decode_message(binary) when byte_size(binary) < 16 do
    {:error, :insufficient_data}
  end

  def decode_message(binary) do
    # Read first byte to determine endianness
    <<endian_byte::8, rest::binary>> = binary

    endianness =
      case endian_byte do
        ?l -> :little
        ?B -> :big
        _ -> :invalid
      end

    if endianness == :invalid do
      {:error, {:invalid_endianness, endian_byte}}
    else
      decode_message_with_endianness(rest, endianness)
    end
  end

  # --- Private encode helpers ---

  defp validate_encoding!(msg) do
    unless Types.valid?(:uint32, msg.serial) and msg.serial != 0 and
             Types.valid?(:byte, msg.flags),
           do: raise(ArgumentError, "Invalid message serial or flags")

    case validate_fields(build_header_fields(msg), msg.type) do
      {:ok, _fields} -> :ok
      {:error, reason} -> raise ArgumentError, "Invalid message headers: #{inspect(reason)}"
    end
  end

  defp encode_body([], nil, _endianness), do: <<>>

  defp encode_body(body, signature, endianness) when is_binary(signature) do
    types =
      case Types.parse_types(signature) do
        {:ok, types} -> types
        {:error, reason} -> raise ArgumentError, "Invalid body signature: #{inspect(reason)}"
      end

    unless is_list(body) and length(body) == length(types),
      do: raise(ArgumentError, "Body does not match signature arity")

    encode_body_values(body, types, endianness, 0)
    |> IO.iodata_to_binary()
  end

  defp encode_body(_body, nil, _endianness),
    do: raise(ArgumentError, "Nonempty body requires a signature")

  defp encode_body_values([], [], _endianness, _offset), do: []

  defp encode_body_values([value | values], [type | types], endianness, offset) do
    {encoded, new_offset} = Encoder.encode_at(value, type, endianness, offset)
    [encoded | encode_body_values(values, types, endianness, new_offset)]
  end

  defp build_header_fields(%__MODULE__{} = msg) do
    []
    |> maybe_add_field(msg.path, @field_path, "o")
    |> maybe_add_field(msg.interface, @field_interface, "s")
    |> maybe_add_field(msg.member, @field_member, "s")
    |> maybe_add_field(msg.error_name, @field_error_name, "s")
    |> maybe_add_field(msg.reply_serial, @field_reply_serial, "u")
    |> maybe_add_field(msg.destination, @field_destination, "s")
    |> maybe_add_field(msg.sender, @field_sender, "s")
    |> maybe_add_field(msg.signature, @field_signature, "g")
    |> maybe_add_field(msg.unix_fds, @field_unix_fds, "u")
    |> Enum.reverse()
  end

  defp maybe_add_field(acc, nil, _code, _sig), do: acc
  defp maybe_add_field(acc, value, code, sig), do: [{code, {sig, value}} | acc]

  # --- Private decode helpers ---

  defp decode_message_with_endianness(binary, endianness) do
    <<type_byte, flags, version, rest::binary>> = binary

    with true <- version == @protocol_version or {:error, {:invalid_protocol_version, version}},
         {:ok, msg_type} <- byte_to_type(type_byte),
         {:ok, body_length, rest} <- decode_raw_uint32(rest, endianness),
         {:ok, serial, rest} <- decode_raw_uint32(rest, endianness),
         true <- serial != 0 or {:error, :invalid_serial},
         {:ok, fields_length, rest} <- decode_raw_uint32(rest, endianness),
         {:ok, frame_length} <- validate_lengths(body_length, fields_length),
         true <- byte_size(binary) + 1 >= frame_length or {:error, :insufficient_data},
         <<fields::binary-size(fields_length), tail::binary>> <- rest,
         {:ok, fields_list, <<>>, _offset} <-
           Decoder.decode_at(
             encode_uint32(fields_length, endianness) <> fields,
             {:array, {:struct, [:byte, :variant]}},
             endianness,
             12
           ),
         {:ok, fields} <- validate_fields(fields_list, msg_type),
         padding = rem(8 - rem(16 + fields_length, 8), 8),
         <<pad::binary-size(padding), body::binary-size(body_length), rest::binary>> <- tail,
         true <- pad == :binary.copy(<<0>>, padding) or {:error, :nonzero_body_padding},
         {:ok, body} <- decode_body(body, Map.get(fields, @field_signature), endianness) do
      {:ok,
       %__MODULE__{
         type: msg_type,
         serial: serial,
         flags: flags,
         path: applicable_field(fields, @field_path, msg_type, [:method_call, :signal]),
         interface: applicable_field(fields, @field_interface, msg_type, [:method_call, :signal]),
         member: applicable_field(fields, @field_member, msg_type, [:method_call, :signal]),
         error_name: applicable_field(fields, @field_error_name, msg_type, [:error]),
         reply_serial:
           applicable_field(fields, @field_reply_serial, msg_type, [:method_return, :error]),
         destination: Map.get(fields, @field_destination),
         sender: Map.get(fields, @field_sender),
         signature: Map.get(fields, @field_signature),
         unix_fds: Map.get(fields, @field_unix_fds),
         body: body
       }, rest}
    else
      {:error, _} = error -> error
    end
  end

  @doc false
  def validate_lengths(body_length, fields_length) do
    header_length = 16 + fields_length
    frame_length = header_length + rem(8 - rem(header_length, 8), 8) + body_length

    cond do
      fields_length > 67_108_864 -> {:error, {:header_array_too_large, fields_length}}
      frame_length > 134_217_728 -> {:error, {:message_too_large, frame_length}}
      true -> {:ok, frame_length}
    end
  end

  @field_types %{
    1 => "o",
    2 => "s",
    3 => "s",
    4 => "s",
    5 => "u",
    6 => "s",
    7 => "s",
    8 => "g",
    9 => "u"
  }

  defp validate_fields(fields_list, type) do
    result =
      Enum.reduce_while(fields_list, {:ok, %{}, MapSet.new()}, fn {code, {sig, value}},
                                                                  {:ok, fields, seen} ->
        cond do
          code == 0 ->
            {:halt, {:error, :invalid_header_field}}

          MapSet.member?(seen, code) ->
            {:halt, {:error, {:duplicate_header_field, code}}}

          Map.has_key?(@field_types, code) and sig != Map.fetch!(@field_types, code) ->
            {:halt, {:error, {:invalid_header_field_type, code, sig}}}

          not valid_field_value?(code, value) ->
            {:halt, {:error, {:invalid_header_field_value, code}}}

          true ->
            fields =
              if Map.has_key?(@field_types, code), do: Map.put(fields, code, value), else: fields

            {:cont, {:ok, fields, MapSet.put(seen, code)}}
        end
      end)

    with {:ok, fields, _seen} <- result do
      required =
        case type do
          :method_call -> [@field_path, @field_member]
          :method_return -> [@field_reply_serial]
          :error -> [@field_error_name, @field_reply_serial]
          :signal -> [@field_path, @field_interface, @field_member]
          {:unknown, _byte} -> []
        end

      case Enum.find(required, &(not Map.has_key?(fields, &1))) do
        nil -> {:ok, fields}
        code -> {:error, {:missing_header_field, code}}
      end
    end
  end

  defp applicable_field(fields, code, type, types) do
    if type in types, do: Map.get(fields, code), else: nil
  end

  defp valid_field_value?(code, value) when code in [@field_interface, @field_error_name],
    do:
      byte_size(value) <= 255 and
        Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\z/, value)

  defp valid_field_value?(@field_member, value),
    do: byte_size(value) <= 255 and Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_]*\z/, value)

  defp valid_field_value?(code, value) when code in [@field_destination, @field_sender] do
    byte_size(value) <= 255 and
      if String.starts_with?(value, ":") do
        Regex.match?(~r/\A:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\z/, value)
      else
        Regex.match?(~r/\A[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)+\z/, value)
      end
  end

  defp valid_field_value?(@field_reply_serial, value), do: value != 0
  defp valid_field_value?(_code, _value), do: true

  defp decode_body(<<>>, nil, _endianness), do: {:ok, []}
  defp decode_body(_binary, nil, _endianness), do: {:error, :missing_body_signature}

  defp decode_body(binary, signature, endianness) do
    with {:ok, types} <- Types.parse_types(signature),
         {:ok, values, rest, _offset} <- decode_body_values(binary, types, endianness, 0) do
      if rest == <<>> do
        {:ok, values}
      else
        {:error, :trailing_body_bytes}
      end
    else
      {:error, reason} -> {:error, {:invalid_body, reason}}
    end
  end

  defp decode_body_values(binary, [], _endianness, offset), do: {:ok, [], binary, offset}

  defp decode_body_values(binary, [type | types], endianness, offset) do
    case Decoder.decode_at(binary, type, endianness, offset) do
      {:ok, value, rest, new_offset} ->
        case decode_body_values(rest, types, endianness, new_offset) do
          {:ok, values, rest2, final_offset} ->
            {:ok, [value | values], rest2, final_offset}

          error ->
            error
        end

      error ->
        error
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

  defp endianness_to_byte(:little), do: ?l
  defp endianness_to_byte(:big), do: ?B

  defp type_to_byte(:method_call), do: @type_method_call
  defp type_to_byte(:method_return), do: @type_method_return
  defp type_to_byte(:error), do: @type_error
  defp type_to_byte(:signal), do: @type_signal

  defp byte_to_type(@type_method_call), do: {:ok, :method_call}
  defp byte_to_type(@type_method_return), do: {:ok, :method_return}
  defp byte_to_type(@type_error), do: {:ok, :error}
  defp byte_to_type(@type_signal), do: {:ok, :signal}
  defp byte_to_type(0), do: {:error, {:invalid_message_type, 0}}
  defp byte_to_type(byte), do: {:ok, {:unknown, byte}}

  defp encode_uint32(value, :little), do: <<value::unsigned-integer-size(32)-little>>
  defp encode_uint32(value, :big), do: <<value::unsigned-integer-size(32)-big>>
end
