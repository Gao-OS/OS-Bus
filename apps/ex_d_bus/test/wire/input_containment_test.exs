defmodule ExDBus.Wire.InputContainmentTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message
  alias ExDBus.Wire.{Decoder, Types}

  # Independent ingress bytes: these fixtures never call the production encoder.
  defp uint32(n, :little), do: <<n::little-unsigned-32>>
  defp uint32(n, :big), do: <<n::big-unsigned-32>>

  defp padding(offset, alignment),
    do: :binary.copy(<<0>>, rem(alignment - rem(offset, alignment), alignment))

  defp string(value, endian), do: uint32(byte_size(value), endian) <> value <> <<0>>
  defp signature(value), do: <<byte_size(value)>> <> value <> <<0>>

  defp field_bytes(fields, endian) do
    Enum.reduce(fields, <<>>, fn {code, sig, value}, acc ->
      start = acc <> padding(16 + byte_size(acc), 8)
      prefix = start <> <<code>> <> signature(sig)

      encoded =
        case sig do
          "g" -> signature(value)
          "y" -> <<value>>
          "u" -> uint32(value, endian)
          "s" -> string(value, endian)
          "o" -> string(value, endian)
        end

      prefix <> encoded
    end)
  end

  defp frame(fields, body \\ <<>>, opts \\ []) do
    endian = Keyword.get(opts, :endian, :little)
    fields = field_bytes(fields, endian)
    endian_byte = if endian == :little, do: ?l, else: ?B

    <<endian_byte, Keyword.get(opts, :type, 1), Keyword.get(opts, :flags, 0),
      Keyword.get(opts, :version, 1)>> <>
      uint32(Keyword.get(opts, :body_length, byte_size(body)), endian) <>
      uint32(Keyword.get(opts, :serial, 1), endian) <>
      uint32(Keyword.get(opts, :fields_length, byte_size(fields)), endian) <>
      fields <> padding(16 + byte_size(fields), 8) <> body
  end

  defp call_fields, do: [{1, "o", "/test"}, {3, "s", "Ping"}]

  defp terminal(binary) do
    assert {:error, reason} = Message.decode_message(binary)
    refute reason == :insufficient_data
  end

  test "independent little and big endian call fixtures consume exactly one frame" do
    for endian <- [:little, :big] do
      bytes = frame(call_fields() ++ [{8, "g", "u"}], uint32(42, endian), endian: endian)

      assert {:ok, %Message{type: :method_call, body: [42]}, ^bytes} =
               Message.decode_message(bytes <> bytes)
    end
  end

  test "protocol versions other than one are terminal" do
    terminal(frame(call_fields(), <<>>, version: 2))
  end

  test "zero serial is terminal" do
    terminal(frame(call_fields(), <<>>, serial: 0))
  end

  test "message type zero is invalid" do
    terminal(frame(call_fields(), <<>>, type: 0))
  end

  test "unknown message types remain well formed forward-compatible input" do
    bytes = frame([{8, "g", "u"}], uint32(42, :little), type: 42, flags: 128)

    assert {:ok, %Message{type: {:unknown, 42}, body: [42], flags: 128}, <<>>} =
             Message.decode_message(bytes)
  end

  test "unknown type does not bypass body validation" do
    terminal(frame([{8, "g", "b"}], uint32(2, :little), type: 42))
  end

  test "each known message type requires its mandatory fields" do
    for {type, required} <- [
          {1, [{1, "o", "/test"}, {3, "s", "Ping"}]},
          {2, [{5, "u", 1}]},
          {3, [{4, "s", "org.test.Error"}, {5, "u", 1}]},
          {4, [{1, "o", "/test"}, {2, "s", "org.test.Interface"}, {3, "s", "Ping"}]}
        ],
        missing <- required do
      terminal(frame(List.delete(required, missing), <<>>, type: type))
    end
  end

  test "known header field types are checked even in unexpected messages" do
    terminal(frame([{1, "s", "/test"}, {3, "s", "Ping"}]))
    terminal(frame([{5, "s", "1"}], <<>>, type: 2))
    terminal(frame(call_fields() ++ [{4, "u", 1}]))
  end

  test "duplicate header fields are terminal" do
    terminal(frame(call_fields() ++ [{3, "s", "Pong"}]))
  end

  test "header field zero is invalid" do
    terminal(frame(call_fields() ++ [{0, "y", 1}]))
  end

  test "valid unknown headers are ignored" do
    assert {:ok, %Message{member: "Ping"}, <<>>} =
             Message.decode_message(frame(call_fields() ++ [{42, "s", "extension"}]))
  end

  test "valid unexpected known headers are ignored" do
    fields = call_fields() ++ [{2, "s", "org.test.Interface"}, {5, "u", 1}]

    assert {:ok, %Message{type: :signal, reply_serial: nil}, <<>>} =
             Message.decode_message(frame(fields, <<>>, type: 4))
  end

  test "reply INTERFACE strings are ignored in both byte orders" do
    for endian <- [:little, :big],
        {type, kind, error_name, required} <- [
          {2, :method_return, nil, [{5, "u", 7}]},
          {3, :error, "org.test.Error", [{4, "s", "org.test.Error"}, {5, "u", 7}]}
        ],
        interface <- [nil, "org.foundation.Blocked", "org.foundation.Accepted"] do
      fields = if interface == nil, do: required, else: required ++ [{2, "s", interface}]

      assert {:ok, message, <<>>} =
               Message.decode_message(frame(fields, <<>>, type: type, endian: endian, serial: 11))

      assert %Message{
               type: ^kind,
               interface: nil,
               error_name: ^error_name,
               reply_serial: 7,
               serial: 11
             } = message
    end
  end

  test "reply INTERFACE with the wrong wire type remains terminal in both byte orders" do
    for endian <- [:little, :big],
        {type, required} <- [
          {2, [{5, "u", 7}]},
          {3, [{4, "s", "org.test.Error"}, {5, "u", 7}]}
        ] do
      assert {:error, {:invalid_header_field_type, 2, "u"}} =
               Message.decode_message(
                 frame(required ++ [{2, "u", 42}], <<>>, type: type, endian: endian)
               )
    end
  end

  test "call and signal INTERFACE strings are retained in both byte orders" do
    for endian <- [:little, :big], {type, kind} <- [{1, :method_call}, {4, :signal}] do
      fields = call_fields() ++ [{2, "s", "org.test.Interface"}]

      assert {:ok, message, <<>>} =
               Message.decode_message(frame(fields, <<>>, type: type, endian: endian))

      assert %Message{
               type: ^kind,
               path: "/test",
               interface: "org.test.Interface",
               member: "Ping"
             } = message
    end
  end

  test "unknown headers still require valid variant values" do
    terminal(frame(call_fields() ++ [{42, "s", <<255>>}]))
  end

  test "nonzero body requires a nonempty signature" do
    terminal(frame(call_fields(), <<42>>))
    terminal(frame(call_fields() ++ [{8, "g", ""}], <<42>>))
  end

  test "complete body decode errors are terminal instead of empty-body success" do
    terminal(frame(call_fields() ++ [{8, "g", "b"}], uint32(2, :little)))
    terminal(frame(call_fields() ++ [{8, "g", "u"}], <<42>>))
  end

  test "body signature must consume every advertised body byte" do
    terminal(frame(call_fields() ++ [{8, "g", "u"}], uint32(42, :little) <> <<0>>))
    terminal(frame(call_fields() ++ [{8, "g", "u"}]))
  end

  test "truncation is incomplete until the advertised frame arrives" do
    bytes = frame(call_fields() ++ [{8, "g", "u"}], uint32(42, :little))

    for size <- 0..(byte_size(bytes) - 1) do
      assert {:error, :insufficient_data} = Message.decode_message(binary_part(bytes, 0, size))
    end
  end

  test "advertised protocol lengths are bounded before payload allocation" do
    terminal(frame([], <<>>, body_length: 134_217_729))
    terminal(frame([], <<>>, fields_length: 67_108_865))
  end

  test "header array elements cannot cross the declared array boundary" do
    bytes = frame(call_fields())
    <<prefix::binary-size(12), length::little-32, rest::binary>> = bytes
    terminal(prefix <> <<length - 1::little-32>> <> rest)
  end

  test "header-to-body padding must be zero" do
    bytes = frame(call_fields())
    <<_prefix::binary-size(12), length::little-32, _::binary>> = bytes
    pad_at = 16 + length
    assert pad_at < byte_size(bytes)
    <<head::binary-size(pad_at), _old, tail::binary>> = bytes
    terminal(head <> <<1>> <> tail)
  end

  test "invalid body signatures return errors instead of raising" do
    terminal(frame(call_fields() ++ [{8, "g", "z"}], <<42>>))
    terminal(frame(call_fields() ++ [{8, "g", "()"}], <<>>))
  end

  test "string-like values require valid text, nul termination, and grammar" do
    for value <- [<<255>>, "a\0b"] do
      assert {:error, _} = Decoder.decode(string(value, :little), :string)
    end

    assert {:error, _} = Decoder.decode(<<1::little-32, "a", 1>>, :string)

    for path <- ["/test/", "//test", "relative", "/dash-name"] do
      assert {:error, _} = Decoder.decode(string(path, :little), :object_path)
    end

    assert {:error, _} = Decoder.decode(signature("z"), :signature)
  end

  test "invalid header names are terminal" do
    for field <- [
          {2, "s", "org.1test.Interface"},
          {3, "s", "bad.member"},
          {6, "s", "org..test"},
          {7, "s", "bad"}
        ] do
      fields =
        if elem(field, 0) == 3, do: [{1, "o", "/test"}, field], else: call_fields() ++ [field]

      terminal(frame(fields))
    end
  end

  test "body alignment padding must be zero" do
    assert {:error, _} =
             Decoder.decode(<<1, 1, 0, 0, 42::little-32>>, {:struct, [:byte, :uint32]})

    assert {:error, _} = Decoder.decode_at(<<1, 0, 0, 42::little-32>>, :uint32, :little, 1)
  end

  test "array element cannot consume bytes after the advertised array" do
    assert {:error, _} = Decoder.decode(<<1::little-32, 42::little-32>>, {:array, :uint32})
  end

  test "array length limits are terminal without the advertised payload" do
    assert {:error, {:array_too_large, 67_108_865}} =
             Decoder.decode(<<67_108_865::little-32>>, {:array, :byte})
  end

  test "empty struct array input cannot create a zero-progress loop" do
    assert {:error, _} = Types.parse_types("a()")
    assert {:error, _} = Decoder.decode(<<1::little-32, 0::little-32, 1>>, "a()")
  end

  test "signature grammar rejects dict entries outside arrays and container keys" do
    for sig <- ["{sv}", "({sv})", "a{vs}", "a{(i)s}", "a{ssu}", "()"] do
      assert {:error, _} = Types.parse_types(sig)
    end

    assert {:ok, _} = Types.parse_types("a{sv}")
  end

  test "signature length and separate array/struct depth limits are enforced" do
    for sig <- [
          String.duplicate("y", 256),
          String.duplicate("a", 33) <> "y",
          String.duplicate("(", 33) <> "y" <> String.duplicate(")", 33)
        ] do
      assert {:error, _} = Types.parse_types(sig)
    end

    assert {:ok, _} = Types.parse_types(String.duplicate("a", 32) <> "y")

    assert {:ok, _} =
             Types.parse_types(String.duplicate("(", 32) <> "y" <> String.duplicate(")", 32))
  end

  test "variant nesting is bounded across dynamically provided signatures" do
    bytes = :binary.copy(signature("v"), 65) <> signature("y") <> <<1>>
    assert {:error, :container_depth_exceeded} = Decoder.decode(bytes, :variant)
  end
end
