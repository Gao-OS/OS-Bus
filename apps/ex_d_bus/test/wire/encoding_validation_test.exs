defmodule ExDBus.Wire.EncodingValidationTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message
  alias ExDBus.Wire.{Encoder, Types}

  test "FD indexes are uint32 values and cannot truncate" do
    assert Types.valid?(:unix_fd, 0xFFFFFFFF)
    refute Types.valid?(:unix_fd, 0x100000000)
    assert_raise ArgumentError, fn -> Encoder.encode(0x100000000, :unix_fd) end
  end

  test "AST types obey the same grammar and static nesting limits as signatures" do
    array = Enum.reduce(1..33, :byte, fn _, type -> {:array, type} end)

    for {value, type} <- [
          {{}, {:struct, []}},
          {[{{"s", "key"}, 1}], {:array, {:dict_entry, :variant, :uint32}}},
          {[], array}
        ] do
      assert_raise ArgumentError, fn -> Encoder.encode(value, type) end
    end
  end

  test "variant nesting cannot exceed 64 even with individually valid signatures" do
    value = Enum.reduce(1..64, {"y", 1}, fn _, value -> {"v", value} end)
    assert_raise ArgumentError, fn -> Encoder.encode(value, :variant) end
  end

  test "invalid variant signatures and mismatched structs report argument errors" do
    for {value, type} <- [
          {{"", 1}, :variant},
          {{"uu", 1}, :variant},
          {{1}, {:struct, [:uint32, :uint32]}},
          {{1, 2}, {:struct, [:uint32]}}
        ] do
      assert_raise ArgumentError, fn -> Encoder.encode(value, type) end
    end
  end

  test "message encoding never silently discards or omits declared body arguments" do
    for {signature, body} <- [{nil, [1]}, {"u", []}, {"uu", [1]}, {"u", [1, 2]}, {"", [1]}] do
      message =
        Message.method_call("/test", nil, "Probe", serial: 1, signature: signature, body: body)

      assert_raise ArgumentError, fn -> Message.encode_message(message) end
    end
  end

  test "outbound message metadata is validated before it reaches the wire" do
    message = Message.method_call("/test", nil, "Probe", serial: 1)

    for invalid <- [
          %{message | serial: 0},
          %{message | serial: 0x100000000},
          %{message | flags: 256},
          %{message | member: "bad.member"},
          %{message | path: "relative"},
          %{message | destination: "org..test"}
        ] do
      assert_raise ArgumentError, fn -> Message.encode_message(invalid) end
    end
  end
end
