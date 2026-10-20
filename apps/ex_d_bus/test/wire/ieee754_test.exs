defmodule ExDBus.Wire.IEEE754Test do
  use ExUnit.Case, async: true
  alias ExDBus.Wire.{Decoder, Encoder, Types}

  @nonfinite [0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000001, 0xFFF0000000000042]

  test "all nonfinite IEEE values preserve sign and NaN payload in both byte orders" do
    for bits <- @nonfinite, endian <- [:little, :big] do
      bytes = if endian == :little, do: <<bits::little-64>>, else: <<bits::big-64>>
      value = {:ieee754, bits}
      assert {:ok, ^value, <<0x42>>} = Decoder.decode(bytes <> <<0x42>>, :double, endian)
      assert Types.valid?(:double, value)
      assert IO.iodata_to_binary(Encoder.encode(value, :double, endian)) == bytes
    end
  end

  test "tagged values accept only valid unsigned nonfinite bit patterns" do
    for bits <- [-1, 0, 0x3FF0000000000000, 0x10000000000000000] do
      refute Types.valid?(:double, {:ieee754, bits})
      assert_raise ArgumentError, fn -> Encoder.encode({:ieee754, bits}, :double) end
    end
  end

  test "finite doubles remain floats including subnormal and signed zero" do
    for bits <- [0, 0x8000000000000000, 1, 0x7FEFFFFFFFFFFFFF], endian <- [:little, :big] do
      bytes = if endian == :little, do: <<bits::little-64>>, else: <<bits::big-64>>
      assert {:ok, value, <<>>} = Decoder.decode(bytes, :double, endian)
      assert is_float(value)
      assert IO.iodata_to_binary(Encoder.encode(value, :double, endian)) == bytes
    end
  end
end
