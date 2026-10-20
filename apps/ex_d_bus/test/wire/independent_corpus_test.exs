defmodule ExDBus.Wire.IndependentCorpusTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message
  alias ExDBus.Wire.{Decoder, Encoder}

  @external_resource Path.expand("../fixtures/glib_wire_corpus.txt", __DIR__)
  @frames @external_resource
          |> File.read!()
          |> String.split("\n", trim: true)
          |> Enum.reject(&String.starts_with?(&1, "#"))
          |> Enum.map(fn line ->
            [name, endian, hex] = String.split(line)

            {name, if(endian == "little", do: :little, else: :big),
             Base.decode16!(hex, case: :lower)}
          end)

  test "GLib frames decode the documented nested values and preserve exact body bytes" do
    for {name, endian, bytes} <- @frames do
      assert {:ok, message, <<0x42>>} = Message.decode_message(bytes <> <<0x42>>)
      assert message.type == :method_call
      assert message.serial == 42
      assert message.path == "/test"
      assert message.member == "Probe"
      assert message.interface == "org.foundation.Corpus"
      assert message.destination == "org.foundation.Corpus"
      assert message.sender == ":1.42"
      assert message.body == expected(name)
      assert message.unix_fds == if(name == "nested", do: 4, else: nil)
      reencoded = Message.encode_message(message, endian)
      assert {:ok, ^message, <<>>} = Message.decode_message(reencoded)
      # Header field order can differ legally; body bytes must match the oracle.
      assert body_bytes(reencoded, endian) == body_bytes(bytes, endian)
    end
  end

  test "every GLib frame split stays incomplete until the last byte arrives" do
    for {_name, _endian, bytes} <- @frames, split <- 0..(byte_size(bytes) - 1) do
      prefix = binary_part(bytes, 0, split)
      assert {:error, :insufficient_data} = Message.decode_message(prefix)

      assert {:ok, _, <<>>} =
               Message.decode_message(
                 prefix <> binary_part(bytes, split, byte_size(bytes) - split)
               )
    end
  end

  test "coalesced GLib frames leave each following frame exactly intact" do
    stream = Enum.map_join(@frames, fn {_, _, bytes} -> bytes end)

    assert <<>> ==
             Enum.reduce(@frames, stream, fn {_name, _endian, bytes}, stream ->
               assert {:ok, _, tail} = Message.decode_message(stream)

               assert tail ==
                        binary_part(
                          stream,
                          byte_size(bytes),
                          byte_size(stream) - byte_size(bytes)
                        )

               tail
             end)
  end

  test "empty eight-aligned arrays consume required padding even without an element" do
    for endian <- [:little, :big], offset <- 0..15 do
      prefix = :binary.copy(<<0>>, rem(4 - rem(offset, 4), 4)) <> <<0::32>>
      bytes = prefix <> :binary.copy(<<0>>, rem(8 - rem(offset + byte_size(prefix), 8), 8))

      assert {:ok, [], <<0x42>>, next} =
               Decoder.decode_at(bytes <> <<0x42>>, "at", endian, offset)

      assert next == offset + byte_size(bytes)
      assert {encoded, ^next} = Encoder.encode_at([], "at", endian, offset)
      assert IO.iodata_to_binary(encoded) == bytes
    end
  end

  test "exactly 64 dynamic variant containers are valid but 65 are terminal" do
    valid = :binary.copy(<<1, ?v, 0>>, 63) <> <<1, ?y, 0, 42>>
    assert {:ok, value, <<>>} = Decoder.decode(valid, :variant)
    assert IO.iodata_to_binary(Encoder.encode(value, :variant)) == valid
    assert {:error, :container_depth_exceeded} = Decoder.decode(<<1, ?v, 0>> <> valid, :variant)
  end

  defp expected("nested"),
    do: [
      [{"Enabled", {"b", true}}, {"Count", {"u", 42}}, {"Object", {"o", "/test"}}],
      [{-7, 0xFFFFFFFFFFFFFFFF}, {0, 1}],
      {"ay", [0, 127, 255]},
      [],
      [],
      "UTF-8: é \uFDD0 \uFFFE",
      "a{sv}",
      3,
      -0.0
    ]

  defp expected("nonfinite"),
    do:
      Enum.map(
        [0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000001, 0xFFF0000000000042],
        &{:ieee754, &1}
      )

  defp body_bytes(bytes, endian) do
    length =
      case {endian, bytes} do
        {:little, <<_::96, n::little-32, _::binary>>} -> n
        {:big, <<_::96, n::big-32, _::binary>>} -> n
      end

    offset = 16 + length + rem(8 - rem(16 + length, 8), 8)
    binary_part(bytes, offset, byte_size(bytes) - offset)
  end
end
