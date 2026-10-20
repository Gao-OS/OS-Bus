defmodule ExDBus.Wire.GeneratedCorpusTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias ExDBus.Wire.{Decoder, Encoder, Types}

  @seed {606, 20_261_009, 7301}
  @scalars [
    {:byte, 255},
    {:boolean, true},
    {:int16, -32768},
    {:uint16, 65535},
    {:int32, -2_147_483_648},
    {:uint32, 4_294_967_295},
    {:int64, -9_223_372_036_854_775_808},
    {:uint64, 18_446_744_073_709_551_615},
    {:double, 1.25},
    {:string, "é"},
    {:object_path, "/test_1"},
    {:signature, "a{sv}"},
    {:unix_fd, 0},
    {:double, {:ieee754, 0xFFF8000000000042}}
  ]

  test "seeded type trees preserve values, offsets and both-endian message bodies" do
    state = :rand.seed_s(:exsss, @seed)

    Enum.reduce(1..256, state, fn serial, state ->
      {type, value, state} = tree(state, 3)
      signature = Types.serialize_signature(type)
      assert {:ok, ^type} = Types.parse_signature(signature)

      for endian <- [:little, :big], offset <- 0..7 do
        {encoded, next} = Encoder.encode_at(value, type, endian, offset)
        bytes = IO.iodata_to_binary(encoded)

        assert {:ok, ^value, <<0x42>>, ^next} =
                 Decoder.decode_at(bytes <> <<0x42>>, type, endian, offset)

        assert next == offset + byte_size(bytes)
      end

      for endian <- [:little, :big] do
        message =
          Message.method_call("/test", "org.foundation.Generated", "Probe",
            serial: serial,
            signature: signature,
            body: [value]
          )

        bytes = Message.encode_message(message, endian)
        assert {:ok, ^message, <<>>} = Message.decode_message(bytes)

        for invalid <- [
              replace(bytes, 0, 255),
              replace(bytes, 3, 2),
              replace_range(bytes, 8, <<0::32>>),
              replace_range(bytes, 12, <<255, 255, 255, 255>>)
            ] do
          assert {:error, reason} = Message.decode_message(invalid)
          refute reason == :insufficient_data
        end
      end

      state
    end)
  end

  test "seeded arbitrary bounded binary inputs always return an explicit result without atom growth" do
    state = :rand.seed_s(:exsss, @seed)

    {inputs, _state} =
      Enum.map_reduce(1..512, state, fn _, state ->
        {length, state} = :rand.uniform_s(128, state)

        {bytes, state} =
          Enum.map_reduce(1..length, state, fn _, state ->
            {byte, state} = :rand.uniform_s(256, state)
            {byte - 1, state}
          end)

        {:erlang.list_to_binary(bytes), state}
      end)

    validate(inputs)
    atoms = :erlang.system_info(:atom_count)
    for _ <- 1..3, do: validate(inputs)
    assert :erlang.system_info(:atom_count) == atoms
  end

  defp validate(inputs) do
    Enum.each(inputs, fn bytes ->
      case Message.decode_message(bytes) do
        {:ok, %Message{}, rest} -> assert is_binary(rest)
        {:error, _reason} -> :ok
      end

      assert match?({:ok, _}, Types.parse_types(bytes)) or
               match?({:error, _}, Types.parse_types(bytes))
    end)
  end

  defp tree(state, depth) do
    choices = length(@scalars) + if(depth == 0, do: 0, else: 4)
    {choice, state} = :rand.uniform_s(choices, state)

    case choice - length(@scalars) do
      1 ->
        {type, value, state} = tree(state, depth - 1)
        {count, state} = :rand.uniform_s(4, state)
        {{:array, type}, List.duplicate(value, count - 1), state}

      2 ->
        {a, x, state} = tree(state, depth - 1)
        {b, y, state} = tree(state, depth - 1)
        {{:struct, [a, b]}, {x, y}, state}

      3 ->
        {type, value, state} = tree(state, depth - 1)
        {:variant, {Types.serialize_signature(type), value}, state}

      4 ->
        {type, value, state} = tree(state, depth - 1)
        {{:array, {:dict_entry, :string, type}}, [{"key", value}], state}

      _ ->
        {type, value} = Enum.at(@scalars, choice - 1)
        {type, value, state}
    end
  end

  defp replace(bytes, offset, value), do: replace_range(bytes, offset, <<value>>)

  defp replace_range(bytes, offset, replacement) do
    <<head::binary-size(offset), _::binary-size(byte_size(replacement)), tail::binary>> = bytes
    head <> replacement <> tail
  end
end
