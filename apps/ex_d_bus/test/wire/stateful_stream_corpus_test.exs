defmodule ExDBus.Wire.StatefulStreamCorpusTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message

  @seed {607, 20_261_011, 7307}
  @cases 64

  test "seeded receives preserve exact frames and incomplete tails across stream transitions" do
    for case_id <- 1..@cases do
      {frames, random} = corpus(case_id)
      chunks = fragmented_and_coalesced(frames, random)
      complete = feed(chunks, state(frames), &Message.decode_message/1)
      assert complete.buffer == <<>>
      assert complete.pending == []
      assert complete.emitted == Enum.map(frames, & &1.message)

      # End a receive stream one byte short, then finish it with another frame.
      bytes = Enum.map_join(frames, & &1.bytes)
      <<truncated::binary-size(byte_size(bytes) - 1), last>> = bytes
      {chunks, _random} = split_random(truncated, random)
      incomplete = feed(chunks, state(frames), &Message.decode_message/1)
      final = List.last(frames)
      assert incomplete.buffer == binary_part(final.bytes, 0, byte_size(final.bytes) - 1)
      assert incomplete.pending == [final]
      assert incomplete.emitted == Enum.map(Enum.drop(frames, -1), & &1.message)

      sentinel = independent_frame(case_id + 100_000, :big, "s", "after-truncation")
      resumed = %{incomplete | pending: incomplete.pending ++ [sentinel]}
      completed = feed([<<last>> <> sentinel.bytes], resumed, &Message.decode_message/1)
      assert completed.buffer == <<>>
      assert completed.pending == []
      assert completed.emitted == Enum.map(frames ++ [sentinel], & &1.message)
    end
  end

  test "seeded corrupt tails and invalid prefixes remain terminal without resynchronizing" do
    for case_id <- 1..@cases do
      {frames, random} = corpus(case_id)
      good_chunks = fragmented_and_coalesced(frames, random)
      sentinel = independent_frame(case_id + 200_000, :little, "u", case_id)
      bad = independent_frame(case_id + 300_000, :big, "s", "corrupt-tail")
      <<header::binary-size(31), 0, body::binary>> = bad.bytes
      corrupt = header <> <<1>> <> body
      error = %{bytes: corrupt, ready: byte_size(corrupt), error: :nonzero_body_padding}
      <<partial::binary-size(byte_size(corrupt) - 1), last>> = corrupt

      healthy = feed(good_chunks, state(frames), &Message.decode_message/1)
      incomplete = feed([partial], %{healthy | pending: [error]}, &Message.decode_message/1)
      assert incomplete.buffer == partial
      assert incomplete.terminal == nil

      rejected =
        feed([<<last>> <> sentinel.bytes, sentinel.bytes], incomplete, &Message.decode_message/1)

      assert rejected.terminal == :nonzero_body_padding
      assert rejected.buffer == corrupt <> sentinel.bytes <> sentinel.bytes
      assert rejected.emitted == Enum.map(frames, & &1.message)

      # Even an invalid endian byte is incomplete until the fixed header arrives.
      stream = Enum.map_join(frames ++ [sentinel], & &1.bytes)
      <<first14::binary-size(14), rest::binary>> = stream
      {later, _random} = split_random(rest, random)
      prefix = %{bytes: <<255>>, ready: 16, error: {:invalid_endianness, 255}}
      pending = feed([<<255>>, first14], state([prefix]), &Message.decode_message/1)
      assert pending.buffer == <<255>> <> first14
      assert pending.terminal == nil
      rejected = feed(later ++ [sentinel.bytes], pending, &Message.decode_message/1)
      assert rejected.terminal == {:invalid_endianness, 255}
      assert rejected.emitted == []
      assert rejected.buffer == <<255>> <> stream <> sentinel.bytes
    end
  end

  test "stream oracle detects lost rest bytes, incomplete success and corruption resynchronization" do
    {frames, random} = corpus(1)
    chunks = fragmented_and_coalesced(frames, random)

    loses_rest = fn bytes ->
      case Message.decode_message(bytes) do
        {:ok, message, <<_lost, rest::binary>>} -> {:ok, message, rest}
        result -> result
      end
    end

    assert_raise ExUnit.AssertionError, fn -> feed(chunks, state(frames), loses_rest) end

    incomplete_success = fn bytes ->
      case Message.decode_message(bytes) do
        {:error, :insufficient_data} -> {:ok, hd(frames).message, <<>>}
        result -> result
      end
    end

    assert_raise ExUnit.AssertionError, fn -> feed(chunks, state(frames), incomplete_success) end

    resynchronizes = fn <<255, rest::binary>> -> Message.decode_message(rest) end
    stream = <<255>> <> Enum.map_join(frames, & &1.bytes)
    prefix = %{bytes: <<255>>, ready: 16, error: {:invalid_endianness, 255}}

    assert_raise ExUnit.AssertionError, fn -> feed([stream], state([prefix]), resynchronizes) end
  end

  defp corpus(case_id) do
    {a, b, c} = @seed
    random = :rand.seed_s(:exsss, {a, b, c + case_id})
    {count, random} = :rand.uniform_s(7, random)

    Enum.map_reduce(1..(count + 5), random, fn index, random ->
      {value, random} = :rand.uniform_s(4_294_967_296, random)
      {length, random} = :rand.uniform_s(48, random)
      endian = if rem(index + case_id, 2) == 0, do: :little, else: :big
      serial = case_id * 100 + index

      frame =
        if rem(index, 2) == 0 do
          independent_frame(serial, endian, "u", value - 1)
        else
          independent_frame(
            serial,
            endian,
            "s",
            "case#{case_id}:" <> String.duplicate("é", length)
          )
        end

      {frame, random}
    end)
  end

  # Independent D-Bus method-return layout: two 8-aligned header structs.
  # REPLY_SERIAL is (BYTE 5, VARIANT "u", UINT32); SIGNATURE is
  # (BYTE 8, VARIANT "g", SIGNATURE). The 15-byte array has one body pad byte.
  # No production encoder, signature parser or decoder constructs this oracle.
  defp independent_frame(serial, endian, signature, value) do
    body =
      case signature do
        "u" -> uint32(value, endian)
        "s" -> uint32(byte_size(value), endian) <> value <> <<0>>
      end

    marker = if endian == :little, do: ?l, else: ?B
    reply_serial = serial + 1_000
    <<type>> = signature

    bytes =
      <<marker, 2, 0, 1>> <>
        uint32(byte_size(body), endian) <>
        uint32(serial, endian) <>
        uint32(15, endian) <>
        <<5, 1, ?u, 0>> <>
        uint32(reply_serial, endian) <> <<8, 1, ?g, 0, 1, type, 0, 0>> <> body

    %{
      bytes: bytes,
      message: %Message{
        type: :method_return,
        serial: serial,
        reply_serial: reply_serial,
        signature: signature,
        body: [value]
      }
    }
  end

  defp uint32(value, :little), do: <<value::little-unsigned-32>>
  defp uint32(value, :big), do: <<value::big-unsigned-32>>

  defp fragmented_and_coalesced([first, second, third | rest], random) do
    <<a::binary-size(15), b, c::binary>> = first.bytes
    <<d::binary-size(3), e::binary>> = second.bytes
    {later, _random} = split_random(Enum.map_join(rest, & &1.bytes), random)
    [a, <<b>>, c <> d, e <> third.bytes | later]
  end

  defp split_random(<<>>, random), do: {[], random}

  defp split_random(bytes, random) do
    {size, random} = :rand.uniform_s(min(81, byte_size(bytes)), random)
    <<chunk::binary-size(size), rest::binary>> = bytes
    {chunks, random} = split_random(rest, random)
    {[chunk | chunks], random}
  end

  defp state(frames),
    do: %{
      buffer: <<>>,
      pending: frames,
      emitted: [],
      consumed: <<>>,
      received: <<>>,
      terminal: nil
    }

  defp feed(chunks, state, decode) do
    Enum.reduce(chunks, state, fn chunk, state ->
      state = %{state | buffer: state.buffer <> chunk, received: state.received <> chunk}
      state = drain(state, decode)
      assert state.received == state.consumed <> state.buffer
      state
    end)
  end

  defp drain(%{terminal: reason} = state, decode) when reason != nil do
    assert decode.(state.buffer) == {:error, reason}
    state
  end

  defp drain(%{pending: []} = state, decode) do
    assert state.buffer == <<>>
    assert decode.(state.buffer) == {:error, :insufficient_data}
    state
  end

  defp drain(%{pending: [next | rest]} = state, decode) do
    ready = Map.get(next, :ready, byte_size(next.bytes))

    if byte_size(state.buffer) < ready do
      assert decode.(state.buffer) == {:error, :insufficient_data}
      state
    else
      case next do
        %{error: reason} ->
          assert decode.(state.buffer) == {:error, reason}
          %{state | terminal: reason}

        %{bytes: bytes, message: message} ->
          <<head::binary-size(byte_size(bytes)), tail::binary>> = state.buffer
          assert head == bytes
          assert decode.(state.buffer) == {:ok, message, tail}

          drain(
            %{
              state
              | buffer: tail,
                pending: rest,
                emitted: state.emitted ++ [message],
                consumed: state.consumed <> bytes
            },
            decode
          )
      end
    end
  end
end
