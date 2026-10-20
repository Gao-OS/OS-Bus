defmodule GaoBus.PeerFrameLengthUnitTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, Peer}

  for {endian, valid_prefix, invalid_prefix} <- [
        {:little, <<?l, 1, 0, 1, 0::little-32, 3::little-32, 67_108_864::little-32>>,
         <<?l, 1, 0, 1, 0::little-32, 3::little-32, 67_108_865::little-32>>},
        {:big, <<?B, 1, 0, 1, 0::big-32, 3::big-32, 67_108_864::big-32>>,
         <<?B, 1, 0, 1, 0::big-32, 3::big-32, 67_108_865::big-32>>}
      ] do
    test "#{endian} fixed prefix rejects an oversized header array before collecting it" do
      xml = %{"max_message_size" => 67_108_888}
      start_supervised!({Limits, xml_limits: xml})
      assert {:ok, initial} = Peer.init(socket: :unused, xml_limits: xml)

      try do
        # Unit-fixture identity and callback state do not prove authentication or kernel credentials.
        credentials = %{uid: 1000, gid: 1000, pid: 123}
        assert :ok = Limits.acquire(self(), credentials)
        assert :ok = Limits.auth_completed(self())
        assert :ok = Limits.hello_completed(self())
        assert :ok = Limits.set_frame(self(), 16, 0)
        assert {:ok, accounting} = Limits.snapshot()

        valid_prefix = unquote(valid_prefix)
        invalid_prefix = unquote(invalid_prefix)

        state = %{
          initial
          | state: :connected,
            credentials: credentials,
            buffer: valid_prefix,
            messages_continuing: true,
            read_scheduled: true
        }

        # A scheduled-read fixture guard keeps the actual framing callback socket-free.
        assert {:noreply, held} = Peer.handle_info(:continue_messages, state)
        assert held.buffer == valid_prefix
        assert held.read_scheduled
        assert {:ok, ^accounting} = Limits.snapshot()

        invalid = %{held | buffer: invalid_prefix, messages_continuing: true}
        result = Peer.handle_info(:continue_messages, invalid)
        assert {:ok, ^accounting} = Limits.snapshot()
        assert {:stop, :normal, stopped} = result
        assert stopped.buffer == invalid_prefix
      after
        Process.cancel_timer(elem(initial.registration_timer, 0))
        assert :ok = Limits.release_peer(self())
      end
    end
  end
end
