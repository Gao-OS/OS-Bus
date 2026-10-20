defmodule GaoBus.Peer do
  @moduledoc """
  Owns one accepted Unix connection, verifies kernel credentials, authenticates
  EXTERNAL, and routes messages only after an explicit Hello registration.

  Authentication and FD-negotiated reads stop at their boundaries so ancillary
  resources belong to exactly one frame. FD-free reads may retain successors
  within bounded frame credits. Credits precede reads and queued deliveries.
  Each output has independently owned descriptors and a bounded continuation.
  """

  use GenServer, restart: :temporary

  alias ExDBus.Message
  alias GaoBus.Auth
  alias GaoBus.Policy.Capability
  alias GaoBus.Unix.{Credentials, Descriptors, Resources, Writer}

  require Logger

  @auth_guid Application.compile_env(:gao_bus, :auth_guid, nil)
  @counter_key :gao_bus_peer_counter
  @recv_bytes 65_536
  @max_buffer_bytes 1_048_576
  @max_output_bytes 65_536
  @frames_per_turn 32

  defstruct [
    :socket,
    :native_socket,
    :unique_name,
    :credentials,
    :auth,
    :auth_timer,
    :registration_timer,
    :frame_timer,
    :frame_deadline,
    :frame_options,
    :pending_fd_timer,
    :pending_fd_deadline,
    :hello_serial,
    :xml_limits,
    :hello_deadline,
    :admission_observer,
    :recv_select,
    :route_wait,
    :write_timer,
    :current_output,
    incoming_fds: [],
    output_queue: {[], []},
    auth_limits: [],
    state: :waiting_socket,
    buffer: <<>>,
    ingress_paused: false,
    read_scheduled: false,
    auth_continuing: false,
    messages_continuing: false,
    frame_timeout_ms: 5000
  ]

  @spec ensure_counter() :: :ok
  def ensure_counter do
    unless :persistent_term.get(@counter_key, nil) do
      ref = :atomics.new(1, signed: false)
      :persistent_term.put(@counter_key, ref)
    end

    :ok
  end

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "Returns nil before Hello has assigned a unique name."
  @spec get_unique_name(pid()) :: String.t() | nil
  def get_unique_name(pid), do: GenServer.call(pid, :get_unique_name)

  @doc "Returns the verified socket identity, or nil before successful authentication."
  @spec get_credentials(pid()) :: map() | nil
  def get_credentials(pid), do: GenServer.call(pid, :get_credentials)

  @doc "Assigns the unique name during the accepted Hello authority transition."
  @spec assign_unique_name(pid()) :: String.t() | {:error, term()}
  def assign_unique_name(pid), do: GenServer.call(pid, :assign_unique_name)

  @impl true
  def init(opts) do
    raw_xml = Keyword.get(opts, :xml_limits)

    timeout =
      Keyword.get(
        opts,
        :frame_timeout_ms,
        if(raw_xml, do: nil, else: Application.get_env(:gao_bus, :frame_timeout_ms, 5000))
      )

    with true <-
           (is_integer(timeout) and timeout in 1..60_000) or (is_map(raw_xml) and is_nil(timeout)),
         {:ok, frame_options} <- frame_options(raw_xml),
         {:ok, xml_limits} <- GaoBus.Limits.connection_limits(raw_xml) do
      accepted_at = Keyword.get(opts, :accepted_at, now_ms())
      deadline = if xml_limits, do: accepted_at + xml_limits["auth_timeout"]

      timer =
        if deadline do
          token = make_ref()

          ref =
            Process.send_after(self(), {:registration_expiry, token}, max(deadline - now_ms(), 0))

          {ref, token}
        end

      {:ok,
       %__MODULE__{
         socket: Keyword.fetch!(opts, :socket),
         xml_limits: xml_limits,
         frame_options: frame_options,
         hello_deadline: deadline,
         registration_timer: timer,
         admission_observer: Keyword.get(opts, :admission_observer),
         frame_timeout_ms: timeout,
         auth_limits:
           Keyword.get(opts, :auth_limits, Application.get_env(:gao_bus, :auth_limits, []))
       }}
    else
      false -> {:stop, :invalid_frame_timeout}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_info(:socket_ready, %{state: :waiting_socket} = state) do
    with :ok <- hello_not_expired(state),
         {:ok, credentials} <- Credentials.read(state.socket),
         {:allow, _generation} <- GaoBus.Policy.authorize(:connect, %{credentials: credentials}),
         :ok <- GaoBus.Limits.acquire(self(), credentials),
         {:ok, auth} <-
           Auth.new(
             credentials,
             auth_guid(),
             now_ms(),
             authentication_options(state)
           ),
         {:ok, native_socket} <- Resources.capture(state.socket) do
      if state.admission_observer, do: send(state.admission_observer, {:peer_admitted, self()})

      state =
        schedule_auth_timer(%{
          state
          | state: :authenticating,
            auth: auth,
            native_socket: native_socket
        })

      read_socket(state)
    else
      {:error, reason} -> stop_peer(state, reason)
      {:deny, reason} -> stop_peer(state, {:admission_denied, reason})
    end
  end

  def handle_info({:route_complete, token}, %{route_wait: token} = state)
      when is_reference(token) do
    process_messages(%{state | route_wait: nil}, @frames_per_turn)
  end

  def handle_info(:read_socket, %{read_scheduled: true} = state) do
    read_socket(%{state | read_scheduled: false})
  end

  def handle_info(:ingress_capacity, %{ingress_paused: true, state: phase} = state)
      when phase in [:awaiting_hello, :connected] do
    process_messages(%{state | ingress_paused: false}, @frames_per_turn)
  end

  def handle_info({:"$socket", socket, :select, reference}, state)
      when socket == state.socket and reference == state.recv_select do
    read_socket(%{state | recv_select: nil})
  end

  def handle_info({:"$socket", socket, :abort, {reference, reason}}, state)
      when socket == state.socket and reference == state.recv_select do
    stop_peer(%{state | recv_select: nil}, reason)
  end

  def handle_info(:continue_auth, %{state: :authenticating, auth_continuing: true} = state) do
    authenticate(%{state | auth_continuing: false}, <<>>)
  end

  def handle_info(:continue_messages, %{messages_continuing: true} = state) do
    process_messages(%{state | messages_continuing: false}, @frames_per_turn)
  end

  def handle_info(
        {:auth_expiry, token},
        %{state: :authenticating, auth_timer: {_ref, token}} = state
      ) do
    case Auth.expire(state.auth, now_ms()) do
      {:ok, auth} -> {:noreply, schedule_auth_timer(%{state | auth: auth})}
      {:error, reason, auth} -> stop_peer(%{state | auth: auth}, reason)
    end
  end

  def handle_info({:registration_expiry, token}, %{registration_timer: {_ref, token}} = state),
    do: stop_peer(state, :hello_timeout)

  def handle_info({:frame_expiry, token}, %{frame_timer: {_ref, token}} = state),
    do: stop_peer(state, :frame_timeout)

  def handle_info({:pending_fd_expiry, token}, %{pending_fd_timer: {_ref, token}} = state),
    do: stop_peer(state, :pending_fd_timeout)

  def handle_info({:send_message, msg, {token, queued_at}}, %{state: phase} = state)
      when phase in [:registering, :connected] do
    case new_output(state, msg, token, queued_at) do
      {:ok, output} ->
        queue = :queue.in(output, state.output_queue)
        continue_write(%{state | output_queue: queue})

      {:error, reason} ->
        release_output(%{message: msg, token: token})
        stop_peer(state, reason)
    end
  end

  def handle_info({:send_message, msg, {token, _queued_at}}, state) do
    release_output(%{message: msg, token: token})
    {:noreply, state}
  end

  def handle_info({:write_tick, token}, %{write_timer: {_ref, token}} = state),
    do: continue_write(%{state | write_timer: nil})

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def handle_call(:get_unique_name, _from, state), do: {:reply, state.unique_name, state}
  def handle_call(:get_credentials, _from, state), do: {:reply, state.credentials, state}

  def handle_call(:assign_unique_name, _from, %{unique_name: name} = state) when is_binary(name),
    do: {:reply, name, state}

  def handle_call(:assign_unique_name, _from, %{state: :registering, credentials: creds} = state)
      when is_map(creds) do
    with :ok <- hello_not_expired(state),
         :ok <- GaoBus.Limits.hello_completed(self(), GaoBus.Limits, state.hello_deadline) do
      name = ":1.#{next_peer_id()}"
      credentials = Map.put(creds, :unique_name, name)
      GaoBus.PubSub.broadcast({:peer_connected, name, self()})

      if Process.whereis(Capability) do
        Capability.setup_defaults(name, credentials)
      end

      # Hello has committed. A stale timer must not undo completed admission.
      cancel_timer(state.registration_timer)

      {:reply, name,
       %{
         state
         | unique_name: name,
           credentials: credentials,
           registration_timer: nil,
           hello_deadline: nil
       }}
    else
      {:error, :hello_timeout} = error -> {:stop, :normal, error, state}
      error -> {:reply, error, state}
    end
  end

  def handle_call(:assign_unique_name, _from, state),
    do: {:stop, :normal, {:error, :hello_required}, state}

  @impl true
  def terminate(_reason, state) do
    cancel_timer(state.auth_timer)
    cancel_timer(state.registration_timer)
    cancel_timer(state.frame_timer)
    cancel_timer(state.pending_fd_timer)
    cancel_timer(state.write_timer)
    close_resources(state.incoming_fds)
    if state.current_output, do: release_output(state.current_output)
    for output <- :queue.to_list(state.output_queue), do: release_output(output)
    if state.native_socket, do: close_resources([state.native_socket])
    safely(fn -> :socket.close(state.socket) end)

    if state.unique_name do
      GaoBus.PubSub.broadcast({:peer_disconnected, state.unique_name, self()})
    end

    :ok
  end

  defp read_socket(%{route_wait: token} = state) when not is_nil(token),
    do: {:noreply, state}

  defp read_socket(%{state: phase} = state)
       when phase in [:authenticating, :awaiting_hello, :connected] do
    with :ok <- hello_not_expired(state),
         :ok <- frame_not_expired(state),
         :ok <- pending_fd_not_expired(state),
         :ok <- input_ready(state),
         {:ok, bytes} <- read_budget(state),
         fd_limit = state.frame_options.max_fds,
         {:ok, bytes} <- reserve_read(state, bytes, fd_limit) do
      state = %{state | ingress_paused: false}

      case Resources.recv(state.native_socket, bytes, fd_limit - length(state.incoming_fds)) do
        {:ok, _data, resources} when phase == :authenticating and resources != [] ->
          close_resources(resources)
          stop_peer(state, :resource_bearing_authentication)

        {:ok, _data, resources} when resources != [] and not state.auth.unix_fd_negotiated ->
          close_resources(resources)
          stop_peer(state, :invalid_unix_fds)

        {:ok, data, resources} ->
          state = track_pending_fds(%{state | incoming_fds: state.incoming_fds ++ resources})

          buffered =
            if phase == :authenticating, do: 0, else: byte_size(state.buffer) + byte_size(data)

          case GaoBus.Limits.set_frame(self(), buffered, length(state.incoming_fds)) do
            :ok -> handle_data(state, data)
            {:error, reason} -> stop_peer(state, reason)
          end

        {:error, :eagain} ->
          case GaoBus.Limits.set_frame(
                 self(),
                 byte_size(state.buffer),
                 length(state.incoming_fds)
               ) do
            :ok -> arm_read(state)
            {:error, reason} -> stop_peer(state, reason)
          end

        {:error, reason} ->
          stop_peer(state, reason)
      end
    else
      {:error, {:xml_limit_exceeded, _name}} -> {:noreply, %{state | ingress_paused: true}}
      {:error, reason} -> stop_peer(state, reason)
    end
  end

  defp read_socket(state), do: {:noreply, state}
  defp handle_data(%{state: :authenticating} = state, data), do: authenticate(state, data)

  defp handle_data(state, data) do
    if byte_size(state.buffer) + byte_size(data) > state.frame_options.max_bytes do
      stop_peer(state, :input_buffer_exceeded)
    else
      process_messages(%{state | buffer: state.buffer <> data}, @frames_per_turn)
    end
  end

  defp authenticate(state, data) do
    case Auth.feed(state.auth, data, now_ms()) do
      {:ok, auth, actions} ->
        credentials =
          if auth.phase in [:authenticated, :connected], do: auth.credentials, else: nil

        state = schedule_auth_timer(%{state | auth: auth, credentials: credentials})

        case auth_actions(state, actions) do
          {:ok, %{state: :awaiting_hello} = state} -> process_messages(state, @frames_per_turn)
          {:ok, %{auth_continuing: true} = state} -> {:noreply, state}
          {:ok, state} -> arm_read(state)
          {:error, reason, state} -> stop_peer(state, reason)
        end

      {:error, reason, auth, actions} ->
        case auth_actions(%{state | auth: auth, credentials: nil}, actions) do
          {:ok, state} -> stop_peer(state, reason)
          {:error, send_reason, state} -> stop_peer(state, send_reason)
        end
    end
  end

  defp auth_actions(state, actions) do
    Enum.reduce_while(actions, {:ok, state}, fn action, {:ok, state} ->
      case auth_action(state, action) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, _reason, _state} = error -> {:halt, error}
      end
    end)
  end

  defp auth_action(state, {:send, data}) do
    case send_bytes(state.native_socket, data) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp auth_action(state, {:authenticated, _credentials}), do: {:ok, state}

  defp auth_action(state, :continue) do
    send(self(), :continue_auth)
    {:ok, %{state | auth_continuing: true}}
  end

  defp auth_action(state, {:begin, buffer}) do
    case GaoBus.Limits.auth_completed(self()) do
      :ok ->
        cancel_timer(state.auth_timer)
        GaoBus.Router.register_peer(self(), nil, state.credentials, state.auth.unix_fd_negotiated)

        registration_timer =
          if state.xml_limits do
            state.registration_timer
          else
            token = make_ref()

            timer =
              Process.send_after(
                self(),
                {:registration_expiry, token},
                state.auth.limits.timeout_ms
              )

            {timer, token}
          end

        {:ok,
         %{
           state
           | state: :awaiting_hello,
             buffer: buffer,
             auth_timer: nil,
             registration_timer: registration_timer
         }}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp process_messages(%{route_wait: token} = state, _budget) when not is_nil(token),
    do: {:noreply, state}

  defp process_messages(%{state: :registering} = state, _budget), do: {:noreply, state}

  defp process_messages(state, budget) do
    with :ok <- frame_not_expired(state),
         :ok <- input_ready(state) do
      process_frame(%{state | ingress_paused: false}, budget)
    else
      {:error, {:xml_limit_exceeded, _name}} -> {:noreply, %{state | ingress_paused: true}}
      {:error, reason} -> stop_peer(state, reason)
    end
  end

  defp input_ready(%{state: :authenticating}), do: :ok
  defp input_ready(%{xml_limits: nil}), do: :ok
  defp input_ready(_state), do: GaoBus.Limits.ingress_ready(self())

  defp process_frame(state, budget) do
    case next_frame(state.buffer, state.frame_options.max_bytes) do
      :incomplete ->
        arm_read(track_frame_deadline(state))

      {:error, reason} ->
        stop_peer(state, reason)

      {:ok, _frame, _rest} when budget == 0 ->
        send(self(), :continue_messages)
        {:noreply, %{state | messages_continuing: true}}

      {:ok, frame, rest} ->
        cancel_timer(state.frame_timer)
        cancel_timer(state.pending_fd_timer)

        state = %{
          state
          | frame_timer: nil,
            frame_deadline: nil,
            pending_fd_timer: nil,
            pending_fd_deadline: nil
        }

        case decode_frame(frame) do
          {:ok, msg, <<>>} ->
            if Descriptors.valid?(
                 msg,
                 state.incoming_fds,
                 state.auth.unix_fd_negotiated,
                 state.frame_options.max_fds
               ) do
              msg = %{msg | fds: state.incoming_fds}
              route_message(%{state | buffer: rest}, msg, budget, byte_size(frame))
            else
              stop_peer(state, :invalid_unix_fds)
            end

          {:error, reason} ->
            stop_peer(state, {:invalid_frame, reason})

          _ ->
            stop_peer(state, :invalid_frame)
        end
    end
  end

  defp route_message(state, %{type: {:unknown, _type}}, budget, _bytes) do
    close_resources(state.incoming_fds)

    case GaoBus.Limits.set_frame(self(), byte_size(state.buffer), 0) do
      :ok -> process_messages(%{state | incoming_fds: []}, budget - 1)
      {:error, reason} -> stop_peer(%{state | incoming_fds: []}, reason)
    end
  end

  defp route_message(%{state: :awaiting_hello} = state, msg, _budget, bytes) do
    if valid_hello?(msg) do
      case GaoBus.Router.route_frame(%{msg | sender: nil}, self(), bytes) do
        {:ok, token} ->
          {:noreply,
           %{
             state
             | state: :registering,
               hello_serial: msg.serial,
               incoming_fds: [],
               route_wait: token
           }}

        {:error, reason} ->
          stop_peer(state, reason)
      end
    else
      error =
        Message.error("org.freedesktop.DBus.Error.AccessDenied", msg.serial,
          serial: 1,
          sender: "org.freedesktop.DBus",
          signature: "s",
          body: ["Hello is required"]
        )

      encode_and_send(state.native_socket, error)
      stop_peer(state, :hello_required)
    end
  end

  defp route_message(state, msg, _budget, bytes) do
    case GaoBus.Router.route_frame(%{msg | sender: state.unique_name}, self(), bytes) do
      {:ok, token} -> {:noreply, %{state | incoming_fds: [], route_wait: token}}
      {:error, reason} -> stop_peer(state, reason)
    end
  end

  defp valid_hello?(%Message{
         type: :method_call,
         serial: serial,
         path: path,
         interface: interface,
         member: "Hello",
         destination: destination,
         signature: signature,
         body: []
       }) do
    ExDBus.Wire.Types.valid?(:object_path, path) and is_integer(serial) and serial > 0 and
      interface in [nil, "org.freedesktop.DBus"] and
      destination in [nil, "org.freedesktop.DBus"] and signature in [nil, ""]
  end

  defp valid_hello?(_msg), do: false

  defp after_send(
         %{state: :registering, hello_serial: serial} = state,
         %{reply_serial: serial} = msg
       ) do
    if msg.type == :method_return and msg.body == [state.unique_name] and
         is_binary(state.unique_name) do
      cancel_timer(state.registration_timer)
      process_messages(%{state | state: :connected, registration_timer: nil}, @frames_per_turn)
    else
      if msg.type == :error and msg.error_name == "org.freedesktop.DBus.Error.LimitsExceeded" do
        process_messages(%{state | state: :awaiting_hello, hello_serial: nil}, @frames_per_turn)
      else
        stop_peer(state, :hello_failed)
      end
    end
  end

  defp after_send(state, _msg), do: {:noreply, state}

  # recvmsg does not report ancillary byte offsets. Keep auth reads separate and
  # calculate the validated current-frame extent before optional FD-free read-ahead.
  defp read_budget(%{state: :authenticating, auth: %{phase: :initial}}), do: {:ok, 1}

  defp read_budget(%{state: :authenticating, auth: auth, socket: socket}) do
    buffered = byte_size(auth.buffer)

    bound =
      min(
        @recv_bytes,
        min(
          auth.limits.max_line_bytes - buffered + 1,
          auth.limits.max_auth_bytes - auth.total_bytes - buffered + 1
        )
      )

    # This data-only preview is bounded scratch outside frame credits. Credits
    # still precede the consuming native receive; no peeked bytes enter Auth.
    case :socket.recv(socket, bound, [:peek], 0) do
      {:ok, prefix} -> auth_prefix_budget(prefix)
      {:error, {:timeout, prefix}} -> auth_prefix_budget(prefix)
      {:error, :timeout} -> {:ok, 1}
      {:error, _reason} = error -> error
    end
  end

  defp read_budget(%{buffer: buffer}) when byte_size(buffer) < 16,
    do: {:ok, 16 - byte_size(buffer)}

  defp read_budget(%{buffer: buffer} = state) do
    case frame_size(buffer, state.frame_options.max_bytes) do
      {:ok, size} when size > byte_size(buffer) ->
        {:ok, min(@recv_bytes, size - byte_size(buffer))}

      {:ok, _size} ->
        {:error, :unexpected_complete_frame}

      {:error, _} = error ->
        error
    end
  end

  defp reserve_read(state, bytes, fd_limit) do
    buffered = byte_size(state.buffer)

    read_ahead =
      if state.state != :authenticating and not state.auth.unix_fd_negotiated and buffered >= 16 do
        min(@recv_bytes, state.frame_options.max_bytes - buffered)
      else
        bytes
      end

    case GaoBus.Limits.set_frame(self(), buffered + read_ahead, fd_limit) do
      :ok ->
        {:ok, read_ahead}

      {:error, {:limit_exceeded, scope, :frame_bytes}}
      when scope in [:peer, :uid, :global] and read_ahead > bytes ->
        # Speculative successors must not prevent a current frame that still fits.
        with :ok <- GaoBus.Limits.set_frame(self(), buffered + bytes, fd_limit),
             do: {:ok, bytes}

      error ->
        error
    end
  end

  defp auth_prefix_budget(<<>>), do: {:error, :closed}

  defp auth_prefix_budget(prefix) do
    case :binary.match(prefix, "\n") do
      {position, 1} -> {:ok, position + 1}
      :nomatch -> {:ok, byte_size(prefix)}
    end
  end

  defp next_frame(buffer, _limit) when byte_size(buffer) < 16, do: :incomplete

  defp next_frame(
         <<?l, _::24, body::little-32, _::32, header::little-32, _::binary>> = buffer,
         limit
       ),
       do: sized_frame(buffer, body, header, limit)

  defp next_frame(<<?B, _::24, body::big-32, _::32, header::big-32, _::binary>> = buffer, limit),
    do: sized_frame(buffer, body, header, limit)

  defp next_frame(_buffer, _limit), do: {:error, :invalid_endianness}

  defp sized_frame(buffer, body, header, limit) do
    with {:ok, size} <- checked_frame_size(body, header, limit) do
      if byte_size(buffer) < size do
        :incomplete
      else
        <<frame::binary-size(size), rest::binary>> = buffer
        {:ok, frame, rest}
      end
    end
  end

  defp frame_size(<<?l, _::24, body::little-32, _::32, header::little-32, _::binary>>, limit),
    do: checked_frame_size(body, header, limit)

  defp frame_size(<<?B, _::24, body::big-32, _::32, header::big-32, _::binary>>, limit),
    do: checked_frame_size(body, header, limit)

  defp frame_size(_buffer, _limit), do: {:error, :invalid_endianness}

  defp checked_frame_size(body, header, limit) do
    case Message.validate_lengths(body, header) do
      {:ok, size} when size <= limit -> {:ok, size}
      {:ok, _size} -> {:error, :frame_too_large}
      {:error, _reason} -> {:error, :frame_too_large}
    end
  end

  defp decode_frame(frame) do
    Message.decode_message(frame)
  rescue
    _error -> {:error, :invalid_encoding}
  end

  defp arm_read(%{route_wait: token} = state) when not is_nil(token),
    do: {:noreply, state}

  defp arm_read(%{recv_select: reference} = state) when not is_nil(reference),
    do: {:noreply, state}

  defp arm_read(%{ingress_paused: true} = state), do: {:noreply, state}

  defp arm_read(%{read_scheduled: true} = state), do: {:noreply, state}

  defp arm_read(state) do
    case :socket.recv(state.socket, 1, [:peek], :nowait) do
      {:ok, <<>>} ->
        stop_peer(state, :closed)

      {:ok, _byte} ->
        send(self(), :read_socket)
        {:noreply, %{state | read_scheduled: true}}

      {:select, {:select_info, _operation, reference}} ->
        {:noreply, %{state | recv_select: reference}}

      {:error, reason} ->
        stop_peer(state, reason)
    end
  end

  defp encode_and_send(socket, msg) do
    send_bytes(socket, Message.encode_message(msg))
  rescue
    _error -> {:error, :invalid_outbound_message}
  end

  defp send_bytes(socket, data) when byte_size(data) <= @max_output_bytes do
    case Resources.send(socket, data) do
      {:ok, count} when count == byte_size(data) -> :ok
      {:ok, _count} -> {:error, :short_send}
      {:error, reason} -> {:error, {:send_failed, reason}}
    end
  end

  defp send_bytes(_socket, _data), do: {:error, :outbound_message_too_large}

  defp new_output(state, message, token, queued_at) do
    with {:ok, writer} <-
           Writer.new(Message.encode_message(message), message.fds, queued_at,
             timeout_ms: Application.get_env(:gao_bus, :send_timeout_ms, 5000),
             max_bytes: state.frame_options.max_output_bytes
           ) do
      {:ok, %{message: message, token: token, writer: writer}}
    end
  rescue
    _error -> {:error, :invalid_outbound_message}
  end

  defp continue_write(%{write_timer: timer} = state) when not is_nil(timer),
    do: {:noreply, state}

  defp continue_write(%{current_output: nil} = state) do
    case :queue.out(state.output_queue) do
      {:empty, _queue} ->
        {:noreply, state}

      {{:value, output}, queue} ->
        continue_write(%{state | current_output: output, output_queue: queue})
    end
  end

  defp continue_write(state) do
    output = state.current_output

    case Writer.step(state.native_socket, output.writer, now_ms()) do
      {:done, _writer} ->
        release_output(output)

        case after_send(%{state | current_output: nil}, output.message) do
          {:noreply, state} -> {:noreply, schedule_write(state, 0)}
          stopped -> stopped
        end

      {:wait, writer} ->
        state = %{state | current_output: %{output | writer: writer}}
        {:noreply, schedule_write(state, if(writer.blocked, do: 5, else: 0))}

      {:error, reason, _writer} ->
        stop_peer(state, {:send_failed, reason})
    end
  end

  defp schedule_write(%{current_output: nil, output_queue: {[], []}} = state, _delay), do: state

  defp schedule_write(state, delay) do
    token = make_ref()
    timer = Process.send_after(self(), {:write_tick, token}, delay)
    %{state | write_timer: {timer, token}}
  end

  defp release_output(%{message: message, token: token}) do
    close_resources(message.fds)

    case GaoBus.Limits.release(token) do
      :ok -> :ok
      {:error, :unknown_reservation} -> :ok
      {:error, reason} -> exit({:resource_accounting_failed, reason})
    end
  end

  defp close_resources(handles) do
    case Resources.close(handles) do
      :ok -> :ok
      {:error, reason} -> exit({:resource_cleanup_failed, reason})
    end
  end

  defp track_frame_deadline(%{buffer: <<>>} = state) do
    cancel_timer(state.frame_timer)
    %{state | frame_timer: nil, frame_deadline: nil}
  end

  defp track_frame_deadline(%{frame_timeout_ms: nil} = state), do: state

  defp track_frame_deadline(%{frame_timer: nil} = state) do
    token = make_ref()
    timer = Process.send_after(self(), {:frame_expiry, token}, state.frame_timeout_ms)
    %{state | frame_timer: {timer, token}, frame_deadline: now_ms() + state.frame_timeout_ms}
  end

  defp track_frame_deadline(state), do: state

  defp frame_not_expired(%{frame_deadline: nil}), do: :ok

  defp frame_not_expired(%{frame_deadline: deadline}),
    do: if(now_ms() < deadline, do: :ok, else: {:error, :frame_timeout})

  defp frame_options(nil),
    do:
      {:ok,
       %{
         max_bytes: @max_buffer_bytes,
         max_fds: 16,
         pending_fd_timeout: nil,
         max_output_bytes: 1_048_576
       }}

  defp frame_options(xml) when is_map(xml) do
    bytes = Map.get(xml, "max_message_size", 33_554_432)
    fds = Map.get(xml, "max_message_unix_fds", 16)
    timeout = Map.get(xml, "pending_fd_timeout", 150_000)

    if is_integer(bytes) and bytes in 1..134_217_728 and
         is_integer(fds) and fds in 1..253 and
         is_integer(timeout) and timeout in 0..0x7FFFFFFF,
       do:
         {:ok,
          %{
            max_bytes: bytes,
            max_fds: fds,
            pending_fd_timeout: timeout,
            max_output_bytes: 134_217_728
          }},
       else: {:error, :invalid_xml_frame_limits}
  end

  defp frame_options(_xml), do: {:error, :invalid_xml_frame_limits}

  defp track_pending_fds(%{incoming_fds: []} = state), do: state
  defp track_pending_fds(%{frame_options: %{pending_fd_timeout: nil}} = state), do: state

  defp track_pending_fds(%{pending_fd_timer: nil} = state) do
    token = make_ref()
    timeout = state.frame_options.pending_fd_timeout
    timer = Process.send_after(self(), {:pending_fd_expiry, token}, timeout)
    %{state | pending_fd_timer: {timer, token}, pending_fd_deadline: now_ms() + timeout}
  end

  defp track_pending_fds(state), do: state

  defp pending_fd_not_expired(%{pending_fd_deadline: nil}), do: :ok

  defp pending_fd_not_expired(state),
    do: if(now_ms() < state.pending_fd_deadline, do: :ok, else: {:error, :pending_fd_timeout})

  defp authentication_options(%{xml_limits: nil} = state),
    do: Keyword.put(state.auth_limits, :unix_fd, true)

  defp authentication_options(state) do
    # XML uses one absolute accept-to-Hello timeout, including SASL. Retain
    # native byte/line bounds but do not reset or shorten the XML time budget.
    remaining = max(state.hello_deadline - now_ms(), 1)

    state.auth_limits
    |> Keyword.put(:unix_fd, true)
    |> Keyword.put(:timeout_ms, remaining)
    |> Keyword.put(:idle_timeout_ms, remaining)
  end

  defp hello_not_expired(%{hello_deadline: nil}), do: :ok

  defp hello_not_expired(state) do
    if now_ms() < state.hello_deadline, do: :ok, else: {:error, :hello_timeout}
  end

  defp schedule_auth_timer(%{auth: %{phase: :connected}} = state), do: state

  defp schedule_auth_timer(state) do
    cancel_timer(state.auth_timer)
    auth = state.auth

    deadline =
      min(
        auth.started_at + auth.limits.timeout_ms,
        auth.last_received_at + auth.limits.idle_timeout_ms
      )

    token = make_ref()
    timer = Process.send_after(self(), {:auth_expiry, token}, max(deadline - now_ms(), 0))
    %{state | auth_timer: {timer, token}}
  end

  defp cancel_timer(nil), do: :ok
  defp cancel_timer({reference, _token}), do: Process.cancel_timer(reference)

  defp stop_peer(state, reason) do
    Logger.debug("GaoBus.Peer: connection closed: #{inspect(reason)}")
    {:stop, :normal, state}
  end

  defp safely(function) do
    function.()
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp next_peer_id do
    ensure_counter()
    :atomics.add_get(:persistent_term.get(@counter_key), 1, 1)
  end

  defp auth_guid, do: @auth_guid || GaoBus.Ids.auth_guid()
  defp now_ms, do: System.monotonic_time(:millisecond)
end
