defmodule GaoBus.Unix.Native do
  @moduledoc false
  @on_load :load

  def load do
    path = :filename.join(:code.priv_dir(:gao_bus), ~c"gao_unix")
    :erlang.load_nif(path, 0)
  end

  def capture(_socket_fd), do: :erlang.nif_error(:not_loaded)
  # Caller owns and retains the public OTP duplicate for this bounded handoff.
  def inherited_listener_handoff(_socket_fd), do: :erlang.nif_error(:not_loaded)
  def recv(_socket_fd, _max_bytes, _max_fds), do: :erlang.nif_error(:not_loaded)
  def send(_socket_fd, _bytes, _handles), do: :erlang.nif_error(:not_loaded)
  def duplicate(_handles), do: :erlang.nif_error(:not_loaded)
  def writable(_socket_fd), do: :erlang.nif_error(:not_loaded)
  def close(_handle), do: :erlang.nif_error(:not_loaded)
  def info(_handle), do: :erlang.nif_error(:not_loaded)
  def identity, do: :erlang.nif_error(:not_loaded)

  def list_dir_bounded(_path, _entry_budget, _name_byte_budget),
    do: :erlang.nif_error(:not_loaded)

  def read_file_at_bounded(_directory, _name, _expected_directory, _byte_budget),
    do: :erlang.nif_error(:not_loaded)
end
