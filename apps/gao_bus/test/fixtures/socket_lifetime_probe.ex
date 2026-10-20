defmodule GaoBus.Unix.NativeProbe do
  @moduledoc false
  def load(path), do: :erlang.load_nif(String.to_charlist(path), 0)

  # Before the repair, reproduce the real borrowed-integer API, not missing API.
  # The repaired NIF overrides this fallback with actual socket capture.
  def capture(fd), do: {:ok, fd}
  def recv(_fd, _bytes, _fds), do: :erlang.nif_error(:not_loaded)
  def send(_fd, _bytes, _fds), do: :erlang.nif_error(:not_loaded)
  def close(_fd), do: :erlang.nif_error(:not_loaded)
  def arm(_phase, _observer), do: :erlang.nif_error(:not_loaded)
  def release, do: :erlang.nif_error(:not_loaded)
  def status, do: :erlang.nif_error(:not_loaded)
  def reuse(_fd), do: :erlang.nif_error(:not_loaded)
  def raw_write(_fd, _bytes), do: :erlang.nif_error(:not_loaded)
  def raw_read(_fd), do: :erlang.nif_error(:not_loaded)
  def raw_close(_first, _second), do: :erlang.nif_error(:not_loaded)
  def resource, do: :erlang.nif_error(:not_loaded)
  def resource_fd(_handle), do: :erlang.nif_error(:not_loaded)
end
