# P01 launcher prototype. This must be repeated with the P11 packaged release.
if System.get_env("LISTEN_PID") != System.pid() or System.get_env("LISTEN_FDS") != "1" do
  raise "invalid inherited listener environment"
end

IO.inspect(File.read_link("/proc/self/fd/3"), label: "BEAM fd3")
{:ok, listener} = :socket.open(3, %{dup: false})
{:ok, :local} = :socket.getopt(listener, {:otp, :domain})
{:ok, :stream} = :socket.getopt(listener, {:socket, :type})
{:ok, true} = :socket.getopt(listener, {:socket, :acceptconn})
Enum.each(["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"], &System.delete_env/1)
IO.puts("READY #{System.pid()}")
{:ok, client} = :socket.accept(listener, 5_000)
{:ok, "probe"} = :socket.recv(client, 5, 5_000)
:ok = :socket.send(client, "inherited-ok", [], 5_000)
:ok = :socket.close(client)
:ok = :socket.close(listener)
IO.puts("CLOSED")
