# Packaged modules only; no GaoBus.Application startup or bus override.
[name, result_file] = System.argv()
:ok = Application.load(:gao_bus)
%{uid: 4, real_uid: 4, gid: 4, real_gid: 4} = GaoBus.Unix.Native.identity()
token = make_ref()
epoch = make_ref()
attempt = make_ref()
{:ok, worker} = GaoBus.Activation.HelperWorker.start_link(owner: self(), epoch: epoch, attempt: attempt, token: token, name: name)
monitor = Process.monitor(worker)
:ok = GaoBus.Activation.HelperWorker.launch(worker, token)
result = receive do
  {:helper_result, ^worker, ^epoch, ^attempt, ^token, {:exited, value}} -> %{kind: 3, stage: 0, value: value}
  {:helper_result, ^worker, ^epoch, ^attempt, ^token, other} -> raise "unproved worker result #{inspect(other)}"
after
  15_000 -> raise "worker observation deadline"
end
receive do
  {:DOWN, ^monitor, :process, ^worker, :normal} -> :ok
after
  1_000 -> raise "worker lifecycle deadline"
end
identity = GaoBus.Unix.Native.identity()
%{uid: 4, real_uid: 4, gid: 4, real_gid: 4} = identity
File.write!(result_file <> ".tmp", :json.encode(%{result: result, worker_down: "normal", caller_pid: System.pid(), caller_identity: identity}))
File.rename!(result_file <> ".tmp", result_file)
