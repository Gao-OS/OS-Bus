# Read-only adapter of the existing quota daemon; policy, monitors and kill stay intact.
original = Enum.at(System.argv(), 2)
source = File.read!(original)
expected = "b9b62c9d3cf98cfb49f5dbbf571c2dd2afb865bdaddb2aadb24dfeb103edc815"
^expected = Base.encode16(:crypto.hash(:sha256, source), case: :lower)

scalar_anchor = "      buffer_bytes: byte_size(state.buffer),\n"
command_anchor = "            [\"blocked\", name] ->\n"

scalars = """
      incoming_fds: length(state.incoming_fds),
      frame_deadline: state.frame_deadline,
      frame_timeout_ms: state.frame_timeout_ms,
"""

command = """
            ["frame", name] ->
              {:ok, pid} = GaoBus.NameRegistry.resolve(name)
              row = peer(pid, %{unique_name: name})
              true = row.buffer_bytes > 0 and row.incoming_fds == 1
              true = is_integer(row.frame_deadline) and row.frame_timeout_ms == 5000
              true = now() < row.frame_deadline
              watch = Map.fetch!(watches, name)

              {%{event: "frame", row: row, now_ms: now()},
               Map.put(watches, name, %{watch | deadline: row.frame_deadline})}

"""

for anchor <- [scalar_anchor, command_anchor] do
  [_, _] = String.split(source, anchor)
end

adapted =
  source
  |> String.replace(scalar_anchor, scalar_anchor <> scalars)
  |> String.replace(command_anchor, command <> command_anchor)

Code.eval_string(adapted, [], file: original <> "::sec17-frame-scalars")
