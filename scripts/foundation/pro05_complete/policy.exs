# Explicit permission for this private finite fixture; no implicit UID exception.
bus = "org.freedesktop.DBus"

admission =
  for uid <- [1100, 1101],
      do: %{action: :connect, effect: :allow, match: %{uid: uid}}

calls =
  for uid <- [1100, 1101],
      member <- [
        "Hello",
        "GetId",
        "GetNameOwner",
        "ListNames",
        "NameHasOwner",
        "GetConnectionUnixUser",
        "GetConnectionUnixProcessID",
        "RequestName",
        "AddMatch"
      ],
      do: %{
        action: :send,
        effect: :allow,
        match: %{
          uid: uid,
          destination: bus,
          interface: bus,
          path: "/org/freedesktop/DBus",
          member: member,
          type: :method_call
        }
      }

replies =
  for uid <- [1100, 1101],
      type <- [:method_return, :error],
      do: %{action: :receive, effect: :allow, match: %{uid: uid, sender: bus, type: type}}

acquired =
  for uid <- [1100, 1101],
      do: %{
        action: :receive,
        effect: :allow,
        match: %{uid: uid, sender: bus, interface: bus, member: "NameAcquired", type: :signal}
      }

admission ++
  calls ++
  replies ++
  acquired ++
  [
    %{
      action: :own,
      effect: :allow,
      match: %{uid: 1100, name: "org.foundation.Observer"}
    },
    %{
      action: :send,
      effect: :allow,
      match: %{
        uid: 1101,
        type: :signal,
        interface: "org.foundation.Probe",
        path: "/probe",
        member: "Changed"
      }
    },
    %{
      action: :receive,
      effect: :allow,
      match: %{
        uid: 1100,
        type: :signal,
        interface: "org.foundation.Probe",
        path: "/probe",
        member: "Changed"
      }
    }
  ]
