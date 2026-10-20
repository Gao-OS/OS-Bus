# Last matching rule wins; no implicit root/low-UID privilege exists.
identities = [0, 1100, 1101]
admission = for uid <- identities, do: %{action: :connect, effect: :allow, match: %{uid: uid}}

traffic =
  for uid <- identities,
      action <- [:send, :receive],
      do: %{action: action, effect: :allow, match: %{uid: uid}}

admission ++
  traffic ++
  [
    %{action: :own, effect: :allow, match: %{uid: 0, name: {:prefix, "org.foundation.Root"}}},
    %{action: :own, effect: :allow, match: %{uid: 1100, name: "org.foundation.Observer"}},
    %{
      action: :own,
      effect: :allow,
      match: %{uid: 1101, name: {:prefix, "org.foundation.Service"}}
    },
    %{action: :own, effect: :deny, match: %{name: "org.foundation.Forbidden"}},
    %{
      action: :send,
      effect: :deny,
      match: %{uid: 1100, destination: "org.foundation.Service.Protected"}
    },
    %{
      action: :receive,
      effect: :deny,
      match: %{uid: 1101, interface: "org.foundation.ReceiveDenied"}
    },
    %{
      action: :receive,
      effect: :deny,
      match: %{uid: 1101, type: :method_return, sender: "org.foundation.Observer"}
    }
  ]
