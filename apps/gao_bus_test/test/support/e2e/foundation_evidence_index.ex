defmodule GaoBusTest.E2E.FoundationEvidenceIndex do
  @moduledoc "Offline, fail-closed accounting for TEST_PLAN requirements; launches no actors."
  alias GaoBusTest.E2E.Qualification
  @plan "docs/codex/os-bus-foundation/TEST_PLAN.md"
  @plan_hash "0b6993e18ebea9a5ec7c2f017025a490e32bdf4406490ac1889381a60de2633d"
  @catalogue [
    %{
      "required_id" => "H-01",
      "scenario" =>
        "Baseline includes existing unit/interop/E2E suites and records actual selection.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["offline"],
          "layer" => "pure",
          "actors" => ["offline_test"],
          "invariants" => [
            "Exact commands, counts, versions, and pre-existing failures saved; no claim that excluded E2E ran."
          ]
        }
      ]
    },
    %{
      "required_id" => "H-02",
      "scenario" =>
        "Deliberately omit a required actor, fail a backend probe, and select an empty gate.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["offline"],
          "layer" => "pure",
          "actors" => ["offline_test"],
          "invariants" => [
            "Each condition fails strict qualification rather than returning green or an unnoticed skip."
          ]
        }
      ]
    },
    %{
      "required_id" => "H-03",
      "scenario" =>
        "Run independent raw-protocol and multiple real-UID actors on isolated sockets.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Actor identity verified externally; no mocked production UID, no implicit host bus address."
          ]
        }
      ]
    },
    %{
      "required_id" => "H-04",
      "scenario" =>
        "Exercise artifact capture, fixture timeout, and teardown after test-runner failure.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Child daemons/fixtures/resources are reaped; selected and executed IDs, logs, config hashes, and seeds are retained."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-01",
      "scenario" =>
        "Valid EXTERNAL authentication through independent GLib and sd-bus/libdbus clients; fragmented and pipelined exchanges.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Clients complete Hello; returned identity agrees with independently known kernel identity."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-02",
      "scenario" => "Non-root client asserts UID 0 or another user's identity.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No admission as that identity, no privileged ownership/call, and no fabricated root credential record."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-03",
      "scenario" =>
        "Empty, malformed, out-of-range, and noncanonical asserted identities; bare AUTH and DATA variants.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Valid standard flows remain valid; bad assertions never grant identity or crash the daemon."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-04",
      "scenario" =>
        "BEGIN before successful authentication, after rejection/cancellation, or after an unsupported mechanism.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No entry into normal bus operations; observer remains connected with unchanged names."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-05",
      "scenario" => "ANONYMOUS and early/invalid FD negotiation in system mode.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No anonymous system-bus admission; negotiation only succeeds in an allowed authenticated state."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-06",
      "scenario" =>
        "Real/simulated adapter failure retrieving required kernel credentials; unavailable metadata.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Connection rejected or required operation denied; no asserted-UID or zero-value fallback."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-07",
      "scenario" =>
        "Oversized/incomplete authentication lines, repeated failures, slow trickle, and handshake expiry.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Bounded bytes/work/time/connections; offending peer closes and healthy observer remains serviceable."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-08",
      "scenario" => "Own a forbidden system name as an ordinary UID and as a service UID.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Access denied before mutation; no unauthorized owner/queue entry or ownership signal."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-09",
      "scenario" =>
        "Denied send through a well-known destination, its unique name, and alternate owned aliases.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Outcome agrees with the configured reference policy; no identity/alias bypass."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-10",
      "scenario" =>
        "Sender allowed but receiver policy denies; include a signal and a reply where applicable.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No delivery; sender/receiver semantics match the same reference policy."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-11",
      "scenario" =>
        "Denied connection admission, privileged bus method, or config/activation control.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No unauthorized side effect or privilege acquired merely by addressing the bus object."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-12",
      "scenario" =>
        "Attempt unauthorized eavesdropping, monitoring, or access to internal payload diagnostics.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No private payload disclosure; unsupported monitoring is rejected and not advertised."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-13",
      "scenario" =>
        "No policy at startup, unavailable evaluator without a valid snapshot, and policy-process restart.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No fail-open path. A deliberately retained valid immutable snapshot is distinguished from absent policy; core reset is coherent if required."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-14",
      "scenario" =>
        "Structurally valid Bus calls with wrong body count/type/signature/path/interface.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Controlled error according to contract; same Router/healthy connection remains operational; no state mutation."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-15",
      "scenario" => "Malformed frame designed to reach a former body-pattern-match crash.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Frame rejected before authority dispatch; no global peer restart or lost healthy ownership."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-16",
      "scenario" =>
        "Pre-Hello operations, repeated Hello, forged sender, and reordered registration input.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No premature privileges; stable registration identity; reply/signal sequencing and errors are correct."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEC-17",
      "scenario" =>
        "Crash/kill a peer while it owns names, queued requests, match rules, capabilities, and resources.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Idempotent monitored cleanup; no stale authority or leaked rights; unrelated peers survive."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-01",
      "scenario" =>
        "Every split point in representative authentication/Hello/frame streams; several complete frames per read.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Same semantic sequence independent of fragmentation/coalescing; no buffered bytes or FDs are lost."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-02",
      "scenario" =>
        "Invalid version/type/serial/required header fields and valid unknown extension cases.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Invalid input rejected; required forward-compatible ignoring/filtering preserved; no blanket extension rejection."
          ]
        },
        %{
          "subcase_id" => "reply-interface",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Invalid input rejected; required forward-compatible ignoring/filtering preserved; no blanket extension rejection."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-03",
      "scenario" =>
        "Duplicate/wrong-typed headers, mismatched signatures, invalid strings/paths, and invalid padding/containers.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => ["Explicit terminal errors; no empty-body success or core crash."]
        }
      ]
    },
    %{
      "required_id" => "PRO-04",
      "scenario" =>
        "Truncated and oversized advertised lengths, missing body signature, and trailing body bytes.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct incomplete-versus-invalid distinction, exact frame consumption, pre-allocation bounds, eventual deadline closure."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-05",
      "scenario" =>
        "Deep signatures/containers, large collections, repeated invalid prefixes, and adversarial match argument values.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Work/memory/atom counts bounded; no arithmetic, pattern-match, or string-function crash in authority."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-06",
      "scenario" =>
        "Independent little-/big-endian corpus, variants, structs, arrays/dictionaries, and FD-index values.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Cross-implementation semantic equivalence; not only an ExDBus self-round-trip."
          ]
        }
      ]
    },
    %{
      "required_id" => "PRO-07",
      "scenario" =>
        "Generated valid/invalid messages and stateful sequences with deterministic seeds.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["offline"],
          "layer" => "pure",
          "actors" => ["offline_test"],
          "invariants" => [
            "Reproducible minimized counterexamples added as regressions; total validators return explicit results."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-01",
      "scenario" =>
        "Current owner repeats RequestName with changed flags; queued requester repeats it.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "owner-repeat",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => ["Correct flag updates and response codes, no duplicate queue entry."]
        },
        %{
          "subcase_id" => "queued-repeat",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => ["Correct flag updates and response codes, no duplicate queue entry."]
        }
      ]
    },
    %{
      "required_id" => "SEM-02",
      "scenario" =>
        "Replacement with several waiters, including a replaced owner with DO_NOT_QUEUE.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Exact queue transition and ownership signals agree with the reference behavior."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-03",
      "scenario" =>
        "Release a queued request; disconnect owner/waiter; race release with disconnect.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => ["Correct promotion and cleanup; no stale or duplicate ownership."]
        }
      ]
    },
    %{
      "required_id" => "SEM-04",
      "scenario" =>
        "Reserved, malformed, unique, and bus-self names; GetNameOwner/NameHasOwner/ListQueuedOwners.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct validation and lookup results; reserved bus authority cannot be acquired by a client."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-05",
      "scenario" => "Hello and ownership transitions while observers subscribe.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Required unicast/broadcast signals go to correct recipients in valid causal order; Hello reply is not overtaken improperly."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-06",
      "scenario" => "No match rules, nonmatching rules, and matching broadcast rules.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No-rule/nonmatch peers receive no broadcast; matching peers receive the expected signal."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-07",
      "scenario" => "Well-known sender match across name acquisition, release, and replacement.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Match follows correct live ownership rather than literal comparison with a unique sender string."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-08",
      "scenario" =>
        "Quoting/escaping, namespaces, typed arguments, invalid keys, duplicate AddMatch/RemoveMatch, and quota exhaustion.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct grammar/duplicate accounting and errors; no partial subscription mutation or parser crash."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-09",
      "scenario" => "Directed signal without a match rule; optional privileged monitoring.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Legitimate unicast delivery is not broken by broadcast filtering; monitor authorization/capability claims remain accurate."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-10",
      "scenario" =>
        "Replies from wrong callee, after owner replacement, duplicate/stale replies, and repeated serials on different connections.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Requested-reply authorization is bound to correct connection incarnations and cannot be hijacked."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-11",
      "scenario" =>
        "NO_REPLY_EXPECTED, NO_AUTO_START, call errors, send failure, timeout, and caller/callee disconnect.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Appropriate output only; no spurious reply/activation; pending-call budget reclaimed."
          ]
        },
        %{
          "subcase_id" => "no-reply-expected-absent-member",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Appropriate output only; no spurious reply/activation; pending-call budget reclaimed."
          ]
        }
      ]
    },
    %{
      "required_id" => "SEM-12",
      "scenario" => "A reference policy explicitly permits or denies unsolicited responses.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Compatibility follows the configured semantics rather than a new unconditional allow or unconditional deny."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-01",
      "scenario" =>
        "Transfer a pipe, regular file/memfd, and Unix socket using the selected OTP/helper implementation.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "pipe",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Receiver actually reads/writes/uses the intended resource; adapter owns and closes arbitrary descriptors correctly."
          ]
        },
        %{
          "subcase_id" => "regular-file-memfd",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Receiver actually reads/writes/uses the intended resource; adapter owns and closes arbitrary descriptors correctly."
          ]
        },
        %{
          "subcase_id" => "unix-socket",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Receiver actually reads/writes/uses the intended resource; adapter owns and closes arbitrary descriptors correctly."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-02",
      "scenario" =>
        "Rights arrive with a partial header/body, followed by later bytes; test each relevant boundary.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "partial-header",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Frame receives its intended descriptor bundle after reassembly; no loss when the first decode returns incomplete."
          ]
        },
        %{
          "subcase_id" => "partial-body",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Frame receives its intended descriptor bundle after reassembly; no loss when the first decode returns incomplete."
          ]
        },
        %{
          "subcase_id" => "each-relevant-boundary",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Frame receives its intended descriptor bundle after reassembly; no loss when the first decode returns incomplete."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-03",
      "scenario" =>
        "Consecutive frames with different rights, mixed FD/no-FD messages, and coalesced input.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "different-bundles",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "No descriptor is attached to another message; counts/index mapping remain correct."
          ]
        },
        %{
          "subcase_id" => "mixed-fd-no-fd",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "No descriptor is attached to another message; counts/index mapping remain correct."
          ]
        },
        %{
          "subcase_id" => "coalesced-input",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "No descriptor is attached to another message; counts/index mapping remain correct."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-04",
      "scenario" =>
        "Control truncation, wrong advertised count, invalid index, excess descriptors, and resource-bearing auth input.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "control-truncation",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights."
          ]
        },
        %{
          "subcase_id" => "wrong-count",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights."
          ]
        },
        %{
          "subcase_id" => "invalid-index",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights."
          ]
        },
        %{
          "subcase_id" => "excess-rights",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights."
          ]
        },
        %{
          "subcase_id" => "auth-rights",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-05",
      "scenario" => "Send a resource-bearing message to a recipient without FD negotiation.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "unnegotiated-recipient",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Explicit correct failure/disposition; never a header claiming resources that were silently stripped."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-06",
      "scenario" => "Force short writes and repeated writable notifications with a slow reader.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "short-writes",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Exact byte stream and exactly the intended ancillary transfer; no duplicate rights on continuation."
          ]
        },
        %{
          "subcase_id" => "repeated-writable",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Exact byte stream and exactly the intended ancillary transfer; no duplicate rights on continuation."
          ]
        },
        %{
          "subcase_id" => "slow-reader",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Exact byte stream and exactly the intended ancillary transfer; no duplicate rights on continuation."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-07",
      "scenario" =>
        "Denied message, missing destination, failed activation, closed recipient, and send error.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "denied-message",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "All descriptor/queue references and budgets retired; independent leak check passes."
          ]
        },
        %{
          "subcase_id" => "missing-destination",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "All descriptor/queue references and budgets retired; independent leak check passes."
          ]
        },
        %{
          "subcase_id" => "failed-activation",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "All descriptor/queue references and budgets retired; independent leak check passes."
          ]
        },
        %{
          "subcase_id" => "closed-recipient",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "All descriptor/queue references and budgets retired; independent leak check passes."
          ]
        },
        %{
          "subcase_id" => "send-error",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "All descriptor/queue references and budgets retired; independent leak check passes."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-08",
      "scenario" =>
        "Source exits after enqueue; recipient exits during partial send; peer/resource-owner failure.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "source-death",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Defined completion/cancellation without use-after-close, double-close, or leak; healthy destination cannot receive a recycled unrelated FD."
          ]
        },
        %{
          "subcase_id" => "recipient-partial-send-death",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Defined completion/cancellation without use-after-close, double-close, or leak; healthy destination cannot receive a recycled unrelated FD."
          ]
        },
        %{
          "subcase_id" => "resource-owner-failure",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Defined completion/cancellation without use-after-close, double-close, or leak; healthy destination cannot receive a recycled unrelated FD."
          ]
        },
        %{
          "subcase_id" => "recycled-fd-exclusion",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Defined completion/cancellation without use-after-close, double-close, or leak; healthy destination cannot receive a recycled unrelated FD."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-09",
      "scenario" =>
        "Authorized resource-bearing fan-out to multiple recipients; one recipient stalls/exits.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "authorized-fanout",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Each authorized recipient gets correct resources; one path's cleanup does not invalidate another."
          ]
        },
        %{
          "subcase_id" => "stalled-recipient",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Each authorized recipient gets correct resources; one path's cleanup does not invalidate another."
          ]
        },
        %{
          "subcase_id" => "exited-recipient",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "Each authorized recipient gets correct resources; one path's cleanup does not invalidate another."
          ]
        }
      ]
    },
    %{
      "required_id" => "FD-10",
      "scenario" => "Repeated transfer/failure batches and service launch while rights are held.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "repeated-batches",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-daemon",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "No unexplained persistent FD growth; CLOEXEC/launch isolation prevents unintended inheritance."
          ]
        },
        %{
          "subcase_id" => "cloexec-service-launch",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["native_fixture", "external_observer"],
          "invariants" => [
            "No unexplained persistent FD growth; CLOEXEC/launch isolation prevents unintended inheritance."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-01",
      "scenario" =>
        "Per-peer, per-UID, and global connection/authentication/name/match limits at N and N+1.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Boundary enforced before allocation/admission; counters remain consistent on denial and cleanup."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-02",
      "scenario" =>
        "Fast producer and slow recipient; bounded ingress, egress, frame bytes, and pending requests.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Limits constrain actual queues/mailboxes/resources, not just a secondary bookkeeping structure."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-03",
      "scenario" =>
        "Burst of malformed traffic and diagnostic events with a concurrent healthy probe.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Bounded logs/cardinality/observer queues; health probe remains within the declared test deadline."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-04",
      "scenario" =>
        "Large broadcasts, many matches, and repeated queued calls under concurrent healthy requests.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Work per scheduling turn is bounded; control/cleanup/other peers are not starved."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-05",
      "scenario" =>
        "Repeated churn, denials, timeout/cancel, and disconnect batches after warm-up.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Reservations return exactly once; no unexplained monotonic FD/name/match/reply/atom/resource growth."
          ]
        }
      ]
    },
    %{
      "required_id" => "RES-06",
      "scenario" =>
        "Freeze qualification workload and run a sustained soak against the packaged release.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Saved numeric ceilings, samples, healthy latency, and completion counts demonstrate bounded behavior for that workload."
          ]
        }
      ]
    },
    %{
      "required_id" => "FAIL-01",
      "scenario" =>
        "Abrupt peer failure, including termination paths that do not run normal cleanup callbacks.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Monitors/resource ownership reclaim all authoritative state; surviving peers stay registered."
          ]
        }
      ]
    },
    %{
      "required_id" => "FAIL-02",
      "scenario" =>
        "Socket transfer/startup failure and second listener instance on an occupied path.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Incomplete peer/socket closed; incumbent listener/path and its clients are unchanged."
          ]
        }
      ]
    },
    %{
      "required_id" => "FAIL-03",
      "scenario" => "Deliberately crash a core authoritative process.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Documented epoch/reset/reconnect behavior; no live connections using stale authority or policy; no false claim of seamless continuity."
          ]
        }
      ]
    },
    %{
      "required_id" => "FAIL-04",
      "scenario" =>
        "Crash optional observer/UI/config service and attempt cluster-enabled startup in the minimal profile.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Bus runtime does not depend on those services; production configuration refuses an unsupported insecure combination."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-01",
      "scenario" => "Load the pinned profile's complete effective XML/configuration inventory.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Inventory/hash and supported directives recorded; no removed policy files or broadened substitutes."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-02",
      "scenario" =>
        "Ordered overlapping allow/deny rules for default, users/groups, ownership, send/receive, and replies.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Same effective decisions as reference for independently verified identities."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-03",
      "scenario" =>
        "Included files/directories, precedence, missing files, cycles, invalid XML, and unknown security/activation directives.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct supported behavior; otherwise clear validation failure with provenance, not silent acceptance."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-04",
      "scenario" =>
        "Known DOCTYPE, attempted network/external-entity expansion, deep includes, and oversized config.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Normal installed files load without DTD network access; malicious expansion is rejected/bounded."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-05",
      "scenario" => "Valid policy reload under concurrent calls and ownership changes.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Readers observe coherent generations; caches cannot preserve an obsolete unauthorized grant."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-06",
      "scenario" => "Invalid reload and unavailable initial config.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Reload retains valid policy; invalid initial state does not report ready or accept privileged work."
          ]
        }
      ]
    },
    %{
      "required_id" => "POL-07",
      "scenario" =>
        "Required MAC directives/security metadata on supported and unsupported deployment profiles.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No fabricated label, disabled enforcement, or unsupported-profile success claim."
          ]
        }
      ]
    },
    %{
      "required_id" => "API-01",
      "scenario" =>
        "UID/PID/credential queries for unique/well-known/bus names and vanished connections.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct live identity and errors; no PID-reuse substitution or asserted credential leakage."
          ]
        }
      ]
    },
    %{
      "required_id" => "API-02",
      "scenario" =>
        "Peer.Ping/GetMachineId, GetId, introspection, Properties, and unsupported methods/features.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Real implementations and accurate advertised feature set; machine ID and bus-instance ID are not conflated."
          ]
        }
      ]
    },
    %{
      "required_id" => "API-03",
      "scenario" =>
        "Privileged reload/monitor/environment-control requests from ordinary and authorized actors.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Policy-appropriate effect/error; disabled capabilities not falsely advertised."
          ]
        }
      ]
    },
    %{
      "required_id" => "API-04",
      "scenario" =>
        "Account groups differ from process groups; peer exits while metadata is queried.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "independent-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Documented trusted group/snapshot semantics and race-safe failure; no privilege granted from stale process metadata."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-01",
      "scenario" =>
        "Unowned activatable destination receives an allowed call or StartServiceByName.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Exactly the intended service starts; caller receives correct eventual response and owned-name identity."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-02",
      "scenario" => "Several callers request the same service; requests include NO_AUTO_START.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Coalesced authorized launch, correct no-start behavior, bounded independent deadlines."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-03",
      "scenario" => "Denied call/activation or launch identity violation.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Service never starts under an unauthorized/default root identity; no queued unauthorized delivery."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-04",
      "scenario" =>
        "Service missing, Exec failure, timeout, service exits before name acquisition.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => ["Correct error/disposition and full queue/pending-call/FD cleanup."]
        }
      ]
    },
    %{
      "required_id" => "ACT-05",
      "scenario" =>
        "SystemdService activation and traditional Exec/User entries required by the profile.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct bootstrap path, identity and name readiness; no shell interpolation or circular bus startup wait."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-06",
      "scenario" => "Name acquisition race, policy reload while activating, and caller exit.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Actual destination/current policy used at delivery; obsolete callers/resources retired."
          ]
        }
      ]
    },
    %{
      "required_id" => "ACT-07",
      "scenario" => "Service-file precedence/listing/config reload and activation request flood.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct selected service and ListActivatableNames, bounded launch work and diagnostics."
          ]
        }
      ]
    },
    %{
      "required_id" => "SYS-01",
      "scenario" => "Inherit a real listening Unix FD through the final release startup chain.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "PID/environment validation, correct socket type, usable listener, descriptor ownership and no child leakage."
          ]
        }
      ]
    },
    %{
      "required_id" => "SYS-02",
      "scenario" =>
        "Existing foreign socket, symlink/non-socket path, stale ambiguous path, and shutdown.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "No deletion of another instance's endpoint or unrelated file; only owned endpoints are removed."
          ]
        }
      ]
    },
    %{
      "required_id" => "SYS-03",
      "scenario" => "Minimal release startup/shutdown without Phoenix/config/cluster.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Ready only after policy and authority are usable; no unexpected HTTP/distribution listener or bootstrap dependency."
          ]
        }
      ]
    },
    %{
      "required_id" => "SYS-04",
      "scenario" =>
        "Wrong/missing inherited FDs, invalid config, activation-bootstrap fault, and restart.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Safe failure or documented standalone mode; no misleading readiness or daemon-owned unlink of manager socket."
          ]
        }
      ]
    },
    %{
      "required_id" => "SYS-05",
      "scenario" =>
        "Reload, graceful stop, restart with manager-owned listener, and finite shutdown timeout.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct cleanup and observed reconnect behavior; listener ownership and bus epochs remain coherent."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-01",
      "scenario" =>
        "Boot identical pinned reference and OS-Bus variants and run independent probes.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Actual daemon identity/socket verified; no test silently talking to the reference bus or a private substitute."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-02",
      "scenario" =>
        "Real systemd API, logind session/identity operations, and polkit allowed/denied requests.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Unmodified services work and deny appropriately for multiple real UIDs; not just ListNames success."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-03",
      "scenario" =>
        "Real automatic activation and FD workload, including a logind inhibitor descriptor where supported by the chosen profile.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct service identity/authorization and usable/closed FD; limits/resources recover."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-04",
      "scenario" => "NetworkManager virtual-device workload in the declared network profile.",
      "profiles" => ["network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Authorized operations work, denied operations remain denied, and reference/OS-Bus behavior is compatible."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-05",
      "scenario" =>
        "Policy reload, faulty clients, overload, service failure, and bus-core restart in the full VM.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Correct containment or documented reconnect/recovery, no policy bypass or resource leak."
          ]
        }
      ]
    },
    %{
      "required_id" => "VM-06",
      "scenario" =>
        "Candidate \u2192 known-good reference rollback using a boot generation or snapshot.",
      "profiles" => ["core", "network"],
      "subcases" => [
        %{
          "subcase_id" => "complete-requirement",
          "backends" => ["reference", "gao_bus"],
          "layer" => "installed-system",
          "actors" => ["independent_client", "external_observer"],
          "invariants" => [
            "Reference endpoint/daemon confirmed; same workload and denial checks pass after rollback; artifacts retained."
          ]
        }
      ]
    }
  ]

  def catalogue, do: @catalogue
  def test_plan_path, do: @plan
  def sha256(path), do: :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)

  def empty_map do
    rows =
      for requirement <- @catalogue,
          subcase <- requirement["subcases"],
          backend <- subcase["backends"],
          profile <- requirement["profiles"] do
        %{
          "required_id" => requirement["required_id"],
          "subcase_id" => subcase["subcase_id"],
          "source_scenario_id" => nil,
          "backend" => backend,
          "profile" => profile,
          "requirements" => Map.take(subcase, ["layer", "actors", "invariants"]),
          "coverage_scope" => requirement["required_id"] <> "/" <> subcase["subcase_id"],
          "record_ref" => nil,
          "block" => %{
            "kind" => "unmapped_requirement",
            "reason" => "No authenticated complete current observation mapped."
          },
          "retained_evidence" => []
        }
      end

    %{
      "index_schema" => 1,
      "catalogue_version" => 1,
      "test_plan_sha256" => @plan_hash,
      "rows" => rows
    }
  end

  def build(root, evidence_map, profile) do
    try do
      check!(profile in ["core", "network"], "unknown profile")

      check!(
        evidence_map["index_schema"] == 1 and evidence_map["catalogue_version"] == 1,
        "schema version"
      )

      check!(
        evidence_map["test_plan_sha256"] == @plan_hash and
          sha256(safe_path!(root, @plan)) == @plan_hash,
        "test plan binding"
      )

      check!(!Map.has_key?(evidence_map, "counts"), "supplied counts are not accepted")
      rows = evidence_map["rows"]
      check!(is_list(rows), "combination catalogue absent")
      keys = Enum.map(rows, &key/1)
      check!(Enum.uniq(keys) == keys, "duplicate combination")

      check!(
        Enum.sort(keys) == Enum.sort(Enum.map(empty_map()["rows"], &key/1)),
        "combination catalogue missing/unknown ID, subcase, backend or profile"
      )

      canonical = Map.new(empty_map()["rows"], &{key(&1), &1})

      validated =
        Enum.map(rows, fn row ->
          expected = canonical[key(row)]

          check!(
            row["requirements"] == expected["requirements"] and
              row["coverage_scope"] == expected["coverage_scope"],
            "requirements/coverage declaration"
          )

          check!(
            is_binary(row["source_scenario_id"]) or
              (is_nil(row["source_scenario_id"]) and is_map(row["block"]) and
                 is_binary(row["block"]["reason"])),
            "source scenario or explicit block"
          )

          retained = Enum.map(row["retained_evidence"] || [], &retained!(root, &1))
          record = if row["record_ref"], do: record!(root, row, rows, canonical), else: nil

          check!(
            record != nil or
              (is_map(row["block"]) and is_binary(row["block"]["kind"]) and
                 is_binary(row["block"]["reason"])),
            "explicit blocker absent"
          )

          %{row: row, record: record, retained: retained}
        end)

      selected = Enum.filter(validated, &(&1.row["profile"] == profile))
      expected = Enum.map(selected, &adapt_expected(&1.row))
      observed = Enum.map(selected, &adapt_observed/1)
      evaluation = Qualification.evaluate(expected, observed)
      qualification = Qualification.report(expected, observed, phase: :offline_required_index)

      id_rows =
        Enum.map(@catalogue, fn row ->
          branches = Enum.filter(qualification.outcomes, &(&1.required_id == row["required_id"]))

          status =
            cond do
              branches == [] -> :out_of_scope
              Enum.any?(branches, &(&1.status == :failed)) -> :failed
              Enum.any?(branches, &(&1.status == :blocked)) -> :blocked
              true -> :passed
            end

          %{
            required_id: row["required_id"],
            status: status,
            reason: if(status == :out_of_scope, do: "network_profile", else: nil),
            branches: branches
          }
        end)

      records =
        Enum.flat_map(selected, fn v ->
          if(v.record, do: [v.record], else: []) ++ v.retained
        end)

      unique = Enum.uniq_by(records, &{&1.run_id, &1.path})
      check_run_bindings!(records)

      result = %{
        index_schema: 1,
        catalogue_version: 1,
        test_plan_sha256: @plan_hash,
        profile: profile,
        index_integrity: :passed,
        product_qualified: evaluation == :ok and qualification.result == :ok,
        runtime_execution: %{broker: 0, vm: 0},
        readiness: "L0",
        rows: id_rows,
        id_counts: %{
          catalogue: 89,
          selected: length(id_rows) - Enum.count(id_rows, &(&1.status == :out_of_scope)),
          passed: Enum.count(id_rows, &(&1.status == :passed)),
          failed: Enum.count(id_rows, &(&1.status == :failed)),
          blocked: Enum.count(id_rows, &(&1.status == :blocked)),
          out_of_scope: Enum.count(id_rows, &(&1.status == :out_of_scope))
        },
        combination_counts: qualification.counts,
        qualification: qualification,
        evidence_counts: %{
          unique_runs: records |> Enum.map(& &1.run_id) |> Enum.uniq() |> length(),
          unique_artifacts: length(unique),
          current: Enum.count(unique, &(&1.currency == "current")),
          historical: Enum.count(unique, &(&1.currency == "historical")),
          partial: Enum.count(unique, &(&1.currency == "partial"))
        },
        observations:
          Enum.flat_map(selected, fn v -> if(v.record, do: [v.record], else: []) ++ v.retained end),
        accounting: Enum.map(selected, & &1.row)
      }

      {:ok, result}
    rescue
      error in [ArgumentError, KeyError, File.Error, Jason.DecodeError] ->
        {:error, Exception.message(error)}
    end
  end

  defp record!(root, row, rows, canonical) do
    ref = row["record_ref"]
    receipt = root |> artifact!(ref) |> File.read!() |> Jason.decode!()
    observations = receipt["observations"]
    check!(is_list(observations) and observations != [], "unique observation absent")
    observation_keys = Enum.map(observations, &key/1)
    check!(Enum.uniq(observation_keys) == observation_keys, "unique observation conflicts")
    check!(is_integer(ref["selector"]) and ref["selector"] >= 0, "structured selector")
    observation = Enum.at(observations, ref["selector"])

    check!(
      is_map(observation) and key(observation) == key(row),
      "unique observation selection identity"
    )

    # Check every identity/reference first, even if the chosen observation is valid.
    mapped =
      Enum.with_index(observations, fn observation, index ->
        check!(
          Map.has_key?(canonical, key(observation)),
          "undeclared receipt observation: #{inspect(key(observation))}"
        )

        mapped_row = Enum.find(rows, &(key(&1) == key(observation)))

        check!(
          mapped_row["record_ref"] == Map.put(ref, "selector", index),
          "unreferenced receipt observation: #{inspect(key(observation))}"
        )

        {mapped_row, observation}
      end)

    validated =
      Enum.map(mapped, fn {mapped_row, observation} ->
        validate_observation!(root, mapped_row, receipt, observation)
      end)

    Enum.at(validated, ref["selector"])
  end

  defp validate_observation!(root, row, receipt, observation) do
    ref = row["record_ref"]
    check!(observation["coverage_scope"] == row["coverage_scope"], "observation coverage")

    check!(
      observation["status"] in ["passed", "failed", "blocked", "skipped"],
      "observation status"
    )

    check!(receipt["currency"] in ["current", "historical", "partial"], "currency declaration")
    bindings = receipt["bindings"] || []

    required_kinds =
      ["source", "test", "fixture", "config"] ++
        if(row["requirements"]["layer"] == "installed-system", do: ["package"], else: [])

    check!(
      Enum.all?(required_kinds, fn kind -> Enum.any?(bindings, &(&1["kind"] == kind)) end),
      "required source/test/fixture/config/package binding absent"
    )

    Enum.each(bindings, fn binding ->
      check!(
        binding["before_sha256"] == binding["sha256"] and
          binding["after_sha256"] == binding["sha256"],
        "before/after binding drift: #{binding["path"]}"
      )

      if receipt["currency"] == "current",
        do:
          check!(
            sha256(safe_path!(root, binding["path"])) == binding["sha256"],
            "current binding drift: #{binding["path"]}"
          )
    end)

    identity = receipt["identity"] || %{}

    check!(
      identity["backend"] == row["backend"] and identity["profile"] == row["profile"],
      "backend/profile identity"
    )

    actors = observation["actors_executed"] || []
    required_actors = row["requirements"]["actors"]

    if observation["status"] == "passed" do
      check!(
        actors != [] and Enum.all?(required_actors, &(&1 in actors)),
        "missing actor execution"
      )
    end

    check!(Enum.all?(actors, &(&1 in (identity["actors"] || []))), "actor identity receipt")
    config = Enum.find(bindings, &(&1["kind"] == "config"))
    backend_receipt = receipt["backend_receipt"] || %{}

    check!(
      backend_receipt["backend"] == row["backend"] and
        backend_receipt["profile"] == row["profile"] and
        is_integer(backend_receipt["pid"]) and backend_receipt["pid"] > 0 and
        is_binary(backend_receipt["version"]) and
        backend_receipt["config_sha256"] == config["sha256"],
      "backend identity/config receipt"
    )

    if receipt["currency"] == "current" and row["requirements"]["layer"] != "pure" and
         receipt["scope"] == row["requirements"]["layer"],
       do: check!(backend_receipt["independent"] == true, "independent backend identity required")

    Enum.each(actors, fn actor ->
      matching = Enum.filter(receipt["actor_receipts"] || [], &(&1["actor"] == actor))
      check!(length(matching) == 1, "unique actor identity receipt")
      [actor_receipt] = matching

      check!(
        actor_receipt["backend"] == row["backend"] and actor_receipt["profile"] == row["profile"] and
          actor_receipt["executed"] == true and is_integer(actor_receipt["pid"]) and
          actor_receipt["pid"] > 0 and
          is_integer(actor_receipt["uid"]) and actor_receipt["uid"] >= 0 and
          actor_receipt["config_sha256"] == config["sha256"],
        "actor identity/config receipt"
      )
    end)

    command = receipt["command"] || %{}

    check!(
      is_list(command["argv"]) and command["argv"] != [] and is_binary(command["cwd"]) and
        is_integer(command["exit"]) and is_integer(command["teardown_exit"]) and
        is_integer(command["log_failures"]) and command["log_failures"] >= 0,
      "command/teardown receipt"
    )

    reconcile_counts!(receipt, receipt["observations"])
    check!(is_binary(receipt["run_id"]) and receipt["run_id"] != "", "run identity")

    assertion_evidence = assertion_evidence!(root, row, receipt, observation, bindings)

    %{
      path: ref["path"],
      sha256: ref["sha256"],
      run_id: receipt["run_id"],
      currency: receipt["currency"],
      scope: receipt["scope"],
      observation: observation,
      assertion_evidence: assertion_evidence,
      assertion_failed: Enum.any?(assertion_evidence, &(&1["status"] == "failed")),
      command: command,
      bindings: bindings,
      source_scenario_id: row["source_scenario_id"],
      qualifies:
        receipt["currency"] == "current" and receipt["scope"] == row["requirements"]["layer"]
    }
  end

  # Witnesses are saved equality measurements, not a general assertion engine.
  # These checks establish local consistency; they cannot prove adversarial authenticity.
  defp assertion_evidence!(root, row, receipt, observation, bindings) do
    scenario = row["source_scenario_id"]

    check!(
      is_binary(scenario) and scenario != "" and observation["source_scenario_id"] == scenario,
      "source scenario binding"
    )

    source_ref = observation["source_ref"] || %{}
    source_path = artifact!(root, source_ref)
    source = File.read!(source_path)

    binding =
      Enum.find(
        bindings,
        &(&1["path"] == source_ref["binding_path"] and &1["kind"] in ["test", "fixture"])
      )

    check!(
      binding != nil and binding["sha256"] == source_ref["sha256"],
      "source scenario test/probe binding"
    )

    check!(
      is_binary(source_ref["excerpt"]) and source_ref["excerpt"] != "" and
        String.contains?(source, source_ref["excerpt"]) and
        String.contains?(source_ref["excerpt"], scenario),
      "source scenario excerpt"
    )

    assertions = observation["assertions"] || []

    check!(
      is_list(assertions) and
        Enum.sort(Enum.map(assertions, & &1["invariant"])) ==
          Enum.sort(row["requirements"]["invariants"]),
      "invariant assertion catalogue missing, duplicate or mismatched"
    )

    Enum.map(assertions, fn assertion ->
      ref = assertion["record_ref"] || %{}
      path = artifact!(root, ref)
      check!(is_list(ref["selector"]), "assertion structured selector")
      witness = path |> File.read!() |> Jason.decode!() |> select!(ref["selector"])

      check!(
        is_map(witness) and key(witness) == key(row) and
          witness["coverage_scope"] == row["coverage_scope"] and
          witness["source_scenario_id"] == scenario and witness["run_id"] == receipt["run_id"] and
          witness["invariant"] == assertion["invariant"] and
          witness["source_sha256"] == source_ref["sha256"],
        "assertion identity/invariant/source binding"
      )

      check!(
        witness["executed"] == true and witness["actor"] in observation["actors_executed"] and
          is_binary(witness["assertion_source"]) and witness["assertion_source"] != "" and
          String.contains?(source, witness["assertion_source"]),
        "assertion execution/source excerpt"
      )

      check!(
        is_map(witness["expected"]) and map_size(witness["expected"]) > 0 and
          is_map(witness["actual"]) and map_size(witness["actual"]) > 0,
        "assertion measurements absent"
      )

      check!(
        witness["status"] in ["passed", "failed"] and
          (witness["status"] == "failed" or witness["expected"] == witness["actual"]),
        "assertion outcome contradicts measurements"
      )

      witness
    end)
  end

  defp retained!(root, ref) do
    path = artifact!(root, ref)

    check!(
      ref["currency"] in ["historical", "partial"],
      "retained evidence cannot claim current qualification"
    )

    check!(
      is_binary(ref["reason"]) and ref["reason"] != "" and is_binary(ref["run_id"]),
      "retained provenance reason/run"
    )

    check!(ref["disposition"] in ["failed", "partial", "historical"], "retained disposition")

    if ref["selector"] do
      value = path |> File.read!() |> Jason.decode!() |> select!(ref["selector"])
      check!(value == ref["value"], "retained structured observation mismatch")
    else
      check!(
        is_binary(ref["text"]) and String.contains?(File.read!(path), ref["text"]),
        "retained exact text observation"
      )
    end

    ref
    |> Map.drop(["path", "sha256", "run_id", "currency"])
    |> Map.merge(%{
      path: ref["path"],
      sha256: ref["sha256"],
      run_id: ref["run_id"],
      currency: ref["currency"]
    })
  end

  defp select!(value, []), do: value

  defp select!(value, [index | tail]) when is_list(value) and is_integer(index) do
    check!(index >= 0 and index < length(value), "invalid structured selector")
    select!(Enum.at(value, index), tail)
  end

  defp select!(value, [key | tail]) when is_map(value), do: select!(Map.fetch!(value, key), tail)
  defp select!(_, _), do: raise(ArgumentError, "invalid structured selector")

  defp reconcile_counts!(receipt, rows) do
    counts = %{
      "selected" => length(rows),
      "executed" => Enum.count(rows, &((&1["actors_executed"] || []) != [])),
      "passed" => Enum.count(rows, &(&1["status"] == "passed")),
      "failed" => Enum.count(rows, &(&1["status"] == "failed")),
      "blocked" => Enum.count(rows, &(&1["status"] == "blocked")),
      "skipped" => Enum.count(rows, &(&1["status"] == "skipped"))
    }

    check!(receipt["counts"] == counts, "inconsistent receipt counts")
  end

  defp adapt_expected(row) do
    %{
      e2e_id: row["required_id"] <> "/" <> row["subcase_id"],
      required_id: row["required_id"],
      subcase_id: row["subcase_id"],
      backend: row["backend"],
      profile: row["profile"],
      actors: row["requirements"]["actors"],
      actors_executed: []
    }
  end

  defp adapt_observed(value) do
    row = adapt_expected(value.row)
    failed_retained = Enum.any?(value.retained, &(&1["disposition"] == "failed"))
    record = value.record

    status =
      cond do
        failed_retained ->
          :failed

        record &&
            (record.observation["status"] == "failed" or record.assertion_failed or
               record.command["exit"] != 0 or
               record.command["teardown_exit"] != 0 or record.command["log_failures"] > 0) ->
          :failed

        record && record.qualifies && record.observation["status"] == "passed" ->
          :passed

        record && record.observation["status"] == "skipped" ->
          :skipped

        true ->
          :blocked
      end

    Map.merge(row, %{
      status: status,
      actors_executed: if(record, do: record.observation["actors_executed"], else: []),
      reason: value.row["block"],
      partial_observation: if(record, do: record.observation, else: nil),
      retained_evidence: value.retained
    })
  end

  defp check_run_bindings!(records) do
    Enum.each(Enum.group_by(records, & &1.run_id), fn {_run, values} ->
      by_path = Enum.group_by(values, & &1.path)

      Enum.each(by_path, fn {_path, refs} ->
        check!(
          length(Enum.uniq(Enum.map(refs, & &1.sha256))) == 1,
          "conflicting run artifact bindings"
        )
      end)
    end)
  end

  defp key(row), do: {row["required_id"], row["subcase_id"], row["backend"], row["profile"]}

  defp artifact!(root, ref) do
    path = safe_path!(root, ref["path"])
    check!(sha256(path) == ref["sha256"], "artifact hash drift: #{ref["path"]}")
    path
  end

  defp safe_path!(root, relative) do
    check!(
      is_binary(relative) and Path.type(relative) == :relative,
      "relative evidence path required"
    )

    parts = Path.split(relative)
    check!(parts != [] and not Enum.any?(parts, &(&1 in ["..", "."])), "unsafe evidence path")

    Enum.reduce(parts, Path.expand(root), fn part, path ->
      next = Path.join(path, part)
      check!(File.lstat!(next).type != :symlink, "symlink evidence path")
      next
    end)
  end

  defp check!(true, _message), do: :ok
  defp check!(_, message), do: raise(ArgumentError, message)
end
