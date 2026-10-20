# Ordinary legacy-private-fixture UID-name cleanup on the current frozen candidate.
# The imported fixture and its policy, assertions, helpers and deadlines are unchanged.
import ../m1_uid_abrupt_peer/test.nix {
  candidatePath = "/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation/test/reports/foundation/resume-20261019/sec17-xml-preparation1/normalized/candidate";
  candidateManifestSha256 = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
  candidateSourceSha256 = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
  selection = "uid_names";
}
