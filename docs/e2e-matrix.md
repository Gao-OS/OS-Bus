# OS-Bus E2E Matrix

Selection manifest version 1 preserves these IDs and their session-profile actors. Strict qualification requires every selected `(ID, backend, actor, session)` combination; the historical verification notes below are not a current gate result. Read the retained qualification report for actual execution and per-backend outcomes.

| Selected gate | Required IDs per backend | Selection |
| --- | --- | --- |
| smoke | 4 | E2E-001–004 |
| release | 16 | smoke plus the 12 release rows |
| compat | 19 | release plus E2E-012–014 |
| stress / all | 20 | compat plus E2E-015 |

The 27 older numbered E2E cases run separately as preserved reference regressions. Their results are not Gao backend execution. System-security and real-UID qualification are separate foundation gates; passing this session manifest makes no system-bus replacement claim.

| ID | Group | Gate | Scenario | Actors | Backends | Expected |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-001 | hello | smoke | client can connect and call Hello | ExDBus | reference, gao_bus | unique name starts with :1. |
| E2E-002 | bus | smoke | ListNames includes org.freedesktop.DBus | ExDBus | reference, gao_bus | name present |
| E2E-003 | names | smoke | RequestName returns primary owner | ExDBus | reference, gao_bus | primary owner |
| E2E-004 | names | smoke | ReleaseName removes owner | ExDBus | reference, gao_bus | name not owned |
| E2E-005 | methods | release | ExDBus calls GLib Echo | ExDBus, GLib-fixture | reference, gao_bus verified (2026-07-07) — gap fixed: bare AUTH now gets `REJECTED <mechanisms>`; EXTERNAL supports Linux bare-DATA transport-credential flow; NameAcquired/NameLost unicast signals emitted | returns same string |
| E2E-006 | methods | release | busctl calls Elixir Echo | busctl, Elixir-service | reference, gao_bus — busctl verified in Linux CI | returns same string |
| E2E-007 | methods | release | gdbus calls Elixir Add | gdbus, Elixir-service | reference, gao_bus verified (2026-07-07) — SASL mechanism-discovery gap fixed | returns integer sum |
| E2E-008 | errors | release | unknown method returns D-Bus error | ExDBus, service | reference, gao_bus verified | UnknownMethod |
| E2E-009 | errors | release | GLib AlwaysFail propagates error | ExDBus, GLib-fixture | reference, gao_bus verified (2026-07-07) — inherited E2E-005 auth/name-signal gaps fixed, including Linux bare-DATA EXTERNAL flow | Failed |
| E2E-010 | signals | release | AddMatch receives matching signal | ExDBus, GLib-fixture | reference, gao_bus verified (2026-07-07) — inherited E2E-005 auth/name-signal gaps fixed, including Linux bare-DATA EXTERNAL flow | signal received |
| E2E-011 | signals | release | unmatched signal is not delivered | ExDBus, GLib-fixture | reference, gao_bus verified (2026-07-07) — inherited E2E-005 auth/name-signal gaps fixed, including Linux bare-DATA EXTERNAL flow | no signal |
| E2E-012 | introspection | compat | busctl introspects Elixir service | busctl, Elixir-service | reference, gao_bus — busctl verified in Linux CI | XML contains interface |
| E2E-013 | properties | compat | gdbus Get property from GLib fixture | gdbus, GLib-fixture | reference, gao_bus implemented — verification pending host/CI | CurrentValue returned |
| E2E-014 | properties | compat | gdbus Set property on GLib fixture | gdbus, GLib-fixture | reference, gao_bus implemented — verification pending host/CI | value changed |
| E2E-015 | concurrency | stress | concurrent calls demux correctly | ExDBus, GLib-fixture | reference, gao_bus implemented — verification pending host/CI | all replies match serial |
| E2E-016 | failure | release | service disconnect cleans owned name | ExDBus, GLib-fixture | reference, gao_bus implemented — verification pending host/CI | NameOwnerChanged emitted |
| E2E-017 | failure | release | client disconnect does not crash bus | ExDBus | reference, gao_bus implemented — verification pending host/CI | bus remains responsive |
| E2E-018 | routing | release | method call to missing destination returns error | ExDBus | reference, gao_bus implemented — verification pending host/CI | ServiceUnknown |
| E2E-019 | bus | release | GetNameOwner works after RequestName | ExDBus | reference, gao_bus implemented — verification pending host/CI | owner unique name |
| E2E-020 | bus | release | NameHasOwner reflects ownership | ExDBus | reference, gao_bus implemented — verification pending host/CI | true/false transitions |
