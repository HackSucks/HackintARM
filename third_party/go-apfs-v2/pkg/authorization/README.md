# Captured Darwin filesystem authorization

`authorization` evaluates discretionary filesystem permissions using explicitly
captured Darwin credentials, ACLs, file attributes and mount context. It lets a
Linux or Windows consumer decide the same source operation without substituting
the receiving host's accounts, permission bits or filesystem capabilities.

Use this package when a foreign operation must resolve a source pathname or
create, remove or rename an entry. Transporting an ACL without evaluating it is
the responsibility of `appledouble` and `metatransport`. Performing an actual
receiving-host filesystem operation remains the caller's responsibility.

## Inputs and operation boundaries

`New` requires an explicit macOS 15, 26 or 27 target and a captured `Authority`.
The authority includes effective UID, complete numeric groups, UUID membership
results when consulted, and an observed process permission policy. A nonnil
`ProcessPolicy{}` records only ordinary node-permission policy. Its `LongPaths`
field remains unknown until set from an observed effective process/thread policy.
A nil process policy means node-permission policy was not captured. An entitlement in an executable does not prove that its process enabled
an override.

Each `Node` supplies observed ownership, complete mode and BSD flags, logical
inode identity, and its own mount identity, filesystem and flags. Path lookup also
requires `Mount.CaseSensitive` from observed volume capabilities; nil means
unknown. Already-resolved permission checks do not need name-comparison policy.
 ACL observation
has three states: `SecurityUncaptured`, `SecurityAbsent` and `SecurityPresent`.
Absence must be established by source observation. A nil ACL from an incomplete
extraction is not evidence of absence.

| Method | Permission boundary |
| --- | --- |
| `Search` | Traverse an already identified directory; read-only mounts do not prohibit search |
| `Create` | Add a file or subdirectory to an already resolved parent |
| `Delete` | Remove an entry, combining leaf DELETE, parent DELETE_CHILD, flags and sticky ownership |
| `Rename` | Authorize already resolved source/destination entries, including mount identity and replacement deletion |

These methods preserve ordered ACL decisions and POSIX fallback. Search of all
actual path components is a separate prerequisite for mutation methods. The
methods do not perform lookup, resolve symbolic links, infer missing ancestors,
or change any filesystem. `recompression.RecompressPath` supplies this lookup
integration for a carrier's original namespace.

`ErrAuthority` identifies missing observations. It is distinct from a captured
native permission denial such as `EACCES`, `EPERM` or `EROFS`. Callers must not
convert unknown context into a grant or a fabricated native denial.

## Obtaining observations

Carrier extraction with source xattrs enabled records
`Record.SourceAttributesCaptured` only after complete successful enumeration.
`Store.ObservedSourceAttribute` distinguishes an observed absence from an old or
incomplete carrier. `recompression.CapturedPathObservation` maps the selected
source Security attribute into a path observation; the caller additionally
supplies actual source mount and logical inode context. Neither helper reads the
receiver's metadata as source evidence.

Older manifests load with `SourceAttributesCaptured=false`. They need a genuine
source recapture before this helper can establish absence. New manifests using
this field require an updated reader: older readers deliberately reject unknown
manifest fields. This is an additive reader change, not bidirectional file-format
compatibility.

## Evidence and scope

The research harness executes independent C syscalls, retains complete outputs,
binds source/SDK hashes and both Clang target ASTs, and compares the portable
evaluator with native macOS observations. Full Apple XNU sources are pinned with
licenses. Source-policy extraction and executable oracle behavior are different
evidence; neither substitutes for the other.

Qualification is in progress. All specified ownership, mount, directory and
process-context controls must be captured and replayed on macOS 15, 26 and 27;
portable replay and package/per-file coverage gates remain mandatory. The local
ordinary process rejects enabling the private owner-permission override, and an
ad-hoc executable carrying that private entitlement is rejected before entry.
The enabled override is source-backed and unit-tested, but those observations do
not qualify a successful native enabled process.

This evaluator does not emulate external MAC/sandbox decisions, change host
privileges, or claim that discretionary permission success guarantees an entire
filesystem operation will succeed. Consumers retain operation order, actual I/O,
partial failures and publication handling.

## Path-length process observation

Path-aware recompression additionally requires `ProcessPolicy.LongPaths`.
Capture both native process and thread support-long-paths getters, check their
success, and combine their enabled values as XNU does. For example, after a
capture has actually reported both disabled:

```go
observedLongPaths := false // established by the successful source getters
policy := authorization.ProcessPolicy{
    IgnoreNodePermissions: false, // separately observed ordinary node policy
    LongPaths: &observedLongPaths,
}
```

This is source process context, not a setting derived from the receiving host.
Ordinary policy admits up to 1023 pathname bytes plus the terminating NUL;
enabled policy selects the 8192-byte allocation limit. The native
corpus retains unsuccessful private enable attempts as failures. Enabled-policy
unit controls do not claim a successful native entitled observation. Already-held
endpoint operations do not require a pathname-length observation.
