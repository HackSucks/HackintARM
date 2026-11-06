# Recompression

`recompression` applies the qualified macOS compression operation to an explicit
foreign metadata record on Linux, macOS or Windows. Use it after editing a file
extracted with a metadata carrier, when an operation must recompress the logical
Darwin file rather than merely preserve its original compressed bytes.

The materialized payload remains ordinary, readable data on every host. Its
Darwin compression attribute, resource fork, flags, ownership and timestamps live
in the selected carrier. Repacking that carrier produces actual compressed APFS
or HFS+ storage. Receiving-host account IDs and filesystem capabilities never
choose the foreign identity, target macOS release or mount policy.

## Package responsibilities

| Package | Responsibility |
| --- | --- |
| `authorization` | Explicit captured credentials, ordered Darwin ACL/POSIX search and namespace permission decisions |
| `recompression` | Path-aware foreign operation integration, endpoint permission checks, private staging, logical inode transitions and hard-link outcomes |
| `metatransport` | Held payload access, immutable blobs, association checks, generation locks and publication |
| `hostdata` | Shared compression lifecycle and native held-file operations |
| `compression/decmpfs` | Encoding and decoding compression storage |
| `osversion` | Explicit macOS product versions and qualified behavior profiles |

The existing `hostdata.Recompress` and installation APIs retain their published
contracts. Carrier storage has no dependency on compression policy. This boundary
lets codesign reuse the shared operation instead of implementing its own metadata
transport or compression lifecycle.

## Selecting a path or an acquired endpoint

Use `RecompressPath` when the operation starts from a source pathname. Bind
explicit observations with `NewPathContext` to the selected Store, manifest and
generation, then supply this context through `PathOptions`. The resolver checks
every directory actually traversed, including symbolic-link and dot-component
traversal, before entering the same endpoint lifecycle. Missing ancestor or leaf
security observations produce `ErrAuthority`; they never bypass lookup checks.

`PathCapture.Root` identifies the captured original directory. `FilesystemRoot`
explicitly establishes a root for absolute link targets. `Complete` declares
that missing entries really are absent; otherwise missing names remain unknown.
Mount observations belong to the logical source and may differ along the path.
A changed manifest requires a new context, even if another store happens to use
the same generation number. Path-aware calls also require an explicitly observed
`Authority.Process.LongPaths` value; a nonnil `ProcessPolicy{}` alone is
insufficient. See the [captured process example](../authorization/README.md#path-length-process-observation).
The original input length is checked before directory search; symlink expansion
preserves native trailing-slash and error-order distinctions. Enabled long-path
behavior is source-backed until a successful native entitled context is qualified.

For each source record, `CapturedPathObservation` can derive ACL presence or
absence through `Store.ObservedSourceAttribute`. It requires complete successful
source-attribute enumeration, recorded as `SourceAttributesCaptured`. The caller
still provides actual logical mount and inode context. Older carriers without
this flag remain explicitly uncaptured. New manifests containing it require an
updated reader because old readers reject unknown fields.

`RecompressRecord` is the pre-resolved, caller-authorized endpoint API. It checks
the leaf operation but cannot establish parent search authorization or prove
that absent source ACL data was observed. Use it only when those prerequisites
have already been established by the caller; it is not a fallback for incomplete
path context.

The namespace integration is still being qualified for mounted filesystem name
comparison, path limits and the full native operation corpus. A successful unit
test does not qualify those unresolved native behaviors.

## Calling the endpoint operation

```go
result, err := recompression.RecompressRecord(ctx, store, originalName, generation,
    recompression.Options{
        Target:              targetMacOSVersion,
        Authority:           &capturedDarwinAuthority,
        Volume:              &capturedDarwinVolume,
        Encoding:            encoding,
        TemporaryDirectory:  privateStagingParent,
        AllowChangedPayload: true,
    })
```

`Target` must select a supported macOS 15, 26 or 27 behavior profile. `Authority`
supplies the effective UID, complete numeric groups and required UUID membership
observations. `Volume` supplies the actual `apfs` or `hfs` filesystem name and
mount flags, including an explicitly observed zero. See
[foreign authority and native evidence](../../docs/recompression-authority.md).
Missing context does not default to the receiving host or the newest macOS.

The record must describe a regular logical and materialized file with a content
baseline, mode, BSD flags, ownership, modification time and access time. Optional
birth and change times are retained. `AllowChangedPayload` explicitly accepts
intentional data edits and establishes a new baseline. It never permits corrupt
old compressed storage to be silently reinterpreted as the edited content.

The caller keeps the store open and excludes uncoordinated changes to payloads,
metadata and namespace for the operation's lifetime. Ordinary host permissions
still control access to that storage. The scoped Darwin evaluator does not grant
host privileges. Path-aware calls require an explicit observed process policy;
the same captured policy reaches endpoint authorization. External sandbox/MAC
hooks remain outside the discretionary evaluator. Enabled private owner overrides
are source-backed controls with an explicit outstanding native-qualification
constraint; see [authorization](../authorization/README.md).

## Outcomes and failures

`Operation` preserves queue admission separately from compression success.
`Published` reports installation of the new manifest generation. Check the
returned error even when either field indicates success: publication or cleanup
can fail after the compression protocol accepted the work. `Record` retains the
proposed resulting state; `Generation` advances only after manifest publication.

A write-open can decompress existing active storage before later compression
eligibility is decided. Inline storage preserves an independent resource fork;
fork-backed compression removes only the fork owned by that storage. The logical
operation retains permission retries, timestamp precision, content-policy declines
and native-permitted partial storage. Logical hard-link aliases are checked and
updated together, including copies used to materialize links on another host.

Cancellation before destructive transitions stops normally. After logical data
truncation, publication uses a noncancelable context to retain the resulting
state before reporting cancellation. Surviving immutable attributes are
reacquired through the public carrier API; generated storage is kept separately.
Private staging is closed and removed on every path. Unreferenced immutable blobs
retain the carrier's existing cleanup contract.

Manifest publication is not whole-tree atomicity. Payload write/truncate failures,
manifest rename errors and cleanup failures remain observable. Failed publication
can leave changed payloads conflicting with the previous baseline; it cannot make
stale compressed bytes authoritative again. Hashing, copying and compression
storage validation use bounded reads rather than whole-resource-fork buffers.

## Qualification and remaining integration

The mandatory harness replays 648 retained native-profile cases, adds 72 replacement-composition cases, produces nine
APFS/HFS+ images with 846 entries on each host and reads each producer's images
through the native macOS kernel. Native access probes retain 168 independent
operations and two LZ4 write-open controls per captured release, with arm64 and
x86_64 Clang ASTs. Existing lifecycle, codec and resource-fork gates remain active.
All three complete packages (`authorization`, `metatransport`, `recompression`) and every production file selected by the new harness
must exceed 95 percent coverage.

The standalone access corpus retains macOS 15, 26 and 27. Targets 15/26 reject
active LZ4 write-open with ENOTSUP and preserve the original storage; 27 accepts
it. The portable decoder still supports LZ4 on every host. Fresh native recapture
and all producer/readback jobs must pass on the final PR revision before this
prerequisite is qualified. A green SDK
harness also does not finish codesign Phase 2: its consumer integration, native
`--preserve-afsc` behavior, full failure matrix, shared resource budgets and
large-file measurements remain obligations in that project's implementation plan.

### Source name comparison and lookup

`RecompressPath` additionally requires each searched directory's observed
`Mount.CaseSensitive` value. `NewPathContext` snapshots that pointer along with
other observations. Capture the source volume's case-sensitivity capability and
its validity bit; do not infer it from the receiving host or the label "APFS" or
"HFS+". APFS and HFS+ each have case-sensitive and case-insensitive variants.

After directory search permission succeeds, lookup applies the source
filesystem's component-length and decoding rules, then its shared name
comparator. A carrier with two matching siblings returns `ErrConflict`, even if
one spelling exactly matches the request. Lookup retains the selected original
manifest name for publication. Creating a new name has different admission
rules and must not be substituted for lookup of an existing entry.

The native lookup corpus separately captures `O_RDWR` without `O_CREAT`, actual
creation attempts, stored directory spelling, permission failures and contents.
For example, HFS+ can resolve illegal UTF-8 bytes through literal percent-escaped
catalog names, while APFS reports a missing name. Native capture and portable
replay on macOS 15, 26 and 27 remain mandatory; one fresh bootstrap capture never
replaces the three retained baselines.
