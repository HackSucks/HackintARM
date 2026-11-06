# Shared host metadata

`hostdata` connects portable Darwin metadata policy with actual held files,
explicit captured observations and image/carrier consumers. Use it when a tool
must preserve more than the data fork, inspect native metadata failures, or
execute AppleDouble packing/restoration on Linux, macOS and Windows. Production
does not invoke Apple tools, C compilers or copyfile subprocesses.

## Package responsibilities

`hostdata` is this project's namespace for filesystem metadata. The former
`hostmeta` name was not an Apple API name. The public operations keep the native
concepts they describe; moving an operation does not change its OS behavior.

| Package | Owns |
| --- | --- |
| `hostdata` | Held/path lifecycle composition, metadata capture and restoration, native descriptor providers, resource-fork streaming and replacement. |
| [`hostdata/acl`](acl/README.md) | ACL records, Darwin attribute/chmod requests, source identity capture and deferred ACL restoration. |
| [`hostdata/accesstime`](accesstime/README.md) | Copying held-file access time and recording native read access. |
| [`hostdata/sandbox`](sandbox/README.md) | Capturing the actual App Sandbox process selector. |
| [`hostdata/xattrintent`](xattrintent/README.md) | Extended-attribute preservation policy for explicit copy intents. |
| [`hostdata/bsdflags`](bsdflags/README.md) | Reading the host's BSD inode flags without inventing foreign-host flags. |
| [`hostdata/diskspace`](diskspace/README.md) | Available space for the calling user, including native quota behavior. |

The subpackages do not import the coordinating `hostdata` package. Shared Linux
and Windows timestamp setters live once in `internal/hosttime`. AppleDouble byte
formats remain in `pkg/appledouble`; portable persistence remains in
`pkg/metatransport`. See the [import migration and verification plan](../../docs/hostdata-packages.md).

## Choose the operation

| Need | API and contract |
| --- | --- |
| Discover only a contained entry's type, independently of data, ACL and EA reads | `ReadEntryType(root, name)`; final links are inspected and basic-attribute authorization remains effective. See [rooted entry types](../../docs/rooted-entry-type.md). |
| Discover a contained entry without reading its data or EAs | `StatMetadata(root, name)`; final symlinks are not followed and host metadata permissions remain effective. See [rooted metadata discovery](../../docs/rooted-metadata-stat.md). |
| Read a contained regular file without requesting ACL or EA read rights | `OpenContentFileRead(root, name)`; read-only held identity, final links rejected. See [rooted content reads](../../docs/rooted-content-reader.md). |
| Discover filesystem-selected attributes without a sidecar flag | `OpenFilesystemMetadata(ctx, root, name)` or borrowed `FilesystemMetadataForFile(ctx, file)`, with `List`, `Size`, bounded `Read`, owned `OpenValue` and `Remove`; see [filesystem metadata and outstanding writes](../../docs/metadata-filesystem.md). |
| Inspect or assign one native host attribute | Strict held xattr APIs below; inspect actual errors and readback normalization. |
| Preserve complete logical metadata between hosts/images | `pkg/metatransport` plus APFS/HFS streaming readers/writers; unsupported local native storage does not discard a logical value. |
| Restore a validated complete AppleDouble snapshot | `RestoreAppleDouble`; validate first, then perform ordered destination effects. |
| Reproduce sequential native reads and partial effects | `RestoreAppleDoubleSequential`; late malformed input may follow earlier successful writes. |
| Execute native-style packing/unpacking on held objects | `PackAppleDoubleObject` / `UnpackAppleDoubleObject`; caller owns descriptor and borrowed-value lifetimes. |
| Include path creation/opening and cleanup | `CopyAppleDoublePath`; library owns opened handles and retains creation, permission, route and close diagnostics. |

## Complete AppleDouble operations

`NewHostAppleDoubleObject` binds a held Darwin file to source identity, process,
sandbox and native metadata providers. `NewCapturedAppleDoubleObject` supplies
the same logical policies on all three supported OSes using captured metadata,
attributes, identities, quarantine process state and mount observations. Native
capture being unavailable on a foreign OS does not disable the captured operation.
Read `LogicalSnapshot` and persist its state/values through the image or carrier;
logical ACL and quarantine updates do not create equivalent Linux/Windows kernel
authorization. No receiving-host account database replaces the source mappings.

`CopyAppleDoublePath(ctx, source, destination, options)` chooses
`PathPackAppleDouble` or `PathUnpackAppleDouble`. Supply
`DefaultObjectPackOptions()` or `DefaultObjectUnpackOptions()` for the selected
route and a positive `MaxOpenAttempts`; zero retry budget is invalid. Native
Darwin use leaves `Captured` nil. Foreign-host use supplies `CapturedPathContext`,
including source and existing destination objects, creator/parent-ACL/umask
context when creating a destination, explicit real/effective UUID pointers, and
observed source/destination protection capabilities. Nil UUID/protection fields
mean unknown and are rejected when required; an explicit negative observation
differs from absent information. Captured source type must agree with its actual
payload object. Required source context should be collected before starting.

These are ordinary explicit OS paths, not a contained-root extraction API.
`NoFollowSource` and `NoFollowDestination` select final-link behavior;
intermediate components resolve normally. Exclude concurrent namespace,
content and metadata changes. The implementation validates observed object
identity and uses held descriptors for temporary permission restoration; it
does not claim protection against substitution followed by restoration between
observations. On foreign hosts, temporary access to the actual backing payload
has its own saved/restored permissions, separate from captured Darwin modes.
Logical link permissions never justify chmod of the receiving-host referent.

The result retains outer lifecycle steps and inner pack/unpack/stat/ACL results.
Inspect both the Go error and recorded steps: native success can ignore an
individual metadata failure. Close/restoration failures remain visible. There
is no rollback or implicit fsync; failures can leave metadata changes, truncated
content or an unlinked pack destination. `MoveSource` and `UnlinkDestination`
request those actual path effects and must be selected deliberately.

Native-style pack preserves observed copyfile omission/normalization policy.
Sequential unpack allocates the complete incoming resource fork in native order.
Default object options allow 64 MiB active workspace, and allocation requires
`size <= (MaxActiveBytes - headerBytes - deferredACLBytes) / 2` as well as explicit
value/aggregate limits. Consequently, less than 32 MiB fits as a single fork under
that default. Budgets are configurable; they do not limit the filesystem or the
streaming preservation APIs. Borrowed input Values stay immutable/readable until
consumption; new logical writes own their bytes, while preserved old fork suffixes
can remain borrowed. Destination-owned snapshots are not a total-memory budget.

See [object operations](../../docs/appledouble-object.md),
[path lifecycle and native evidence](../../docs/appledouble-path-lifecycle.md),
[large resource forks](../../docs/appledouble-large-values.md) and
[carrier storage](../metatransport/README.md) for complete contracts and examples.
The implementation and native qualification in the
[completion matrix](../../docs/appledouble-completion-matrix.md) passed in PR182.
The same 23-report coverage audit, native, large-value, foreign-image, fuzz/race/lint
and vendor gates apply to this package refactor. C-only allocator faults and
unavailable native observations remain distinct from implemented Go policy.
Downstream package PR72 and codesign remain held until the qualified APFS release
is adopted and downstream validation completes.

## Strict extended attributes

`ListXattrNames`, `XattrSize`, `ReadXattr` and `RemoveXattr` operate on an already-open `*os.File`.
The corresponding `XattrSizeNoFollow`, `ReadXattrNoFollow` and
`RemoveXattrNoFollow` operate on a path without following its final symlink.
These APIs provide strict results separately from the existing best-effort
`ListXattrs`/`SetXattrs` behavior.

```go
size, present, err := hostdata.XattrSize(file, "user.example")
if err != nil { return err }
if present {
    // size == 0 is still a present attribute.
    value, present, err := hostdata.ReadXattr(file, "user.example", 4096)
    // Handle err and a possible intervening disappearance before using value.
    _, _, _ = value, present, err
}
_, _ = size, present
```

| Result | Meaning |
| --- | --- |
| `present == false`, nil error | Native missing-attribute result only |
| Size zero, `present == true` | Present-empty value |
| Non-nil error | No absence/success claim; permission and I/O causes survive |
| `ErrXattrUnsupported` | Host/filesystem lacks the operation; native errno is also retained when available |
| `ErrXattrTooLarge` | Value exceeds the caller's explicit read limit; no value is returned |
| `ErrXattrChanged` | A value disappeared or its observed size changed during the two-call read; no partial value or retry |

Read limits range from zero to `MaxXattrReadSize` (8 MiB). Unix size queries and
removal do not allocate the value. Windows native EA queries require a complete
record and use at most 65,799 bytes of scratch space, including for size queries.
This is separate from the caller-bounded returned value. Reading a zero-length value uses a one-byte
buffer to make a real read rather than another size-only query. A successful
present-empty read returns a non-nil empty slice. Error results never return a
truncated value. A same-size concurrent value change is not detectable: callers
needing stable metadata must exclude concurrent mutation.

Descriptor operations use `SyscallConn.Control` to keep the handle held through
the native calls, including both phases of a read. They do not reopen `File.Name`,
close the caller's file or change file position. Renames and old-name decoys do
not redirect them. Regular files, directories and OS-supported link descriptors
are passed to the native API; a file opened through a symlink already identifies
the target. Darwin `O_SYMLINK` descriptors operate on the link itself. Linux
`O_PATH` descriptors return `EBADF` from these operations, without a pathname
fallback. Nil and closed descriptors fail.

`ListXattrNames(file, maxBytes)` retains native name order and bytes, with a
caller budget up to 1 MiB including name terminators. Errors return nil, never a
partial or successful-empty list. Unix size/read changes fail; Windows uses one
EA cursor with fixed scratch space and rejects duplicate records. Enumeration
retains native casing and raw name bytes even beyond the named-read ASCII subset.
See [held-file listing](../../docs/appledouble-held-xattr-list.md) for its native
qualification, concurrency limits and carrier/provider integration.

`CaptureXattrValuesAt(ctx, root, name, limits)` captures through a held root,
including Linux symlinks. Linux reads the link's own namespace through a pinned
parent descriptor and no-follow xattr calls; dangling links and targets outside
the root do not cause the target to be opened. Identity checks before and after
capture reject observed replacement. Callers must exclude concurrent changes,
including substitution followed by restoration of the original entry. Linux
requires accessible procfs for this descriptor-relative symlink capture; a
missing procfs or denied native operation returns its error without dropping
metadata. Ordinary values remain bounded owned snapshots. Darwin regular-file
resource forks remain borrowed 64-bit readers with the documented owner lifetime.

`SetXattr(file, name, value)` assigns one native attribute through the held object.
The filesystem controls empty-value and special-name behavior; a successful write
is not a byte-equality guarantee. Windows requests write access without read access
and bounds its EA record allocation. Unix uses ordinary native flags. See
[held-file writes](../../docs/appledouble-held-xattr-write.md) for limits, native
readback evidence and provider/carrier integration.

Path operations are not a containment or identity primitive. Intermediate
components can be symlinks and each call resolves the path again. Use a suitably
opened descriptor for held-object semantics. Missing files remain errors rather
than being mistaken for missing attributes.

Darwin and Linux implementations use supported `golang.org/x/sys/unix` wrappers;
there are no new direct syscalls, native bindings or helper processes. The
namespace is the ordinary native namespace: Darwin does not request
`XATTR_SHOWCOMPRESSION`, so compression-hidden metadata is not exposed. Linux
namespace/permission rules still apply; names are not automatically remapped.
Windows implements all eight strict operations using native NTFS extended
attributes through the supported `NtCreateFile`, `NtQueryEaFile` and `NtSetEaFile`
wrappers. Path opens use `FILE_FLAG_OPEN_REPARSE_POINT`; held-object opens use an
empty relative name without looking up `File.Name`. Access is checked against the
current DACL, without backup privilege. Files, directories and held symbolic links
are supported. Named EA operations accept case-insensitive ASCII names up to 254 bytes, with
Windows name restrictions; values follow native EA storage limits. Assigning zero
length deletes a native EA, so NTFS cannot store a present-empty EA. Removal
queries presence before deletion on the same handle; concurrent mutation is not
atomic. Protected `$Kernel.` assignment/removal is explicitly denied because Windows silently
ignores user-mode updates in that namespace. Alternate data streams remain separate
and untouched. The older best-effort `ListXattrs`/`SetXattrs` APIs and their
`XattrsSupported` constant retain their existing behavior.

`ErrXattrUnsupported` is reserved for other unimplemented hosts or an actual
filesystem capability error, never used as a blanket Windows result.

Removal requests deletion of one named attribute, returns true on success and
false/nil for native absence, and preserves other errors. Hard links share the
mutation, and metadata change time can advance. Attribute-specific effects on
compression, ACLs or other filesystem state belong to the OS. There is no
rollback, transactional attribute set or promise that an attribute hidden from
ordinary reads is safe to remove. Ordinary unrelated attributes and file contents
are preserved in the tested profile.

The Mac tests compare reads and removals with `/usr/bin/xattr`, cover file/directory
and held symlink identity, and assert real ACL-denial errors. APFS normalizes a
fresh empty ResourceFork and all-zero FinderInfo to absence; an ordinary empty
attribute remains present. An empty or shorter assignment over an existing
resource fork does not necessarily truncate its previous bytes. Linux tests cover permission denial, final-link
behavior and rejection of `O_PATH` handles. Windows tests perform real file/directory EA creation, query, bounded read and
removal, including 60,000-byte values, case-insensitive lookup, empty-value
normalization, moved handles, hard links, old-name decoys, dangling and held
symbolic links, alternate-stream retention and real DACL denials for every API.
No Windows lifecycle or permission test skips an unsupported result. Shared tests cover bounded allocation, changing sizes,
disappearance, nil/closed files and retained error causes. The existing CI runs
these tests and enforces **above 95% statement coverage in the new strict API**
using `go run scripts/verify-xattrs.go`; this is not a whole-repository coverage
claim. Test transcripts, coverage and source hashes are uploaded per platform.

The intended first consumer is codesign sideband policy. Apple's
[attribute helpers](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_utilities/lib/unix%2B%2B.cpp)
use ordinary descriptor queries and distinguish zero-length/nonempty values;
their policy also suppresses `EPERM` in `checkFork`. These generic APFS APIs
preserve that error so consumers can apply their own measured policy. They do
not implement codesign flags, decide whether an attribute is prohibited or
modernize the legacy compression-aware best-effort reader.

## Access and creation times

`CopyAccessTime(source, target)` copies a regular file's current access time
into a distinct open regular file on Darwin, Linux and Windows. It uses held
descriptors, so moved names or old-path decoys cannot redirect the update.
Darwin/Linux retain nanoseconds; Windows retains its native 100ns precision.
Source metadata, contents and file
positions are unchanged. Only target access time is explicitly set; its metadata
change time may advance. Other timestamps, ownership, mode, ACLs and xattrs remain
unchanged. Target hard links share the update. Nil, closed, non-regular and
same-inode pairs fail; unsupported hosts return `ErrAccessTimeUnsupported` without
mutation. The caller needs metadata-write permission on the target and must keep
both descriptors open without concurrent metadata changes. Use this after a
source read to update a privately staged clone without repeating allocation.
Replacement APIs do not implicitly copy access times.

`RecordReadAccess(file)` requests native mapped-read access-time behavior for an
open regular file on Darwin. It briefly maps one byte read-only without accessing
the mapping, so empty files and truncation cannot cause a mapped-memory fault.
The filesystem chooses the access time; contents, file position and other metadata
are unchanged. Hard links share the access-time update. Read permission is enough,
including on files whose ACL denies metadata writes. Nil, closed, non-regular,
write-only and event-only descriptors are rejected. Other hosts return
`ErrReadAccessUnsupported`; no timestamp-write emulation is performed. This is an
explicit operation and does not change replacement API defaults.

`SetCreationTime(file, when)` updates the creation time of an open regular file,
directory or held symlink
on Darwin with nanosecond precision and Windows with 100ns precision. Windows
rejects values outside its representable range or precision. Replacing the original pathname does not change
the target. Contents, access/modification times and other supported metadata remain
unchanged. Hard-link names share the update. Nil, closed and other special files
fail; other hosts return `ErrCreationTimeUnsupported` without emulating the time.
This is an explicit caller operation; replacement APIs retain their source
creation-time preservation contract. Call it on a private staged file before
restoring restrictive flags, then sync and commit through the caller's writer.

`SetFileTimes(file, modify, access)` sets both timestamps on held regular files or
directories on Darwin, Linux and Windows. Native filesystem resolution can differ:
read back results when exact projection matters. Store the original logical values
in the portable carrier to retain nanoseconds or creation times unavailable on the
host. These setters never fabricate a native metadata-change timestamp.

`CaptureQuarantineProcess(ctx)` captures effective raw process quarantine state
on macOS 26/27. Its owned snapshot retains binary agent/metadata/tracking values;
`Process()` supplies the pure-Go application planner on every operating system.
Capture does not change process state. Unknown ABIs and native capture on foreign
hosts return an explicit unsupported error; callers supply a previously captured
snapshot when applying Darwin policy on Linux or Windows. See
[raw capture and native qualification](../../docs/appledouble-quarantine-process-capture.md).

APFS/HFS+ writers, extraction, capacity checks and external consumers share these
implementations and platform definitions. Consumers adopt the new import paths
through the qualified release described in the migration guide.

`ListXattrs`, `SetXattrs`, `bsdflags.Flags`, `Link`, `diskspace.AvailableSpace` and the attribute
constants retain their existing behavior. Attribute extraction is best effort;
callers must inspect reported failures. Darwin compression-aware reads use
option-aware, typed Darwin wrappers in `internal/darwinabi`, following the
`golang.org/x/sys/unix` static import pattern with CGo disabled. See the
[wrapper boundary and qualification](../../docs/darwin-wrappers.md). They no longer use deprecated raw syscalls or silently fall back to
ordinary visibility when hidden storage cannot be read.

`CaptureXattrs` captures a complete namespace on a held file with explicit
name, per-value and aggregate budgets. `CaptureXattrsNoFollow` targets the final
path component itself; its Unix pathname calls require the caller to exclude
concurrent path replacement. Both distinguish missing metadata from an unknown
or failed capture and return no partial snapshot. Ordinary attribute values
still require one complete native read; the explicit budget is not a claim that
ordinary xattrs support positioned reads.

`ImageMetadataFS` exposes numeric ownership, Unix mode, BSD flags, independent
timestamps and resolved link identity from APFS/HFS+ readers on every supported
host. `pkg/metatransport` preserves this logical state outside the payload tree
when the destination host cannot represent it. Storage and host enforcement are
separate capabilities; there is no global preservation/native mode.

`PrepareReplacementContext(ctx, source, parent)` prepares a writable replacement
while preserving the source. The original `PrepareReplacement` API delegates with
a background context. The rooted operation is `PrepareReplacementAtContext`; both
result types expose `RestoreMetadataContext` as well as the original method.
For example:

```go
func replace(ctx context.Context, source *os.File, destination string, contents []byte) (err error) {
r, err := hostdata.PrepareReplacementContext(ctx, source, filepath.Dir(destination))
if err != nil { return err }
defer func() { err = errors.Join(err, r.Close()) }()
if _, err := r.File.WriteAt(contents, 0); err != nil { return err }
if err := r.File.Truncate(int64(len(contents))); err != nil { return err }
if err := r.RestoreMetadataContext(ctx); err != nil { return err }
if err := r.File.Sync(); err != nil { return err }
if err := r.File.Close(); err != nil { return err }
// Close source and verify the destination still names the expected source.
// The caller owns the decision to commit, and whether to use a rename.
return os.Rename(r.File.Name(), destination)
}
```

For an explicit foreign carrier, `ReplacementAttributeValues(ctx, sourceFlags,
values)` applies the same attribute selection to borrowed values. Use captured
Darwin flags: native replacement omits both the compression attribute and resource
fork while compression is active. macOS hides even independent forks on active
inline-compressed files from this operation's ordinary attribute enumeration.
Inactive compression attributes remain ordinary metadata. The helper reads only the
compression header, so large forks stay borrowed. The caller keeps the source
values alive, restores stat/security separately and publishes the returned values
with the rewritten payload through `metatransport.Store.Publish`. This helper
neither mutates a carrier nor activates compression; recompression is a later
explicit operation.

The visibility rule is source-backed by Apple's
[`decmpfs_hides_rsrc` and `decmpfs_hides_xattr`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/decmpfs.c#L963).
The mounted replacement harness independently compares every selected attribute
and resource-fork byte with native `copyfile`; source inspection is not a
substitute for that live qualification.

The source stays open and unchanged while the replacement is prepared. The
package owns a private staging directory and cleans it on `Close`, including
after the caller renames the staged file. Callers handle concurrency and the
final rename; no transactional or crash-durability guarantee is made. Check the
error returned by `Close` as well as the operation error; close, permission-reset
and removal failures are retained together. Cancellation is checked around native
operations and between bounded transfers. Cleanup is never canceled, and one
native call need not be immediately interruptible. Neither cancellation nor cleanup
closes a caller-owned source or root.

- Darwin uses x/sys's libSystem-backed `Fclonefileat`, `Setattrlist` and
  `Fchflags` wrappers. It preserves ownership, mode, xattrs, source ACLs, birth
  time and supported flags. Its own staging directory has inherited ACLs
  cleared before cloning. Source ACL entries are omitted from the temporary clone
  so a source deny-write entry cannot block staging; `RestoreMetadata` reads the
  held source ACL and installs it on the held replacement through the released
  typed metadata wrappers after content writes. Neither step changes the source
  ACL. ACL read/write failures require discarding staging; callers must not
  commit after a restoration error. No deprecated raw syscall is used by this API.
  Clone-capability errors (`ENOTSUP`, `EXDEV`, `ENOSYS`) use an exclusively
  created writable file instead. Held-descriptor APIs copy visible xattrs and
  creation time; resource forks stream in 64 KiB chunks with 64-bit offsets.
  The fallback bounds xattr names to 1 MiB and ordinary values to 8 MiB in
  aggregate, excluding resource forks. It works on HFS+ without cloning and
  fails rather than discarding metadata on any capture, transfer or restoration
  error. Permission, storage and other clone errors do not trigger fallback.
  Immutable and append-only inputs still fail before commit. Compressed Darwin
  sources use a fresh uncompressed stage. The metadata copier reads the hidden
  compression header through the existing typed host wrapper, excludes the old
  compression attribute and its owned storage fork. Ordinary native enumeration
  also hides independent forks while compression is active, so replacement does
  not copy those forks. This differs from lossless archive transport. Unknown/missing headers fail without
  discarding an unclassified fork. Restoration keeps the target's compression
  state; it never reattaches the source flag to rewritten logical data.
  Recompression is a separate caller policy, not an automatic replacement step.
- Linux copies owner/group, mode and readable xattrs (including POSIX ACLs),
  with an 8 MiB bound for the name list and each individual value. Values are
  transferred separately, without a cumulative attribute-byte limit. Inherited staging
  ACLs are removed first. Linux inode flags and birth time are not preserved.
- Windows transfers unencrypted files through held `BackupRead`/`BackupWrite`
  handles, preserving sparse alternate streams without materializing their holes.
  EFS uses `CopyFileEx` inside an atomically secured private directory, with
  held namespace pins and a separate raw EA transfer because native encrypted
  copying omits those attributes. A path obtained from the source handle is a lookup hint:
  the callback must observe the same source identity and a destination beneath
  the held stage. Empty files also require this identity observation. A native
  copy handle is duplicated without increasing its rights; separate held
  security/attribute rights allow deferred acquisition of the writable data
  handle after native copying finishes. Temporary permissions apply only to the
  private copy. The source owner, group and complete DACL are restored after writing,
  including inherited ACEs and protection/auto-inheritance control bits. A held
  `NtSetSecurityObject` operation avoids re-inheriting permissions from the private
  staging directory. Closed files never reach this operation as pseudohandles.
  Ordinary/sparse alternate streams, EAs, NTFS compression, encryption, creation
  time and ordinary attributes are preserved. EFS user and recovery-certificate
  hashes/SIDs are compared through pinned names: a decrypted destination or
  changed key set fails preparation. SACL preservation is not promised.
  Replacing a read-only destination may still fail at the caller's rename.

All three implementations build with `CGO_ENABLED=0`. The new API never invokes
an external tool or signing service. Tests run on Linux, macOS and Windows in
the existing CI matrix. Darwin tests compare ACL text, xattr values, ownership,
BSD flags and creation time on the host; Windows tests compare streams and
security descriptors.
Replacement qualification adds `go run scripts/verify-replacement.go` on every
CI host, requiring coverage strictly above 95% for every changed replacement
production file and the complete hostdata package. The original focused gate
retains mandatory suites, rejects every skipped replacement test, binds source
hashes to the tested revision and independently audits the report and raw
transcript. The complete-package run has a separate transcript/profile. Windows
2022 and 2025 qualification requires native EFS and NTFS controls, empty inputs,
large alternate streams, restrictive ACLs, retained-source identities and
cancellation; capability failures are not skipped. On macOS,
`go run scripts/verify-replacement-native.go` creates disposable APFS and HFS+
images, compiles the C control with Clang, retains arm64/x86_64 ASTs and checks
both public APIs with inherited/deny-write ACLs and a resource fork exceeding
8 MiB. It also qualifies 34 compressed replacement cases per filesystem:
17 native storage profiles through both APIs, including fresh zlib/LZVN/LZFSE
producers, inline and resource-fork containers, empty/type-1 boundaries and
independent forks. Raw captures retain the native destination birth time before
copying, source modification time, and destination birth/modification times after
copying and rewriting. Copying an older modification time clamps destination
birth to that time; the corpus checks the exact transition rather than comparing
against the test process's wall clock. A fixed historical modification time makes
this regression deterministic on both filesystems. Linux and Windows replay the
committed native corpus and run the shared
failure/budget/64-bit boundary tests alongside their existing native replacement
suite. A sparse fork boundary test above 4 GiB checks offset forwarding; it is
not a claim of a full native 4 GiB transfer acceptance run.

The control retains raw `fcopyfile(COPYFILE_SECURITY | COPYFILE_METADATA)`
results separately. That native operation can preserve destination creation
time (subject to modification-time clamping), merge inherited ACLs and normalize
quarantine's agent/timestamp; this
SDK's existing replacement contract instead
preserves source creation time and restores the source ACL after writing. The
corpus verifies both observations rather than treating this generic metadata
API as a complete `codesign` timestamp or inheritance policy.

# Root-relative replacements

`PrepareReplacementAt(source, root, parent)` stages a replacement beneath an
already-open `*os.Root`. `RootReplacement.File` is writable and its `Path` is
relative to that root. Write/truncate the complete output, call
`RestoreMetadata`, sync and close the file, then use `root.Rename` to commit.
Always call `Close` to discard staging. Keep the caller-owned source open through
metadata restoration and the root open through cleanup. The API never commits
or closes those caller-owned objects and is not safe for concurrent method calls.

Darwin clones or exclusively creates relative to the opened staging directory and uses the held
directory's `/dev/fd/N` name with the supported `Setattrlist` wrapper to clear
inherited ACLs. Linux creates through the root and copies metadata by descriptor.
Windows uses the same held-stream and EFS routes as the path API. Its private
DACL is supplied to the root-relative `NtCreateFile(FILE_CREATE)` operation,
avoiding a create-then-chmod permission window. Held directory/anchor capabilities
remain live through copy and final identity checks. EFS destination copy flags
reject existing links, including dangling symlinks. Callback identity validation
is additional protection; it does not substitute for contained creation.

Unencrypted sources use `ReOpenFile` plus `BackupRead`/`BackupWrite` throughout.
The transfer streams EAs and alternate data, excluding main-data and backup
identity/link records. It preserves NTFS compression through held filesystem
controls. Stream payloads, sparse extents and record counts have no arbitrary
aggregate limit; fixed transfer buffers and checked signed offsets bound resource
use. Reparse sources remain unsupported. Encrypted files never use BackupRead or
a plaintext fallback: unavailable EFS names/keys return an error. EFS attributes
transfer as raw native EA records to preserve their flags, names and values.
Permission, identity and storage failures do not silently select another algorithm.

Prepare the replacement before unlinking the source. Windows can retain readable
main data on a zero-link, delete-pending handle while rejecting both backup-stream
reads and new alternate-stream opens. Such a handle does not by itself retain all
metadata capabilities. Late preparation must fail and remove the private stage
when complete capture is impossible. The prepared stage retains the transferred
streams for writing and publication; keep the source open through restoration.
Both Windows runner versions must qualify this lifecycle for ordinary, compressed,
sparse, encrypted, deny-write and read-only inputs, including cancellation cleanup.

`RestoreMetadata` restores source attributes before publication. A subsequent
native rename may change attributes, including setting the archive flag. The
caller owns that rename; cleanup does not rewrite the published target. Acceptance
compares exact attributes before publication and independently checks the native
rename transition.

Cleanup retains attribute rights acquired before restrictive source ACLs are
restored. It clears readonly only after verifying the held file still has its
private staging name. If the caller already renamed it, cleanup leaves the
committed target's attributes unchanged, including when `File` was closed first.
Darwin's protected-file limitations remain; SACLs remain outside the contract.
The [prerequisite tracker](../../docs/codesign-filesystem-prerequisites.md) records
outstanding platform qualification; implementation alone does not close a gate.

The existing path API remains available. Both APIs run the same platform metadata
tests. Root-specific tests cover containment, a moved root with an old-path decoy,
hard-link detachment, failed restoration, cleanup and close after commit.
Concurrent source/staging-tree mutation and crash durability are not promised;
callers own source/destination identity checks and commit decisions.

Windows protocol references: [CopyFileEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexw),
[copy callbacks](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nc-winbase-lpprogress_routine),
[EFS users](https://learn.microsoft.com/en-us/windows/win32/api/winefs/nf-winefs-queryusersonencryptedfile),
[EFS recovery agents](https://learn.microsoft.com/en-us/windows/win32/api/winefs/nf-winefs-queryrecoveryagentsonencryptedfile),
[BackupRead](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread),
[BackupWrite](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite),
[WIN32_STREAM_ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id)
and [ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).

# Directory stat metadata

`CopyDirectoryStat(source, target)` copies a bounded stat-metadata profile between
distinct, already-open directories. Both descriptors remain caller-owned; neither
contents, xattrs, alternate streams nor ACL entries are copied. It never creates,
replaces or commits a directory. Names may move without redirecting the operation.

- Darwin copies owner/group, mode, nanosecond access/modification times and
  `UF_NODUMP`, `UF_OPAQUE`, `UF_HIDDEN`. Like Apple's `COPYFILE_STAT`, it omits
  source tracked/protected flags and drops setuid/setgid on nosuid volumes.
  Other source flags and unsupported target flags are rejected before mutation.
  Creation time is not explicitly copied; setting an earlier modification time
  can lower it. Existing destination ACL entries remain unchanged.
- Linux copies owner/group, mode and nanosecond access/modification times using
  `utimensat(AT_EMPTY_PATH)` through x/sys (kernel 5.8+). It does not copy inode
  flags or birth time. Changing mode may update a destination POSIX ACL's mask.
- Windows copies read-only, hidden, system, archive and not-content-indexed
  attributes plus access/modification times. It leaves creation time, security
  descriptors and streams unchanged. Other directory attributes are rejected.
  The supported x/sys `NtCreateFile` wrapper opens an empty name relative to the
  held target with explicit directory semantics; it never resolves `File.Name`.

This is a stat operation, not Apple's full `COPYFILE_SECURITY`: that operation
also combines explicit source ACL entries with inherited destination entries.
There is no supported Darwin ACL reader in the current x/sys API, and this API
does not add native bindings, raw syscalls or helper processes to read them.
Unlike Apple's best-effort stat copy, failures are returned. An error after a
mutation can leave partial metadata changes; callers must avoid concurrent
metadata mutation and keep handles open. No rollback is promised.

Darwin tests compare the API with a test-only native `copyfile(COPYFILE_STAT)`
helper, including precise times, setgid, BSD flags and creation-time effects.
Platform tests cover invalid/same directories, held handles after name changes,
content/identity preservation, ACLs, xattrs and Windows security/stream retention.
The native helper is compiled only for tests, never for production.

Reference: Apple's [copyfile implementation](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
and [flag masks](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h),
pinned at `9f91eb6ced021952278816cdc76ad68da8631ccb`.

Strict Windows EA references: [query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryeafile),
[EA wire format and zero-length deletion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989),
and [protected kernel EAs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes).

## Deferred AppleDouble ACL restoration

`acl.RestoreACL` executes an `appledouble.ACLUpdate` through an explicit
`acl.ACLRestoreBackend`. It captures destination security once, retains ownership and
mode, and reports actual capture/write errors. An unsupported first write clears
cached source security and retries the unchanged destination request once.
Permission failures are not retried. Every callback request owns its data.

The routine is pure Go on Linux, macOS and Windows. `NewHeldMetadata` supplies
the native Darwin backend, while `NewLogicalMetadata` and the image bindings
provide portable logical restoration. The complete object/path APIs compose
these operations with acquisition and cleanup. Native APFS and FAT comparisons
include real permission and unsupported-operation failures. See
[the backend contract and coverage](../../docs/appledouble-acl-restoration.md).

## Portable Darwin ACL attribute records

`acl.ParseDarwinACLAttributes` decodes successful Darwin attribute-list responses;
`acl.ACLMetadata.MarshalDarwinACLAttributes` encodes set requests for the explicit
`acl.DarwinACLCommonAttributes` profile. Both operate identically on every OS and
retain numeric ownership, raw mode, UUID ownership and ACL bytes without native
calls. Ownership UUIDs use their separate attribute fields because Darwin ignores
the embedded blob ownership slots. See the [wire profile and native evidence](../../docs/appledouble-acl-attributes.md).

This codec represents the attribute-list wire layout. Native tests show that the
attribute API and copyfile differ on empty ACL flags and immutable/append-only
failures. The production held provider uses the extended chmod protocol to retain
the qualified copyfile behavior; the attribute codec keeps its separate contract.

## Extended chmod requests

`acl.ACLMetadata.DarwinChmodRequest` builds the numeric arguments and owned security
blob for the extended chmod operation used by copyfile. Ownership UUIDs remain
embedded; mode narrows to Darwin's 16-bit `mode_t`. It uses the same pure-Go
implementation on Linux, macOS and Windows. Native comparisons resolve all 16
measured attribute/copyfile error differences and eight empty-ACL flag differences
by submitting the request to the correct operation. See the [contract and evidence](../../docs/appledouble-acl-chmod.md).

The held native provider consumes these requests through libSystem; the logical
provider applies them to captured metadata on every supported OS. Do not
substitute `fsetattrlist` or add a permission-changing preflight. Complete
lifecycle, privileged/nonowner and signed-sandbox qualification passed in PR182.
Controlled owner/non-owner APFS/HFSX contexts are also qualified; see
[authorization evidence](../../docs/appledouble-acl-nonowner.md). Ordinary
copy selection uses [`appledouble.CopyACL`](../../docs/appledouble-acl-copy.md),
separately from this package's deferred replacement protocol.

## Optional extended chmod properties

`acl.DarwinChmodProperties.ChmodArguments` handles independently present numeric,
UUID and raw-security properties plus explicit ACL removal on every OS.
Omitted ownership uses Darwin's -101 sentinel, and omitted mode is integer -1.
Null security, a record and the removal sentinel remain distinct arguments.
Explicit zero UUIDs can cause a record to be sent even without an ACL property.
See the [contract and native effects](../../docs/appledouble-acl-chmod-properties.md).
The production held and logical providers bind these properties into complete
object/path operations and carrier/image preservation.

## Ordinary security-copy execution

`CopySecurity` coordinates ACL selection, optional filesec properties, set-ID
filtering and copyfile-compatible fallback ordering through a portable backend.
It retains write failures even where native copyfile reports success. Callers
must inspect `SecurityCopyResult.Failures`; `Completed` alone does not prove
metadata preservation. See [execution and qualification](../../docs/appledouble-security-copy.md).

`SecurityCopyOptions.VolumePolicy` optionally acquires source/destination mount
policy after ACL selection and before writes. `SecurityCopyResult.VolumeQueries`
distinguishes observed negatives, positive `MNT_NOSUID` results, failed queries
and unqueried endpoints. The executor preserves native short-circuit order and
continues after lookup failures. Both image writers accept the same provider on
Linux, macOS and Windows; the provider must supply actual host or captured foreign
mount state. See [volume policy and native comparisons](../../docs/appledouble-security-copy-volume.md).

`CaptureSecuritySource` acquires fresh descriptor-style source state through
explicit callbacks. Only classified statx `EPERM`/`ENOTSUP` errors permit plain
stat fallback; failures remain visible even when native execution continues.
`CopySecurityFrom` connects acquisition to ordinary copying while retaining the
pre-selection source separately from the copy cache. `ImageSecurityCapture`
binds existing APFS/HFS+ readers without loading file payloads or resource forks.
Both image writers expose `root.CopySecurityFrom(target, capture, options)` on
every OS. See [source acquisition and qualification](../../docs/appledouble-security-source.md).

`FileTimes` carries four independent inode times for APFS/HFS+ image preservation
on every OS. Both image volumes expose `FileTimes(name)`, and both writer entries
accept `Times`. See [image timestamps](../../docs/appledouble-image-times.md) for
selection, epoch, clamping and format precision rules. It is not a host setter.

## Ordered stat restoration

`CopyStat` executes the final stat stage through `StatCopyBackend`: times,
ownership, permissions, then BSD flags. It uses the same pure-Go implementation
on Linux, macOS and Windows. It retains protected destination flags, retries
compare-and-swap contention at most four times, and records errors that native
copyfile ignores. `Completed` is sequence completion, not proof of preservation;
inspect `Failures`, `VolumeQueries` and `FlagsApplied`.

Use this after ordinary security copying in an explicitly bound restoration
pipeline. It neither acquires source state nor creates a live host adapter.
See [the contract, usage and native qualification](../../docs/appledouble-stat-copy.md).

Both APFS/HFS+ image readers also expose `BSDFlags(name)` and both writer entries
accept `BSDFlags`. These are portable image metadata APIs, not live host flag
setters or an automatic binding to `CopyStat`. See [image BSD flags](../../docs/appledouble-image-flags.md).

APFS/HFS+ writer entries bind `CopyStat` to offline trees.
`ImageStatCopyResult.Applied` distinguishes publication into all aliases from
private executor completion. Explicit destination times are required; failed
staging leaves entries untouched. See [image stat staging](../../docs/appledouble-image-stat.md)
for validation and diagnostics. The complete held/path APIs provide the qualified
live-host lifecycle integration.

### Sparse Windows replacements

`PrepareReplacementAt` supports NTFS sparse sources. It marks the private
replacement sparse, preserves named streams (including sparse streams), and
leaves all main-data writes to the caller. Original sparse main-data extents
never overwrite the new content. The API preserves the sparse attribute; it
does not promise the original allocation map for content the caller rewrites.
Creation time, ordinary attributes, owner/group and DACL retain the existing
restoration contract. Preparation and discard never modify the source.

The backup filter follows Microsoft's [sparse block stream format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-bkup/6be866e6-6d1f-4183-8b78-b10c2941228a):
sparse blocks belong to the preceding main or named data stream. Named-stream
logical extents and transferred metadata are streamed without the former 8 MiB
aggregate ceiling. Sparse offsets use checked 64-bit arithmetic; malformed,
orphaned, overflowing and truncated records fail before commit. Main-stream data
is never used as replacement content.
The portable filter has a strict coverage gate above 95%; Windows CI also
exercises a source above 4 GiB with populated regions, sparse/ordinary named
streams, hard-link neighbours, commit, discard and staging cleanup.

### Compression observation before a write

`QueryCompressionNoFollow(ctx, path, expected, attributeBytes)` reads native
Darwin compression metadata without opening file contents. This matters when a
resource envelope permits writing and metadata reads but denies data reads:
opening it for reading fails, while opening it for writing can decompress it
before the original codec is observed. Call this query before opening the writer;
use the returned compression description with the shared recompression policy.

`expected` is the regular-file identity already observed by the caller. The
query rejects observed identity, size or compression-flag changes and follows
no final symlink. Its attribute buffer has an explicit budget; it measures a
resource fork without loading its contents. Cancellation and metadata permission
errors remain errors. Native pathname operations resolve independently, so the
caller must exclude concurrent namespace/content changes, including an
adversarial replace-and-restore race. This API does not claim rooted lookup or
snapshot isolation. Prefer `QueryCompression` when a descriptor is already held.

On Linux and Windows, captured Darwin metadata goes directly to
`decmpfs.Query`; receiving-host flags do not represent Darwin compression.
The native pathname provider reports an unsupported native view on those hosts,
while the shared query/codec policy and foreign carrier operations remain portable.

The owned-compression gate requires every new query file above 95% coverage on
all three hosts. The macOS 15/26/27 jobs compile both Clang targets and compare
query bytes, errors, canaries and unchanged metadata with Apple's framework
under ordinary, deny-read, deny-read/write and deny-extended-attribute ACLs.
Artifacts retain the C source hashes, SDK/compiler/host identity and both ASTs.

## Publishing file replacements

Use `PrepareReplacementContext` or `PrepareReplacementAtContext` to stage a
replacement privately. Write and truncate its data, call `RestoreMetadataContext`,
sync and close `File`, and call `PublishContext` over the original source entry.
Always call `Close`, including after publication. Keep the source open and
unchanged through metadata restoration; exclude concurrent changes to the source,
its metadata and parent namespace through publication.

On Linux and Windows FAT/exFAT volumes, preparation reads the filesystem-selected
AppleDouble metadata and constructs fresh storage matching native macOS metadata
copy. `PublishContext` validates the source, staged file and carrier identities,
then publishes the data and its paired carrier. Plain `os.Rename` or `root.Rename`
cannot perform that paired operation. Other filesystems retain their native
rename behavior; neighboring `._` files do not select this route by themselves.

Two foreign filesystem entries cannot be renamed atomically. Cancellation before
publication leaves the original intact. After the data rename, the metadata
operation is attempted even if cancellation arrives. A
`ReplacementPublicationError` reports that data was published but its metadata
operation failed; it does not imply rollback. Inspect the error and retain caller
recovery state. Publication does not promise crash durability.

The fresh carrier encoder retains native attribute order, allocation increments,
alignment and resource-fork storage bytes. Forks stream through 64 KiB buffers.
The qualified macOS 26/27 attribute-file writer rejects nonempty forks shorter
than the 286-byte resource header; macOS 15 accepts them. Portable preparation
defaults to macOS 27. Use `PrepareReplacementWithOptionsContext` or
`PrepareReplacementAtWithOptionsContext` with
`ReplacementOptions{MacOSProfile: osversion.MacOS15}` when targeting the qualified
macOS 15 filesystem behavior. Unsupported profiles fail before staging. These
SDK options do not add codesign CLI flags or select neighboring files as metadata.
macOS uses its actual native VFS operations. The raw AppleDouble codec represents
both accepted and rejected inputs; a failed preparation never publishes a partial
replacement.

`verify-replacement-filesystem.go` captures 220 real FAT/exFAT cases on each of
macOS 15, 26 and 27, including successful copies and partial native failure output.
Collection records the C oracle independently of Go parity and completes native
cleanup before sealing the producer. CI verifies capture sources, both Clang
architecture ASTs, exact profile and current-run integrity, then replays every
producer on Linux, Windows 2022/2025 and macOS 15/26/27. Separate native jobs
compare Go held-copy errors and partial carrier bytes against Apple. Behavioral
baseline checks do not block consumers from receiving complete native evidence.
JSON transcripts and tool diagnostics are separate artifacts. Coverage and the
existing native APFS/HFS+ replacement controls remain required.
