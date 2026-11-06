# AppleDouble

AppleDouble stores macOS file metadata in a separate file, usually named
`._<filename>`. For example, `._Report.pdf` can carry the Finder information,
resource fork and extended attributes belonging to `Report.pdf`.

`pkg/appledouble` reads and writes those metadata bytes in pure Go. It also
interprets serialized macOS ACLs (access control lists) and quarantine envelopes.
The same implementation
works on Linux, macOS and Windows without cgo, macOS commands or access to a host
account database.

## Why this package exists

Copying a file's main contents is not always enough to preserve the file.
Resource forks can contain additional content; Finder information affects how
macOS presents a file; extended attributes can carry application and security
metadata. Archives and filesystems may need a separate place to store it.

AppleDouble provides that container. This package gives image tools, package
builders and metadata-preservation tools a shared way to interpret it, so each
consumer does not need to implement its own binary codec or require a Mac just
to process the bytes.

## When to use it

| Situation | Use this package to |
| --- | --- |
| Reading an archive or package payload containing `._` files | Decode the sidecar and inspect the metadata belonging to its companion file. |
| Building a package or archive that carries macOS metadata | Encode captured metadata into an AppleDouble sidecar. |
| Preserving metadata across filesystems or operating systems | Encode and decode the metadata container used by the surrounding transport layer. |
| Inspecting a serialized `com.apple.acl.text` record | Convert between ACL text, structured entries and portable external binary bytes. |
| Inspecting a serialized `com.apple.quarantine` record | Parse its envelope or construct canonical serialized quarantine bytes. |

The package operates on bytes. Filesystem reads/writes, choosing where to store a
sidecar, resolving filename conflicts and applying permissions belong to the
surrounding metadata layer. Shared filesystem operations live in `pkg/hostdata`;
`pkg/metatransport` supplies the explicit portable carrier, and APFS/HFS+ readers,
writers and the CLI bind that carrier to extraction and repacking.
[`pkg/recompression`](../recompression) owns foreign compression operations; it
uses the carrier without putting compression policy into the byte codec.

## What it provides

- **Sidecar encoding and decoding:** `File`, `Attr`, `FromXattrs`, `Encode` and
  `Decode` carry FinderInfo, resource forks and extended-attribute records.
- **Streamed metadata:** `Value`, `StreamFile`, `DecodeStream` and `EncodeTo`
  retain sized borrowed readers and use bounded scratch space. Keep their image,
  file or carrier owners open and exclude mutation until consumption finishes.
- **Compressed logical contents:** the shared storage decoder reads large
  resource-fork indexes without retaining the complete table. Native kernel
  controls cover logical sizes around 1, 2 and 4 GiB; Linux, macOS and Windows
  verify complete decoded hashes. See [compression storage](../../docs/appledouble-compression-storage.md#large-compressed-files)
  for the distinction between retained compression metadata and recompression.
  [`compression/decmpfs.EncodeFork`](../../docs/compression-writer.md) supplies
  bounded creation of new compressed fork bytes; `Encode` adds native content
  selection and `Query` provides bounded metadata inspection. LZ4 types 15/16
  are readable through the shared storage decoder. Callers own installation policy.
- **Complete metadata operations:** `hostdata.PackAppleDoubleObject` and
  `UnpackAppleDoubleObject` operate on held objects; `CopyAppleDoublePath` adds
  creation/opening, temporary permission handling, retries and owned-descriptor
  cleanup. Captured source context supplies the same logical policy on Linux
  and Windows. These native-style operations preserve native omissions and
  partial failures; lossless transport uses the carrier and image APIs. See
  [object operations](../../docs/appledouble-object.md) and
  [path lifecycle](../../docs/appledouble-path-lifecycle.md).
- **Logical metadata:** `Xattrs` resolves ordinary duplicate attributes and the
  implemented FinderInfo/resource-fork write semantics. `File.Attrs` retains
  ordered records for consumers that need to inspect them directly.
- **Naming helpers:** `IsSidecarName`, `SidecarName` and `OwnerName` work with
  sidecar path names. The caller is responsible for establishing which files
  actually belong together.
- **ACL conversion:** `ParseACLText` and `ParseACLBinary` produce an `ACL`.
  `MarshalBinary` exports portable `acl_copy_ext` bytes; `MarshalText` formats
  canonical text using UUIDs. `FormatText` accepts a source UUID-to-account resolver
  when names and IDs are needed. Name/UID/GID-only text input requires an
  `ACLResolver` using source identity information.
- **ACL update decisions:** `File.ACLUpdate` selects the last nonempty ACL record
  and reports whether to preserve or replace the destination ACL. Malformed text
  is explicitly marked as ignored; a valid zero-entry ACL requests clearing.
- **Complete security records:** `FileSecurity` preserves owner/group UUIDs, ACLs
  and opaque bytes in disk and Darwin memory byte orders. `ACLUpdate.FileSecurity`
  prepares a replacement using captured destination ownership. See
  [security records and native write refusals](../../docs/appledouble-filesec.md).
- **ACL creation inheritance:** `InheritACL` computes a new file or directory's
  ACL from captured parent and initial ACLs, including propagation flags and
  allocation limits. It runs on every supported OS without applying host
  permissions. A subsequent valid AppleDouble ACL update replaces this result;
  see [creation and restoration](../../docs/appledouble-acl-inheritance.md).
- **ACL copy policy:** `CopyACL` keeps explicit source entries followed by
  inherited destination entries, preserving entry order and bits while dropping
  global flags. It is distinct from creation inheritance and AppleDouble
  replacement. See [ordinary ACL copies](../../docs/appledouble-acl-copy.md).
- **Image security capture:** APFS/HFS+ readers expose ownership, mode, UUID and
  ACL snapshots for portable security copying, with malformed/empty/absent
  records distinguished and native comparisons on four filesystem variants.
  See [image security capture](../../docs/appledouble-image-security.md).
- **Deferred image ACL restoration:** APFS/HFS+ writers expose
  `root.RestoreACL(destinationEntry, update)` to stage the selected replacement,
  preserving ownership and exact permissions and updating hard-link aliases
  together. It works on every OS; writing the resulting image is a separate step.
  See [image ACL restoration](../../docs/appledouble-image-acl-restoration.md).
- **Ordinary image security copying:** APFS/HFS+ writers expose
  `root.CopySecurity(destinationEntry, source, options)` for ACL inheritance
  merging, selected numeric properties, removal and set-ID policy. Source
  validation and all alias updates precede image serialization on every OS.
  See [image security copying](../../docs/appledouble-image-security-copy.md).
- **Ordered image stat staging:** both writer trees expose `root.CopyStat` for
  modification/access times, ownership, permissions and BSD flags. All aliases
  publish together after validation; failed staging leaves the tree unchanged.
  See [image stat staging](../../docs/appledouble-image-stat.md).
- **Ordered unpack execution:** `hostdata.RestoreAppleDouble` decodes a captured
  sidecar before destination changes, then executes cleanup, ordered records,
  dedicated FinderInfo/fork slots, deferred ACL and final stat through held
  providers. Native return codes remain separate from retained failures. See
  [unpack restoration](../../docs/appledouble-unpack-restoration.md).
- **Held destination names:** `hostdata.ListXattrNames` provides bounded native
  enumeration on Linux, macOS and Windows, retaining descriptor identity, native
  order and failure diagnostics. It is a prerequisite for the complete unpack
  provider. See [held-file listing](../../docs/appledouble-held-xattr-list.md).
- **Source identity capture and replay:** `NewACLIdentityCapture` records the
  source callbacks used during parsing and formatting. Its serializable snapshot
  supplies immutable resolvers on any supported OS, preserving confirmed absence
  and rejecting uncaptured queries. See [source identities](../../docs/appledouble-acl-identities.md).
- **Quarantine conversion:** `ParseQuarantine` reads the serialized `q/` envelope;
  `Quarantine.MarshalBinary` writes canonical bytes. These APIs handle escaping,
  field limits and native parsing quirks without applying destination policy.
  The default targets macOS 27. The `WithProfile` variants explicitly select
  macOS 26 or 27 behavior on any supported operating system.
- **Quarantine application planning:** `Quarantine.PlanApplication` computes exact
  destination bytes, preservation decisions and specific errors for qualified
  effective process contexts, including explicitly confirmed process-label absence
  for the macOS 26 target profile. It requires explicit process/destination state and
  an injected timestamp; it never reads the Go host's policy. See
  [application planning](../../docs/appledouble-quarantine-application.md) for
  supported contexts and the remaining transport work.
- **Filesystem quarantine import:** `ParseQuarantineXattr` and its `WithProfile`
  variant interpret a captured filesystem xattr, including its separate stored
  size limit. The caller supplies the bytes and handles filesystem read errors.
- **Quarantine update decisions:** `File.QuarantineUpdates` preserves record order
  and reports ignored malformed records. Optional resolved source quarantine
  state overrides each matching record, including empty records.

Always check encoding and decoding errors. FinderInfo must contain exactly 32
bytes. `Sniff` is a format hint; `Decode` performs validation. Canonical encoding
can change padding or layout while preserving logical metadata.

ACL and quarantine parsing are explicit. The raw codec preserves ACL and
quarantine payloads;
executing ACL update decisions or restoring quarantine state is a
separate operation. Binary ACL conversion retains unknown bits and entry kinds;
text formatting follows macOS by emitting only known bits and allow/deny entries.
Use the binary representation when those additional details must be preserved.

## Example

```go
import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

func encodeMetadata(attrs map[string][]byte) ([]byte, error) {
    return appledouble.FromXattrs(attrs).Encode()
}

func decodeMetadata(sidecar []byte) (map[string][]byte, error) {
    metadata, err := appledouble.Decode(sidecar)
    if err != nil {
        return nil, err
    }
    return metadata.Xattrs(), nil
}
```

The caller supplies or consumes the metadata map and handles filesystem access.
Use `File.Attrs` instead of the map when duplicate record order matters.

## Roadmap

The byte codec, streamed carrier and composed metadata operations are implemented.
Their existing native capture, fuzzing, race, cross-host image readback and strict
coverage gates remain mandatory when shared filesystem behavior changes. The
[completion plan](../../docs/appledouble-completion-plan.md) and
[completion matrix](../../docs/appledouble-completion-matrix.md) retain the detailed
qualification contract; component tests alone do not close an integration gate.

The remaining work serving codesign is in the surrounding operation packages:

| Area | Remaining work |
| --- | --- |
| Filesystem-selected metadata | Complete version-qualified mutations, association/lifecycle handling and codesign integration after the [shared filesystem reader](../../docs/metadata-filesystem.md); retain genuine macOS 15/26/27 captures and foreign readback |
| Foreign recompression | Qualify [the recompression package](../recompression) on every host, including genuine macOS 15/26/27 acquisition and permission captures, partial publication and native readback of foreign-produced images |
| Operation integration | Consume the qualified shared APIs in codesign, preserving native compression applicability, admission failures and post-commit outcomes |
| Scale and lifecycle | Complete downstream shared memory/storage/handle accounting, populated large-file acceptance and operation failure/cancellation matrices |
| Release and adoption | Qualify the maintained APFS batch release and recapture downstream dependency provenance before closing codesign Phase 2 |

Keep these boundaries explicit:

- AppleDouble represents metadata bytes. Its wire limits do not become arbitrary
  resource-fork limits in the carrier or image formats.
- Native-style metadata operations retain observed omissions and partial effects.
  Lossless transport retains explicit source state without a global mode switch.
- Carrier records associate payloads and verified immutable values. Arbitrary
  neighboring `._` files are never automatically selected as metadata.
- Foreign operation policy requires explicit target, identity and volume context.
  Linux or Windows storage does not itself enforce Darwin ACL or process policy.

Use `apfs extract IMAGE -C PAYLOAD --xattrs --preserve-meta --metadata-root METADATA`
to select portable storage, and `apfs pack PAYLOAD OUTPUT.dmg --metadata-root METADATA`
to supply that association explicitly when repacking. The payload destination must
be empty, and metadata must live outside it. Keep the metadata directory with the
payload. The existing flags select which metadata categories to capture.

Native-style sequential unpack owns an incoming resource fork as one buffer and
uses an explicit workspace budget. The object defaults are 64 MiB active space;
simultaneous input/write copies plus header/ACL storage mean less than a 32 MiB
fork fits that default. Callers can raise the budget. This is not a filesystem
size limit. The streaming carrier and image APIs preserve larger values without
whole-fork allocation; AppleDouble's own unsigned 32-bit fork length remains a
format limit. See [large resource forks](../../docs/appledouble-large-values.md)
for the real 4 GiB + 17 byte qualification and foreign-image checks.

New implementation PRs remain draft through complete CI qualification. The
maintainer controls the batch release and downstream phase-closure decision.

### Filesystem attribute removal

`DecodeFilesystemStream` interprets a carrier as filesystem-visible storage.
Unlike snapshot decoding, it rejects the zero-offset empty ATTR records produced
by `COPYFILE_PACK`, matching the native namespace rejection. Native VFS-created
empty values with a data offset remain readable and removable. `DecodeStream`
continues to preserve valid packed snapshots for transport and unpacking.

`RemoveFilesystemAttribute` mutates an already-authorized VFS-layout carrier
without canonical repacking. It preserves unrelated bytes and uses bounded
streaming shifts for large values. The filesystem owner handles association,
permissions, unlink and cleanup; `hostdata.FilesystemMetadata.Remove` provides
that integration. See [filesystem-selected metadata](../../docs/metadata-filesystem.md)
for native evidence, rejected mutation layouts and remaining qualification.

### Fresh filesystem attribute storage

`StreamFile.EncodeFilesystemTo` constructs a fresh macOS filesystem attribute
file from visible FinderInfo, ordered ordinary attributes and a resource fork.
Use it when creating a replacement carrier. `EncodeTo` continues to produce
`COPYFILE_PACK` transport output; the two layouts have different allocation and
padding rules. Existing carriers should continue through the mutation APIs when
the operation changes existing storage rather than creating a replacement.

Filesystem encoding streams values with bounded working memory, retains native
allocation slack and installs the blank resource-fork marker when appropriate.
Empty visible metadata produces no carrier bytes. Association, authorization,
publication and cleanup belong to the filesystem layer (`hostdata`); encoding
alone does not safely replace a neighboring `._` file. The native replacement
matrix exercises allocation boundaries and forks around 286 bytes and 64 KiB.
