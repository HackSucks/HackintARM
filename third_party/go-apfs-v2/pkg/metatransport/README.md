# Metadata transport

`metatransport` preserves logical file metadata in a separately selected directory.
Use it when the payload filesystem cannot store a Darwin attribute name, an empty
value, a resource fork, an ACL or the original inode properties faithfully. The
same carrier works on Linux, macOS and Windows without cgo or native commands.

The caller supplies two existing, non-overlapping directories: the payload root
and metadata root. Nothing discovers metadata by scanning for `._` filenames.
An ordinary user file named `._Report` remains ordinary content.

## Storage and association

A version 1 `manifest.json` maps original relative names to materialized names.
Each record identifies its logical and materialized object type, original link
target, logical hard-link group, regular-file content baseline, attributes and
optional Darwin state. Numeric IDs, mode, flags and each of the four inode times
have explicit presence. Recording an ACL does not claim that the host enforces it.

Values are immutable `blob-<sha256>` files. Their references include exact sizes;
readers verify both size and the complete SHA-256. Attribute names use base64
`nameBytes` in JSON so native non-UTF-8 names are not silently replaced. An optional
canonical AppleDouble blob accompanies the raw values where the AppleDouble
format can represent them. `ReadRecordAttributes` verifies that this duplicate
representation agrees with the raw attributes before returning metadata.

The manifest is not an authentication mechanism. The caller owns and trusts the
metadata root and excludes uncoordinated modification during operations. Paths
are relative to held `os.Root` handles, overlapping roots are rejected, and
payload association checks reject symlinks in intermediate path components.
`VerifyPayload` checks a record's content or link baseline separately: loading a
manifest does not reject an intentional edit to an ordinary data fork.

## Using a carrier

```go
store, err := metatransport.Open(payloadDir, metadataDir, metatransport.DefaultLimits())
if err != nil {
    return err
}
defer store.Close()

attrs, err := store.StoreAttributes(ctx, capturedAttributes)
if err != nil {
    return err
}
// Supply a record with an established payload association and logical state.
record.Attributes = attrs
manifest := metatransport.Manifest{Version: 1, Records: []metatransport.Record{record}}
return store.Commit(ctx, manifest, 0)
```

`PutBlob` accepts a borrowed `io.ReaderAt` and an explicit length, copying with a
64 KiB buffer. `OpenBlob` returns a verified file owned by the caller.
`ReadAttributes` and `ReadRecordAttributes` materialize snapshots under an explicit
aggregate value budget. `BorrowBlob`, `BorrowPayload` and
`BorrowRecordAttributes` return sized `ReaderAt` values without retaining an open
file descriptor per value. Their owner must remain open; `Store.Close` invalidates
them. Each read checks held-root association, identity and size. The caller excludes
concurrent content edits, including same-size changes.

`MergeAttributes` combines complete native and carrier captures. Equal values
coalesce; conflicting values return `ErrConflict`. Name comparison is exact,
including case. An empty value remains distinct from an absent name. Returned
snapshots own their bytes.

Extraction records a separate native materialization baseline. `NativeCaptured`
distinguishes an observed empty namespace from missing capture; `NativeUnsupported`
records a host that cannot expose the namespace. `ReconcileAttributes` and
`ReconcileAttributeValues` subtract unchanged baseline values before merging with
logical metadata. This prevents host-created attributes from leaking into the
source image without ignoring names such as `com.apple.provenance`. New or changed
native attributes must agree with overlapping logical values. Deleting an attribute
that belongs to both the baseline and logical source produces an explicit conflict.

## Publication and failure

Blobs publish before the manifest. A shared exclusive writer lock protects
publication without requiring filesystem hard links, so FAT/exFAT carriers can
use the same operations. `Commit` checks the expected generation and advances it
once. Concurrent writers and stale generations fail explicitly.

Missing or corrupt referenced blobs prevent publication. Cancellation, short
reads/writes, budget exhaustion and filesystem failures propagate. Failed work
can leave unreferenced immutable blobs, but cannot turn an incomplete manifest
into a successfully loaded empty metadata set. An abandoned lock requires explicit
operator recovery; no timeout guesses that another writer has stopped.

Publication is not a transaction covering native payload changes or a promise
of crash durability for the entire tree. Callers retain operation diagnostics and
must check close errors. A loaded manifest and its referenced files must remain
unchanged while a caller uses them.

## Image directory packing

Both APFS and HFS+ `WalkOptions` accept `MetadataRoot`, `MetadataLimits`,
`CaptureLimits` and `Context`. Selecting a metadata root restores its recorded
metadata independently of the legacy `Xattrs` selector. The shared walker restores
original names, degraded symlinks, hard-link groups, root metadata, exact modes,
IDs, four captured times and BSD flags. It rejects ambiguous names, orphaned
records, conflicting host attributes and inconsistent hard-link aliases.

An ordinary edited data fork is repacked with its retained metadata. Reusing
original compressed storage first verifies the extracted data baseline; editing
the decompressed payload cannot silently discard that edit. Explicit decompression
uses the edited data and removes the corresponding compression storage/flag.

`OpenEntryTreeFromDir` returns an owned tree with `Root`, `Report` and `Close`.
Its regular file contents and carrier attributes use borrowed sized readers;
keep the tree open through image creation, then close it. The APFS reader exposes
`XattrValues`; its writer accepts `Entry.DataValue` and `Entry.XattrValues` without
materializing large values. Borrowed sources must remain immutable and open through
`CreateContainer`. Existing `EntryTreeFromDir` and `Xattrs` APIs retain their owned
byte-slice contracts.

Ordinary native attribute acquisition remains explicitly budgeted. Initial and
post-projection native baselines use held capture and streamed blob publication;
Darwin regular-file resource forks do not inherit a whole-value allocation limit.
Format and layout bounds remain enforced before image publication. The
[large-value qualification](../../docs/appledouble-large-values.md) exercises a
real fork beyond the AppleDouble 32-bit length field through the carrier, both
image formats and native macOS readback. Complete native copy/unpack policy,
authorization and lifecycle qualification remain separate requirements.

## Held payload publication

`OpenPayload` returns an owned read/write descriptor after rooted regular-file
identity checks. `CheckPayload` revalidates its pathname association.
`PayloadReference`, `VerifyHeldPayload` and `CopyPayload` share the carrier's
bounded hashing and copy implementation without acquiring new pathnames.

`Publish` prepares and validates the next generation before invoking a payload
transition under the writer lock. The callback can read the store and use held
payloads; it must not recursively write the store or close it. Store closure waits
for the callback. The returned publication boolean remains true if rename
succeeded but lock cleanup failed. Payload effects are not rolled back.

Foreign compression policy belongs to [`recompression`](../recompression), which
uses these general storage primitives. Merely retaining a compressed attribute
does not request recompression or activate that storage.
