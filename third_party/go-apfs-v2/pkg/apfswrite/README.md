# pkg/apfswrite — APFS file system writer

A pure-Go writer that builds a complete APFS container from scratch: an empty
single-volume container, or one populated with a directory tree of files,
symbolic links and nested directories. The whole container is written as one
static checkpoint (transaction id 1), so every object is laid out in its final
position up front — no copy-on-write mutation.

This package is MIT-licensed, like the rest of the repository (`pkg/apfs`,
`pkg/hfsplus`, `pkg/disk`).

## Provenance and licensing

This writer began as a study of **mkapfs**, part of
[apfsprogs](https://github.com/linux-apfs/apfsprogs) by Ernesto A. Fernández
(GPL-2.0), which was used as a reference and a springboard for understanding
how APFS lays a container out. It has since been reimplemented independently
from Apple's *Apple File System Reference* — with its own code structure,
checkpoint-area sizing and space manager layout — and shares none of mkapfs's
source expression. It is therefore original work under the MIT license.

Where a container must carry values that Apple's APFS implementation validates
when it mounts a volume (for example the space manager free-queue node limits),
those values are reproduced as functional interoperability requirements of the
format, verified against Apple's `fsck_apfs`/`hdiutil` and the Linux `apfsck`.

## Deferred AppleDouble ACL restoration

Use `root.RestoreACL(destinationEntry, update)` with the result of
`appledouble.File.ACLUpdate`. It stages an ACL replacement while preserving
ownership, permissions and unrelated metadata, and updates regular hard-link
aliases together. `hfsplus.Entry` exposes the same API. The operation runs in
pure Go on all platforms; serialize the resulting tree separately. See
[image ACL restoration](../../docs/appledouble-image-acl-restoration.md) for
validation, native qualification and the remaining integration work.

## Exact permissions

Set `Entry.ModeExplicit` when `Mode` contains captured or explicitly requested
permissions, including `0000`. Both APFS and HFS+ writers retain Go's
`os.ModeSetuid`, `os.ModeSetgid` and `os.ModeSticky` bits; both readers expose them
through `FileInfo.Mode`. With `ModeExplicit` false, existing low-permission
defaults remain. Host-directory walkers set it automatically. See
[image permission preservation](../../docs/appledouble-image-modes.md) for root
semantics, native qualification and the remaining security integration work.

## Block size

Containers are written with a 4096-byte block, and that is the only size
accepted. The format allows any power of two up to 65536, and this writer's
arithmetic is parameterised by block size throughout, so the larger sizes look
supported — but the containers that came out were unsound, not merely unusual.
At 16384 both `fsck_apfs` and `apfsck` reject the result; at 65536 `fsck_apfs`
spins without reaching a verdict. All non-4096 sizes are also unreadable by
`pkg/apfs`, which reads a fixed-size container superblock and so verifies a
different checksum span than the writer sealed.

`CreateOptions.BlockSize` is retained and deprecated rather than removed.

## Validation

Created containers are checked three ways: by our own reader in
`pkg/apfs`, Apple's `fsck_apfs` and `hdiutil` (macOS), and `apfsck` (Linux).

## Volume-root metadata

`CreateOptions.Root` and `VolumeSpec.Root` retain root ownership, mode, time and
extended attributes, including ACLs and streamed values, even with no children.
The root name, payload and link group are ignored; explicit non-directory types
fail. Zero mode defaults to directory 0755; explicit `os.ModeDir` permits 0000.
See [root metadata and native qualification](../../docs/appledouble-root-metadata.md)
for defaults, native attribute visibility and compatibility details.

### Ordinary security copying

`root.CopySecurity(target, source, options)` stages an ordinary captured security
copy, including inherited ACL selection and numeric permission/ownership policy.
The equivalent API exists in HFS+. See [image security copying](../../docs/appledouble-image-security-copy.md)
for its completion contract, native qualification and remaining host integration.

### Independent timestamps

Set `Entry.Times` to a `hostdata.FileTimes` value to retain separate birth,
modification, change and access times. Nil keeps existing `ModTime` defaults.
Both image readers expose `Volume.FileTimes(name)` without following symlinks. See
[image timestamps](../../docs/appledouble-image-times.md) for clamping, precision,
validation and native qualification.

### BSD flags

Set `Entry.BSDFlags` to preserve ordinary inode flags, including explicit zero.
Nil keeps legacy compression inference. Both readers expose `Volume.BSDFlags`;
HFS+ has the same entry field. Tracked entries receive new-volume document IDs.
See [image BSD flags](../../docs/appledouble-image-flags.md) for compression
validation, HFS catalog mapping, native evidence and limits.

### Ordered stat restoration

`root.CopyStat(target, source, options)` stages modification/access times,
ownership, permissions and selected BSD flags into target and its hard-link
aliases. Destination `Times` must be explicit. Inspect `Applied` and executor
diagnostics before serializing. HFS+ exposes the same API; see
[image stat staging](../../docs/appledouble-image-stat.md).

### Filename policy

`CreateOptions.TargetVersion` selects the macOS creation policy for ordinary
filesystem entries. Set `osversion.Version{Major: 15}`, `26`, or `27` explicitly
when targeting that version. The zero value selects macOS 27 on every host;
it never queries the operating system running the writer.

The writer validates all volume trees before writing image bytes. It rejects
names that the selected native profile cannot create, overlong components,
malformed UTF-8, and equivalent siblings under the volume's case policy.
Case-insensitive APFS uses canonical decomposition and full default case folding;
case-sensitive APFS still treats canonical equivalents as the same name.
Volume labels and snapshot names retain their separate validation contracts.

Creation admission is separate from reading existing images. An older filesystem
may contain names that a selected newer or older creation profile would reject;
readers compare the stored keys without applying a new-creation policy. See
[filename compatibility](../../docs/filename-compatibility.md) for the native
fixtures, raw-pathname boundary, and qualification commands.
