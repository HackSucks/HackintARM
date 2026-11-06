# bsdflags

Reading BSD inode flags from host file information. `Flags` returns the native value and whether the host exposes it. A false availability result does not describe absent logical Darwin flags: preserve those through the image or carrier metadata instead. This package does not change flags or infer them from xattr names.

Use [hostdata](../README.md) for complete held/path lifecycle operations. The
[package migration guide](../../../docs/hostdata-packages.md) describes import
changes and the unchanged cross-platform qualification requirements.
