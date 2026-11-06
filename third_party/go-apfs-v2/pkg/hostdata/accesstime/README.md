# accesstime

Held-file access-time operations. `CopyAccessTime` copies native precision on macOS, Linux and Windows. `RecordReadAccess` records an actual Darwin read event without requesting timestamp-write permission; other hosts return its explicit unsupported-native-operation error. Neither operation takes ownership of the descriptor or falls back to a replacement pathname.

Use [hostdata](../README.md) for complete held/path lifecycle operations. The
[package migration guide](../../../docs/hostdata-packages.md) describes import
changes and the unchanged cross-platform qualification requirements.
