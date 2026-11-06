# diskspace

Native writable-space queries for the current user. `AvailableSpace` reports the bytes available to that user in the target filesystem, including reserved space or quota effects. Use it before allocating an image or scratch file. A query error is preserved; lack of a host capability is distinct from zero available space.

Use [hostdata](../README.md) for complete held/path lifecycle operations. The
[package migration guide](../../../docs/hostdata-packages.md) describes import
changes and the unchanged cross-platform qualification requirements.
