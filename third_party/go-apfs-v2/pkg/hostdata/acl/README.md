# acl

ACL record conversion, captured identities and deferred restoration. Use this package when applying an AppleDouble ACL update or preparing Darwin attribute/chmod requests. It owns portable policy and identity capture; the caller supplies the held destination backend. Captured Darwin principals remain source identities on Linux and Windows, rather than being resolved against the receiving host's accounts.

Use [hostdata](../README.md) for complete held/path lifecycle operations. The
[package migration guide](../../../docs/hostdata-packages.md) describes import
changes and the unchanged cross-platform qualification requirements.
