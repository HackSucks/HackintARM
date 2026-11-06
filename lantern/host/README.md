# Lantern host probe

`lantern-probe` checks that the pinned reims-vgpu C API can create both the
GPU and IOSurface devices over a file-backed RAM range. It prints their initial
register values and releases them cleanly. It does **not** connect to QEMU or
implement the EL2 transport; that remains the next integration step.

The prototype in `/tmp/opencode` includes the exact pinned reims-vgpu source
tree at `1fe0acb68b287db36f1e6c7b9f45383940b8a76f` and a successful Cargo build
log. Build the distributable C library from that checkout:

```sh
cd /tmp/opencode/reims-vgpu
cargo xtask dist --platform vulkan --out /tmp/opencode/reims-dist
```

Then build and run this probe:

```sh
cd /mnt/newvol/hackintarm/lantern/host
PKG_CONFIG_PATH=/tmp/opencode/reims-dist/lib/pkgconfig make
LD_LIBRARY_PATH=/tmp/opencode/reims-dist/lib ./lantern-probe
```

By default it creates and removes a 64 MiB temporary RAM file. To use an
existing file-backed guest RAM image, pass its path and mapped size:

```sh
LD_LIBRARY_PATH=/tmp/opencode/reims-dist/lib \
  ./lantern-probe --ram-file /path/to/guest-ram --ram-size 8589934592
```

The probe maps the file `MAP_SHARED` and passes both the host mapping and file
descriptor to reims-vgpu. The caller must ensure the file represents the same
physical range and offset as the guest's RAM. It does not initialize or clear
an existing file.
