# Trestle

Trestle is the HackintARM **platform layer**. Gatehouse boots; Trestle provides
the machine.

macOS on Apple Silicon is not a general-purpose kernel: it expects the Apple
virtual platform (AVP) around it — a device tree describing AVP devices, the
services those devices expose, and a handful of named nodes the kernel looks up
by path early in bring-up. On real Apple hardware that platform is the SoC and
the firmware. On anything else it has to be synthesised. That is Trestle.

Trestle is:

* **Machine-portable.** Device models never touch a fixed physical address;
  the machine description is passed in (`trestle_machine`).
* **Freestanding.** No C library, no allocator assumptions, builds as a
  static library to link into a bare-metal image.
* **Device-oriented.** The unit of work is a *device model* implementing a
  small, uniform contract (`trestle_device`), whether it is emulated in
  software, paravirtualised, or forwarded to host hardware.

## Status

| Piece | State |
|-------|-------|
| Device-model framework (`trestle_device`, `trestle_platform`) | done |
| NVRAM device model (`IONVRAMCHRPHandler` contract) | done, host-tested |
| Device tree ownership | planned — today Gatehouse's `dt/build_adt.py` owns the tree |
| EL2 trap layer (MMIO routing to device models) | planned |

## Build

```sh
make            # libtrestle.a (aarch64-none-elf)
make test       # host-side device-model tests
```

## The NVRAM device

The first device is the smallest one on the boot critical path. XNU reaches
non-volatile storage through `IONVRAMCHRPHandler`, which takes its store from
the device tree: `/chosen`'s `nvram-total-size` is the store size and
`nvram-proxy-data` is the image, a run of 16-byte-aligned CHRP partitions
(`iokit/Kernel/IONVRAM.cpp`). The device model in `src/nvram.c` owns that image
and builds a well-formed, factory-empty one. See `docs/design.md`.

## Layout

```
include/trestle.h    core types, device contract, platform registry
include/nvram.h      NVRAM device + CHRP image format
src/platform.c       device registry
src/nvram.c          NVRAM device model
src/main.c           entry point
tests/               host-side model tests
docs/design.md       architecture
```

## Licence

GPL-2.0-or-later, like the rest of HackintARM. See `../LICENSING.md`.
