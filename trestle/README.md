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
| NVRAM device model (the `/chosen` store contract) | done, host-tested |
| Device tree builder (`adt.c`) | done, host-tested |
| The platform's own nodes (`platform_nodes.c`) | done, host-tested |
| Early platform devices (RTC, power manager, panic log, CTRR) | done, host-tested |
| Machine descriptions (QEMU virt, the AVP) | done |
| EL2 trap layer (MMIO routing to device models) | planned |
| Trestle on the boot path (Gatehouse calls `trestle_main`) | planned |

## Build

```sh
make            # libtrestle.a (aarch64-none-elf)
make test       # host-side model tests
```

`make test` builds both machine descriptions' trees and checks the properties
the boot path depends on. It can also write the bring-up tree out so
`../tools/adt_diff.py` can compare it, node for node, with the one
Gatehouse's `dt/build_adt.py` generates:

```sh
tests/adt_test /tmp/trestle.adt
../tools/adt_diff.py ../build/gatehouse.adt /tmp/trestle.adt
```

## The NVRAM device

The first device is the smallest one on the boot critical path. XNU reaches
non-volatile storage through `IONVRAM`, which takes its store from the device
tree: `/chosen`'s `nvram-bank-size` is the image size and `nvram-proxy-data` is
the image itself (`iokit/Kernel/IONVRAM.cpp`). The factory accepts it only when
it is a V3 image — the CHRP branch builds a handler that faults on first use.
The device model in `src/nvram.c` owns that image, builds a well-formed,
factory-empty one, and publishes it. See `docs/design.md`.

## Layout

```
include/trestle.h        core types, device contract, machine description
include/adt.h            the device tree builder
include/machines.h       the machine descriptions
include/nvram.h          NVRAM store
include/rtc.h            PL031 and the AVP RTC
include/pmgr.h           the power manager and the PSCI conduit
include/panic.h          the panic log (/pram) and pvpanic
include/aprr.h           CTRR and the sealed registers
src/boot.c               the platform's device list, assembled
src/platform.c           the device registry and window lookup
src/adt.c                building and serialising the tree
src/platform_nodes.c     the platform's own nodes (identity, /chosen, ...)
src/machines.c           where each machine's hardware is
src/main.c               entry point
tests/                   host-side model tests
docs/design.md           architecture
```

## Licence

GPL-2.0-or-later, like the rest of HackintARM. See `../LICENSING.md`.
