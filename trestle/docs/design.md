# Trestle design

## 1. The problem

XNU does not probe for hardware the way a portable kernel does. Very early —
before the first kext starts — it looks up a fixed set of device-tree nodes and
properties **by path and by name**, and panics if they are absent. The boot log
from the QEMU bring-up shows the shape of it:

```
panic: failed to get chosen node
panic: failed to get options node
panic: failed to get defaults node
panic: failed to get product node
panic: failed to get manifest properties
```

and, once those exist, the next layer down asks for platform devices:

```
panic(cpu 0 caller ...): IONVRAMCHRPHandler creation failed @IONVRAM.cpp:1691
```

Those names, nodes and services are the **Apple virtual platform**: the contract
between the kernel and the machine it is running on. On Apple hardware the SoC
and firmware provide it. On other AArch64 machines it does not exist, and macOS
will not run without it.

Trestle exists to provide it. It is not a general virtual machine; it is a
*purpose-built* platform that satisfies exactly the contract macOS expects,
using real hardware where the contract can be forwarded and software emulation
where it cannot.

Boundary: Gatehouse is the bootloader — it loads a kernel collection, lays it
out and jumps. Trestle is the platform the loaded kernel wakes up inside.

## 2. Layers

```
                 +--------------------------------------------------+
   XNU (EL1)     |           sees: device tree, devices, services   |
                 +--------------------------------------------------+
                        ^                       ^
                        | looked up by path     | MMIO / traps
                 +------+------------------------+------------------+
   Trestle       |  device tree  |  device models  |  trap / route    |
                 +--------------------------------------------------+
                                   |  machine description
                 +-----------------+--------------------------------+
   Machine       |  RAM layout, interrupt controller, timers, ...   |
                 +--------------------------------------------------+
```

The three Trestle sub-systems:

1. **Device models** — one per thing macOS expects: NVRAM, RTC, panic log
   device, the AVP role devices, and so on. Each is a `trestle_device`.
2. **Device tree builder** — turns the set of device models into the native ADT
   blob XNU parses.
3. **Trap/route layer** — delivers guest accesses (MMIO, hypercalls) to the
   owning model. This is the only part that is machine-specific; on the QEMU
   bring-up it may be absent entirely and the device tree alone is enough.

## 3. The device model contract

```c
typedef struct trestle_device {
    const char *name;
    trestle_status (*init)(struct trestle_device *, const trestle_machine *);
    trestle_status (*adt_contribute)(struct trestle_device *, void *node);
    trestle_status (*mmio_read)(struct trestle_device *, u64, usize, u64 *);
    trestle_status (*mmio_write)(struct trestle_device *, u64, usize, u64);
    void           (*deinit)(struct trestle_device *);
} trestle_device;
```

A device is *portable* when its behaviour depends only on `trestle_machine`,
never on a hard-coded address. The address it lives at is decided by the device
tree builder; the model itself is address-free. This is the same separation
Gatehouse uses: the bootloader is portable because the only thing tying it to a
board is `dt/build_adt.py`.

## 4. Case study: NVRAM

NVRAM is the first model because it is small, self-contained, and directly on
the wall the bring-up hit.

### The contract

From Apple's open-source `iokit/Kernel/IONVRAM.cpp`:

* `initProxyData()` reads the `/chosen` property **`nvram-proxy-data`** — the
  whole NVRAM store as one image — into the handler's buffer.
* `getNVRAMSize()` reads the `/chosen` property **`nvram-total-size`**.
* `initNVRAMImage()` walks the image as a sequence of CHRP partitions and
  remembers the `system` and `common` partitions. A store with a `common`
  partition is the minimum required.

The modern (lockdown) handler, `IONVRAMCHRPHandler`, takes the same image and
adds a small authenticated header; the failure in the bring-up is that the image
was never provided at all.

### The image format

```
struct chrp_nvram_header {          // 16 bytes, 16-byte aligned
    u8   sig;                       // 0x70 = system, 0x71 = config
    u8   cksum;                     // the 16 header bytes sum to zero (mod 256)
    u16  len;                       // partition length in 16-byte blocks
    char name[12];                  // "system" / "common" ("2system"/"2common")
};
```

The image is a run of these, each followed by its data area, packed until the
store is full. `src/nvram.c` builds an empty (factory) image: a `system` and a
`common` partition, both zeroed — a zeroed variable area deserialises to the
default dictionary.

### Who writes it

On a real machine, iBoot writes the live image into `/chosen` before starting
the kernel. That is exactly Trestle's job here. The model owns the image; the
device tree builder publishes it as `/chosen`'s `nvram-proxy-data` and
`nvram-total-size`. `tests/nvram_test.c` asserts the produced image has that
shape.

## 5. Device tree ownership

Today the device tree is produced offline, by `gatehouse/dt/build_adt.py`, and
the NVRAM contribution is mirrored there so the QEMU bring-up can move without
Trestle running yet. That mirror is the *contract*, not the architecture.

The target is for Trestle to own the tree: each device's `adt_contribute` emits
its nodes and properties, and Gatehouse asks Trestle for the finished blob
before it jumps. At that point `build_adt.py` becomes the bring-up stand-in for
the Trestle tree builder, and the two are kept in step by tests.

## 6. Machine portability

| Concern | Portable part | Machine-specific part |
|---------|---------------|-----------------------|
| Device behaviour | the model (`src/*.c`) | none |
| Where devices live | device tree builder | nothing |
| How accesses arrive | the model's `mmio_*` | the trap/route layer |
| Where RAM is | `trestle_machine` | supplied by Gatehouse |

The plan is that no file under `src/` mentions a board: the same NVRAM model
serves the QEMU bring-up, a later hypervisor build, and real hardware.

## 7. Relationship to Gatehouse

```
Gatehouse (UEFI)  ->  load + lay out kernel collection
                  ->  build/obtain the device tree  (build_adt.py today, Trestle later)
                  ->  hand control to XNU
```

Trestle is loaded and brought up by Gatehouse before the jump. Which exception
level Trestle sits at (EL2 as a hypervisor, EL1 as a platform library) is a
bring-up decision, not a design one: the device models are the same either way.

## 8. Roadmap

1. **NVRAM** — done (model + image + tests); unblocks `IONVRAMCHRPHandler`.
2. **Device tree builder** — move ADT construction into Trestle; make devices
   contribute their own nodes.
3. **The rest of the early platform** — the devices the next failures ask for
   (RTC, panic log, the AVP role devices seen in the authentic ADT:
   `avp,rtc`, `qemu,pvpanic-mmio`, `paravirtualizedgraphics,*`).
4. **Trap/route layer** — only once a device must be emulated rather than
   described.

## 9. Non-goals

* Being a general-purpose hypervisor. Trestle serves one guest and one
  contract.
* Reimplementing Apple firmware. It builds the *minimum* platform macOS
  accepts, and grows only when a failure demands it.
