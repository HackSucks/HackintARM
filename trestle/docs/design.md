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
panic(cpu 0 caller ...): IONVRAMV3Handler creation failed @IONVRAM.cpp:1688
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
    trestle_status (*adt_contribute)(struct trestle_device *, trestle_adt *);
    trestle_status (*mmio_read)(struct trestle_device *, u64, usize, u64 *);
    trestle_status (*mmio_write)(struct trestle_device *, u64, usize, u64);
    void           (*deinit)(struct trestle_device *);
} trestle_device;
```

A device is *portable* when its behaviour depends only on `trestle_machine`,
never on a hard-coded address. The machine description says where each device's
registers are (`trestle_machine_window`: a name, an offset from the SoC base, a
size and its GIC interrupt id), and `init` is where a model resolves its own
windows; a window that the machine does not have means the device is not
present, and the model then contributes no nodes at all. `adt_contribute` is
where it publishes what it *does* have, into the shared builder. So the same
model serves QEMU's virt machine and the Apple virtual platform, and the only
file that changes between them is `src/machines.c`.

## 4. Case study: NVRAM

NVRAM is the first model because it is small, self-contained, and directly on
the wall the bring-up hit.

### The contract

The modern kernel does not link `IONVRAMCHRPHandler` from the old open-source
`IONVRAM.cpp`; the classes moved into XNU. Reversing the factory in the shipping
kernel collection gives the real contract. It reads `/chosen` and picks a
handler from the *contents* of the store:

```
entry = IORegistryEntry::fromPath("/chosen")
bank  = entry->getProperty("nvram-bank-size")
image = entry->getProperty("nvram-proxy-data")

if (image[0..3] == 0x4e565633 && image[0xe] == 1 && bank >= 0x18)
        IONVRAMV3Handler::create(this, image, bank)     // with the image
else
        IONVRAMCHRPHandler::create(this, NULL, bank)    // with *no* image
```

The CHRP branch is the trap. It builds a handler over a `NULL` image, so the
partition offsets stay at their `-1` sentinel and the first access faults. It is
not a fallback that can be satisfied by device-tree data; the store must be a V3
image.

`IONVRAMV3Handler::create()` then calls `init()`, which requires, on `/chosen`:

| property | type | meaning |
|----------|------|---------|
| `nvram-bank-size` | OSData(u32) | bank size; also the image size `create()` is called with |
| `nvram-bank-count` | OSData(u32) | number of banks |
| `nvram-current-bank` | OSData(u32) | active bank |
| `nvram-raw` | OSData(u32) | non-zero selects raw interpretation of the store |
| `nvram-proxy-data` | OSData | the V3 image |

`init()` fails silently (returns false) if any of these is missing, and the
factory reports `IONVRAMV3Handler creation failed @IONVRAM.cpp:1688`. The
`nvram-raw` property is the easy one to miss: it is a plain flag but `init()`
still requires it to be present.

### The image format

`IONVRAMV3Handler` parses the store through a 0x18-byte header and requires
`size >= 0x18` and `header.size == size`:

```
struct nvram_v3_header {            // 0x18 bytes
    u32 magic;                      // 0x4e565633
    u32 size;                       // total image size
    u32 region_offset;              // -> handler field 0x30
    u8  reserved[2];                // 0x0c, 0x0d
    u8  version;                    // 0x0e == 1
    u8  reserved2;
    u32 field_10;                   // -> handler field 0x4c
    u32 data_end;                   // -> handler field 0x48 (minus 0x18)
};
```

An empty (factory) image is a zeroed buffer with just this header. `src/nvram.c`
builds it; the older CHRP-partition image the code used to build is what a raw
store looks like and is selected by `nvram-raw`, but the bring-up needs the
structured image.

### Who writes it

On a real machine, iBoot writes the live image and the geometry into `/chosen`
before starting the kernel. That is exactly Trestle's job here. The model owns
the image; the device tree builder publishes it as `/chosen`'s
`nvram-proxy-data` and `nvram-total-size`/`nvram-bank-*`/`nvram-raw`.
`tests/nvram_test.c` asserts the produced image has the shape above.

## 5. Device tree ownership

Trestle owns the builder (`src/adt.c`): it produces the pexpert encoding --
`DeviceTreeNode { nProperties, nChildren }` followed by the properties and then
the children, values padded to four bytes, integers little-endian, strings
carrying their NUL -- and every device contributes into it through
`adt_contribute`. The platform's own nodes, and the phandle numbering, are in
`src/platform_nodes.c`; `src/boot.c` lists the devices and assembles them.

`gatehouse/dt/build_adt.py` still produces the tree Gatehouse hands XNU on the
bring-up, because Trestle is not on the boot path yet. It is now the *stand-in*
for the Trestle builder, and the two are held in step by

    tools/adt_diff.py build/gatehouse.adt <Trestle's tree>

which compares them node by node and property by property, ignoring order.
`tests/adt_test.c` writes Trestle's tree out, so the check is mechanical: for
the bring-up machine the two are currently identical, byte for byte.

## 6. Machine portability

| Concern | Portable part | Machine-specific part |
|---------|---------------|-----------------------|
| Device behaviour | the model (`src/rtc.c`, `src/panic.c`, ...) | none |
| Where devices live | building the tree (`src/adt.c`, `src/platform_nodes.c`) | the windows in `src/machines.c` |
| How accesses arrive | the model's `mmio_*` | the trap/route layer |
| RAM, SoC base, GIC regions | `trestle_machine` | `src/machines.c` (boot facts filled in by Gatehouse) |
| Who the machine is | the tree's identity nodes | `src/machines.c` |

Two descriptions exist: `trestle_machine_qemu_virt()` (the bring-up target) and
`trestle_machine_avp()` (the Apple virtual platform, whose windows come from the
reference device tree). No file under `src/` other than `machines.c` mentions a
board, and `tests/adt_test.c` builds both trees from the same models to keep it
that way.

The devices Trestle currently models, and what each one is for:

| Device | `src/` | Why it is on the boot path |
|--------|--------|----------------------------|
| NVRAM store | `nvram.c` | `IONVRAMV3Handler` (see §4) |
| PL031 RTC | `rtc.c` | the kernel's time base; the AVP also has `avp-rtc` |
| Power manager | `pmgr.c` | the root power domain Image4 waits for; the PSCI conduit |
| Panic log | `panic.c` | `/pram` + `embedded-panic-log-size`, and `qemu,pvpanic-mmio` |
| CTRR / sealed registers | `aprr.c` | `/chosen` `kernel-ctrr-to-be-enabled`, `/chosen/lock-regs` |

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

1. ~~**NVRAM** — model + V3 image + the full `/chosen` contract~~ done.
2. ~~**Device tree builder** — ADT construction inside Trestle, devices
   contributing their own nodes~~ done (`src/adt.c`); kept in step with
   `build_adt.py` by `tools/adt_diff.py`.
3. **The early platform** — the RTC, the power manager, the panic log and the
   configuration registers are modelled (`src/rtc.c`, `src/pmgr.c`,
   `src/panic.c`, `src/aprr.c`). Still to do: the AVP's graphics and
   `iosurface-mapper` roles, the AES window, and `pcie` — the last of which is
   wanted for attaching a root volume.
4. **Trap/route layer** — only once a device must be emulated rather than
   described. The `mmio_*` contract is already the shape it feeds.
5. **Put Trestle on the boot path** — Gatehouse calls `trestle_main()` and
   plants the returned tree at `boot_args->deviceTreeP`, at which point
   `build_adt.py` retires to being a reference.

## 9. Non-goals

* Being a general-purpose hypervisor. Trestle serves one guest and one
  contract.
* Reimplementing Apple firmware. It builds the *minimum* platform macOS
  accepts, and grows only when a failure demands it.
