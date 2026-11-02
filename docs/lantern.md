# Lantern

**VMApple's paravirtual GPU, translated to real hardware.**

Lantern is the HackintARM sub-project that gives the booted guest a working
display and GPU. It presents the two devices macOS 27's graphics stack expects
(`paravirtualizedgraphics,gpu` and `paravirtualizedgraphics,iosurface`), speaks
the paravirtual graphics (PVG) protocol to the guest, and renders with a real
GPU on the host.

This document records the architecture decision, the guest contract as far as
it is known, how Lantern fits QEMU `virt` and Trestle, and the bring-up phases.

---

## 1. The problem

On Apple Silicon, Virtualization.framework puts two paravirtual devices in front
of the guest:

| Device | Driver | Match |
|---|---|---|
| GPU | `AppleParavirtGPU` (`AppleParavirtGPUIOGPUFamily.kext`) | `paravirtualizedgraphics,gpu` on `AppleARMIODevice`, category `IOAccelerator` |
| IOSurface | `AppleParavirtIOSurface` (`AppleParavirtIOSurface.kext`) | `paravirtualizedgraphics,iosurface` |

The guest side is Apple's own driver and is already in the kernel collection.
The host side is normally `ParavirtualizedGraphics.framework`: it owns the
device register file, the FIFOs, task address spaces, resources and textures,
and it forwards Metal work to the real GPU.

HackintARM cannot link that framework: it is Apple-only, closed, and unavailable
on the hardware we target. We have to provide the host side ourselves.

The guest is not optional about it. `WindowServer`, `loginwindow` and the
services that connect to the window server bind through `IOAccelerator`; with
no GPU device they crash-loop, which is exactly what the current boot shows.

---

## 2. Decision: reuse reims-vgpu

**Lantern will use [`steelbrain/reims-vgpu`](https://github.com/steelbrain/reims-vgpu)
as the PVG protocol core rather than reimplementing the protocol.**

reims-vgpu is a clean-room, framework-free host implementation of
`ParavirtualizedGraphics.framework`. It already contains the hard, undocumented
parts:

- the device register file and MMIO semantics;
- the root and child FIFOs, doorbells, stamps, faults and interrupts;
- task address spaces and page tables;
- resources, textures, IOSurfaces, samplers, pipelines and command streams;
- the IOSurface device, video and scaler devices;
- a `Platform` seam with a Metal backend and a Vulkan backend
  (`metal2vulkan`) for Linux;
- a stable C API (`rvg_*`, `struct_size`-versioned) and a static library.

Pinned revision: **`1fe0acb68b287db36f1e6c7b9f45383940b8a76f`** (2026-10-29).
Licence: `GPL-2.0-or-later OR LGPL-3.0-or-later`; we take the GPL option, which
is compatible with this tree's `GPL-2.0-or-later` (see `LICENSING.md`).

### What Lantern adds

Lantern owns only what is specific to *this* machine:

1. **Device front-end** — publishes the ADT nodes, decodes the MMIO windows,
   forwards register accesses to `rvg_device_*`/`rvg_iosurface_device_*`, and
   injects interrupts into the guest.
2. **Guest-memory provider** — describes guest RAM to reims-vgpu as a
   `RvgMemoryMap` with file-backed ranges so the Vulkan backend can build views
   of guest pages.
3. **Display sink** — decides where a presented frame goes: a library window, a
   QEMU `DisplaySurface`, a QMP screendump, or (bare metal) a scanout buffer.
4. **Platform backend selection** — Vulkan now; a native GPU backend later.
5. **Build/packaging** — vendored reims-vgpu, a QEMU device, and a Trestle
   device model.

### What Lantern deliberately does not do

- Reimplement any PVG wire structure, FIFO or command decoding.
- Link `ParavirtualizedGraphics.framework` or require Apple hardware.
- Patch signed Apple binaries. The guest's GPU kexts are used as shipped.
- Depend on QEMU or Linux in the core. The front-end is the only machine-aware
  part.

---

## 3. Architecture

```
+--------------------------------------------------------------+
| Guest (XNU, EL1)                                             |
|   AppleParavirtGPU  ── MMIO + IRQ ──  AppleParavirtIOSurface  |
+---------------------------┬----------------------------------+
                            |  two MMIO windows, two IRQs
+---------------------------▼----------------------------------+
| Lantern device front-end (machine-specific)                  |
|   · ADT nodes            · MMIO decode / dispatch            |
|   · guest memory map     · interrupt injection               |
|   · display placement                                        |
+---------------------------┬----------------------------------+
                            |  rvg_* C API
+---------------------------▼----------------------------------+
| reims-vgpu core (vendored, unmodified)                       |
|   PVG registers, FIFOs, tasks, resources, IOSurface, ...     |
+---------------------------┬----------------------------------+
                            |  Platform trait
+---------------------------▼----------------------------------+
| Platform backend                                             |
|   VulkanPlatform (Linux/now)  →  native GPU backend (later)  |
+--------------------------------------------------------------+
```

The front-end is deliberately thin. A register write is forwarded, not
interpreted; a frame is encoded through the display API, not decoded. That is
what keeps the bare-metal port bounded.

### Where the code lives

| Piece | Path (planned) | Notes |
|---|---|---|
| Vendored reims-vgpu | `third_party/reims-vgpu/` | git submodule, pinned |
| Front-end core | `lantern/src/` | machine-independent device logic, C/Rust |
| QEMU device | `lantern/qemu/` | based on reims-vgpu's `apple-gfx-mmio` |
| Trestle device model | `trestle/src/lantern.c` | implements `trestle_device` |
| Machine descriptions | `gatehouse/dt/build_adt.py`, `trestle/src/machines.c` | addresses and IRQs |
| Build glue | `lantern/Makefile`, top-level docs | static library + pkg-config |

Lantern runs **in-process** with its host: a static library linked into QEMU's
device, and later into the Trestle bare-metal image. There is no daemon and no
IPC on the boot path. Process isolation can be added on hosted systems later; it
is not part of the design.

---

## 4. The guest contract

The authoritative reference for the wire format is reims-vgpu's
`docs/testing.md` §6 ("Guest ABI reference"). Only the parts the front-end must
handle are repeated here.

### 4.1 Devices and ADT

Two nodes, two MMIO windows, two interrupts. VMApple's own machine places them
at:

| Device | AVP physical | Size | AVP GIC id |
|---|---|---|---|
| `APV_GFX` (GPU) | `0x30200000` | 64 KiB | `0x11` |
| `APV_IOSFC` (IOSurface) | `0x30210000` | 64 KiB | `0x10` |

The exact node names and properties still have to be copied from a real VMApple
device tree (or derived from what the drivers read). The match strings and the
provider class are known from the kexts:

```
compatible        = "paravirtualizedgraphics,gpu"
IOProviderClass   = AppleARMIODevice
IOMatchCategory   = IOAccelerator

compatible        = "paravirtualizedgraphics,iosurface"
```

A GPU node also needs its `reg`, `interrupts`, and whatever phandle wiring the
IOSurface mapper uses. Trestle already reserves
`TRESTLE_PHANDLE_IOSURFACE_MAPPER` (`0x41`); the node it points at, and the
properties the guest reads from it, must be confirmed against a real tree before
the first descriptor table is expected to work.

**Do not invent properties.** A node that advertises something the device model
does not back is worse than no node: the driver maps it and faults on first
access, which is how the missing PL061 controller produced a synchronous
external abort earlier in the project.

### 4.2 MMIO

The GPU register file is 64 KiB. The core's index rule is:

```
index = (uint16_t)((offset - 0x1000) / 4)
```

so offsets below `0x1000` wrap, and `0x41000` aliases `0x1000`. The front-end
forwards the raw BAR offset (0 to `0x3fff`) unchanged:

```c
uint32_t lantern_gfx_read(void *opaque, uint64_t offset)
{
    return rvg_device_mmio_read(((lantern_gfx *)opaque)->device, offset);
}

void lantern_gfx_write(void *opaque, uint64_t offset, uint32_t value)
{
    rvg_device_mmio_write(((lantern_gfx *)opaque)->device, offset, value);
}
```

The IOSurface device has its own register window and its own API. Its registers
live at `0x1000`–`0x1030` in its 64 KiB region; its accesses are 64-bit:

```c
uint64_t rvg_iosurface_device_mmio_read(RvgIOSurfaceDevice *, uint64_t offset);
void     rvg_iosurface_device_mmio_write(RvgIOSurfaceDevice *, uint64_t offset,
                                         uint64_t value);
```

Unhandled reads return 0 and unhandled writes are ignored by the core; the
front-end does not need a register table of its own.

Key GPU registers the bring-up will watch (offsets in the GPU BAR):

| Offset | Meaning |
|---|---|
| `0x1000` | root FIFO enable |
| `0x1004` | root FIFO length |
| `0x1008` | root FIFO written |
| `0x100c` | root FIFO read |
| `0x1010` | root FIFO start (GPA page) |
| `0x1014` | display interrupt mask |
| `0x1018` | stamp interrupt mask (read-to-clear) |
| `0x101c` | root page |
| `0x1020` | doorbell / wake |
| `0x1024`, `0x1028` | resume |
| `0x102c` | fault flag |
| `0x1030` | base |
| `0x1034` | binary version |
| `0x1200+` | EFI display registers |

### 4.3 Guest memory

reims-vgpu needs to reach guest RAM. Two options exist:

- **Memory callbacks** (`create_task`, `map_memory`, `read_memory`, ...).
- **A memory map** (`RvgMemoryMap` plus `RvgMemoryRangeFile`), which is what the
  Vulkan backend needs so it can build host views of guest pages.

Lantern uses the memory map. The host supplies one range per guest RAM region,
and, on Linux, the file descriptor behind each range (QEMU:
`memory-backend-file,share=on`; Trestle: the backing file or its own mapping).
Ranges without a file still work, but every guest use that needs a host view
fails the way a failed remap does, so file-backed RAM is the supported setup.

Passthrough of guest page tables and task address spaces is the core's job; the
front-end only says where RAM is.

### 4.4 Interrupts

The host gives reims-vgpu an `raise_interrupt(ctx, vector)` callback. The
front-end maps `vector` to the machine's interrupt controller:

- QEMU: `qemu_set_irq` on the device's IRQ line.
- Trestle: inject the corresponding GIC interrupt into the guest.

The callback runs on a library thread, or on the host's thread inside a call
marked "may call back". It must not wait for a host thread that is itself in a
call on the device, and the device's signal lock is held, so one device's
raises never run concurrently.

### 4.5 Display and frames

A display is created with `rvg_display_create`:

- one port per display (`RvgDeviceConfig.display_port_count`);
- a serial number, name and physical size;
- `mode_change` and `new_frame` callbacks;
- optionally a library-owned window (`RvgWindowConfig`), which also provides
  pointer, wheel, key and scroll input.

For a scanout sink that is not the library's window:

1. `rvg_frame_target_create` makes a readable GPU texture of the mode's size.
2. `rvg_display_encode_frame` encodes the current guest frame into it.
3. `rvg_frame_commit` submits it; `rvg_frame_wait` waits.
4. `rvg_frame_target_read_pixels` copies it into the sink (a
   `DisplaySurface`, a scanout buffer, or a file).

The first encode after each guest present counts one host present. A display
keeps its device alive; a frame keeps its display and target alive until it
completes.

Modes are offered with `rvg_display_set_modes`; the guest's display page takes
the first 128. The EFI display registers read port 0's list.

### 4.6 Lifetime

- The device is created at machine realize and released at machine teardown.
- A reset (`rvg_device_reset`) must be wired to the guest's reset path if the
  machine supports one.
- Suspend/resume (`will_suspend`, `finish_suspend`, `will_resume`,
  `did_resume`) is optional for bring-up. QEMU migration is explicitly out of
  scope: the device is unmigratable, and a migrated guest must rebuild its GPU
  state from scratch, as it does after a cold boot.
- Teardown may block; the front-end must not hold a host lock the library might
  need while calling it.

---

## 5. Host API mapping

| Guest-visible thing | reims-vgpu API |
|---|---|
| GPU register window | `rvg_device_mmio_read` / `rvg_device_mmio_write` |
| IOSurface register window | `rvg_iosurface_device_mmio_read` / `_write` |
| GPU interrupt | `RvgHostCallbacks.raise_interrupt` |
| IOSurface interrupt | `RvgIOSurfaceCallbacks.raise_interrupt` |
| Guest RAM | `RvgDeviceConfig.memory_map` + `memory_files` |
| Display port | `rvg_display_create`, `rvg_display_set_modes` |
| Frame present | `rvg_display_encode_frame`, `rvg_frame_commit/wait` |
| Frame readback | `rvg_frame_target_read_pixels` |
| IOSurface mapping | `rvg_iosurface_device_create`, `use_iosurface_mapper` |
| Reset | `rvg_device_reset` |

Sketch of device creation (error handling and cleanup omitted):

```c
RvgHostCallbacks callbacks = {
    .struct_size      = sizeof callbacks,
    .ctx              = gfx,
    .raise_interrupt  = lantern_raise_irq,
};

RvgDeviceConfig config = {
    .struct_size          = sizeof config,
    .display_port_count   = 1,
    .feature_level        = 4,
    .use_iosurface_mapper = true,
    .memory_map           = &gfx->memory_map,
    .memory_files         = gfx->memory_files,
    .callbacks            = &callbacks,
};

rvg_device_create(&config, &gfx->device);
```

Then the IOSurface device (it requires the same memory map):

```c
RvgIOSurfaceCallbacks iosfc_callbacks = {
    .struct_size     = sizeof iosfc_callbacks,
    .ctx             = gfx,
    .raise_interrupt = lantern_raise_iosfc_irq,
};

RvgIOSurfaceDeviceConfig iosfc_config = {
    .struct_size  = sizeof iosfc_config,
    .memory_map   = &gfx->memory_map,
    .callbacks    = &iosfc_callbacks,
};

rvg_iosurface_device_create(&iosfc_config, &gfx->iosfc);
```

`feature_level = 4` offers every feature; lower values cap the binary version
the guest may choose. Whether macOS 27's driver expects the full version is an
open question (see §10).

---

## 6. Integration A: QEMU `virt`

The first target is the existing QEMU `virt` bring-up, because that is where the
guest already reaches userland.

### Device and addresses

A `SysBusDevice` modelled on reims-vgpu's `apple-gfx-mmio`:

- two MMIO regions (GPU and IOSurface, 64 KiB each);
- two IRQ outputs;
- properties for the RAM memory region and the display geometry;
- `rvg_device_create` at realize, release at unrealize.

Proposed machine description for QEMU `virt` (offsets are from the machine's
`soc_base`, `0x08000000`):

| Device | Offset | Physical | Size | GIC id |
|---|---|---|---|---|
| `lantern-gfx` | `0x03000000` | `0x0b000000` | 64 KiB | SPI 0x30 (48) |
| `lantern-iosfc` | `0x03010000` | `0x0b010000` | 64 KiB | SPI 0x31 (49) |

These addresses are inside `virt`'s `VIRT_MMIO` window and clear of the
virtio-mmio slots, the PL011, RTC, GPIO and ACPI regions. They must be identical
in:

- `gatehouse/dt/build_adt.py` (the ADT nodes), and
- `trestle/src/machines.c` (`g_qemu_windows`), and
- the QEMU device's placement.

If the AVP's real offsets are used instead, the same rule applies: one machine
description, three consumers.

### Guest RAM

QEMU must give the device file-backed RAM. The launcher will switch to
`memory-backend-file,share=on` (one backend for the low RAM region) and pass the
backend's file descriptor to the device. Without that, Vulkan cannot create host
views, and the first texture upload fails.

### Display

Two modes, in order of usefulness:

1. **Library window** — `RvgWindowConfig` with `RVG_WINDOW_MATCH_HOST_SCREEN`.
   Fastest route to a visible desktop; also gives input for free. On a headless
   host, use SDL's offscreen driver or leave it off.
2. **QEMU display sink** — encode into a frame target and copy into QEMU's
   `DisplaySurface`, so `-display gtk` and QMP `screendump` work without the
   library's window. This is the mode that matches the eventual scanout path.

QMP `screendump` is the acceptance check: a frame with the Dock and menu bar is
a real desktop, not merely a process that has not crashed yet.

### Build

QEMU's device needs to be compiled into the emulator. Lantern will carry a
small patch series against a pinned QEMU, applied by `lantern/qemu/build.sh`;
the device code itself lives in `lantern/qemu/hw/display/` and links
`libreims_vgpu.a`. The alternative — an out-of-tree module — still needs QEMU's
headers and a matching build, so a pinned patch series is simpler and
reproducible.

### What stays QEMU-specific

Only this directory: the SysBus wrapper, the IRQ wiring, the RAM backend, the
display sink and `run.sh` arguments. The front-end core and the ADT contract are
shared with Trestle.

---

## 7. Integration B: Trestle and bare metal

Trestle already has the right shape: a `trestle_device` with `init`,
`adt_contribute`, `mmio_read`, `mmio_write` and `deinit`, plus a machine
description that supplies windows and interrupt ids.

The Lantern Trestle model:

- `init` finds the `lantern-gfx` and `lantern-iosfc` windows in the machine
  description, creates the reims-vgpu devices, and records the guest RAM map.
- `adt_contribute` publishes the GPU and IOSurface nodes (the same contract as
  the QEMU path).
- `mmio_read` / `mmio_write` forward to the core.
- `deinit` releases the devices.
- The trap layer routes stage-2 faults for the two windows to the model, and
  interrupt injection uses the machine's GIC.

The display sink on bare metal is a framebuffer or scanout buffer owned by the
native GPU backend, not a window.

### The freestanding problem

reims-vgpu is a Rust `std` library with threads and a Vulkan runtime. That is
fine for QEMU and for a hosted Trestle prototype, but a bare-metal EFI image has
no `std`, no OS threads and no Vulkan loader.

The design keeps this contained:

- The **front-end** talks only to the C API. It does not care how the core is
  built.
- The **core** is isolated behind that API and can be built two ways:
  1. hosted: current reims-vgpu with `VulkanPlatform`;
  2. freestanding: a `no_std` build with an allocator, a cooperative thread
     runtime, and a native `Platform` backend.
- The **Platform backend** is where a bare-metal GPU driver lives. It implements
  the same object model the Metal/Vulkan backends do (devices, queues, buffers,
  textures, pipelines, encoders), but over the target GPU's command stream.

This is a real project, not a configuration switch. It is deliberately deferred
until the protocol works on QEMU: by then the front-end and ADT contract are
fixed, and the remaining work is the runtime shim and the GPU backend.

If a `no_std` build proves impractical, the fallback is a small privileged
service (a second domain or a host partition) that owns the GPU and exposes the
same C API over shared memory. That keeps the guest contract identical; only the
transport changes. Lantern does not commit to either option yet.

---

## 8. Bring-up phases

Each phase has an observable result; a phase is not done until that result is
seen in a boot log or a screenshot.

### Phase 0 — Probe

- Add the ADT nodes and the QEMU/Trestle device windows.
- Create the reims-vgpu device and IOSurface device with a memory map.
- Boot the existing image.

**Done when:** the guest logs `AppleParavirtGPU` and `AppleParavirtIOSurface`
matching and starting, and the first MMIO reads (binary version, base) appear in
the device trace. No fault, no panic.

### Phase 1 — Register file and interrupts

- Forward MMIO both ways.
- Raise the display and stamp interrupts.
- Confirm the guest enables the root FIFO and writes its start/length.

**Done when:** the guest's interrupt handler reads `0x1018`, `0x1014` and
`0x102c`, and the host sees FIFO doorbells.

### Phase 2 — FIFOs and memory

- The root FIFO accepts commands; child FIFOs run.
- Task creation and page-table walks work against the guest RAM map.
- Stamps are published and consumed.

**Done when:** the guest creates its first task and the host completes a command
without a fault; `WindowServer` stops crash-looping.

### Phase 3 — Resources and textures

- Resources, textures, samplers and pipelines are created through the Platform
  backend.
- IOSurface mappings work (descriptor table, `use_iosurface_mapper`).

**Done when:** the guest draws its first non-trivial frame and readback matches
a known pattern.

### Phase 4 — Scanout

- Offer modes, handle `mode_change`.
- Encode and present frames to the sink.
- Input (if the window path is used).

**Done when:** QMP `screendump` shows the login window or desktop with the Dock
and menu bar, and `WindowServer` survives for minutes.

### Phase 5 — Breadth

- Multiple FIFOs, fences, events, shared textures, video/scaler devices as
  needed.
- Test with real applications, not just the login screen.

**Done when:** a normal desktop session is usable under TCG without GPU faults.

### Phase 6 — Bare metal

- Port the front-end to Trestle's trap layer.
- Replace the machine description and the Platform backend.
- Keep the ADT contract and guest driver untouched.

**Done when:** the same kernel collection reaches the same desktop on a physical
AArch64 machine.

---

## 9. Engineering rules

- **Never patch signed Apple binaries.** The GPU kexts are used as shipped.
- **The kernel collection in `kernel/` is pristine.** Any workaround is applied
  to the staged copy only, documented, and byte-verified.
- **Diagnostics are reversible.** Extra boot arguments are opt-in and never
  committed as defaults.
- **Pin third-party code.** reims-vgpu is a submodule at the commit above; an
  update is a deliberate change with a boot test.
- **Keep machine specifics in the machine description.** Addresses, IRQs, RAM
  and the display sink do not belong in the core.
- **One source of truth per address.** The ADT builder, the QEMU device and the
  Trestle machine description must agree; a test should compare them.
- **Licence hygiene.** New code is `GPL-2.0-or-later`; reims-vgpu is used under
  its GPL option. Do not copy `GPL-2.0-only` Linux code into the front-end.

---

## 10. Open questions

1. **Exact ADT properties.** The node names, `reg` encoding, `interrupts`
   cells, IOSurface mapper phandle and any Apple-specific properties must be
   copied from a real VMApple tree or derived from the drivers. Until then,
   Phase 0 is a hypothesis, not a contract.
2. **Feature level / binary version.** Which `feature_level` macOS 27's driver
   needs (62, 113, 209 or 245+) is not established. Start at 4 and lower it only
   if the guest misbehaves.
3. **`use_iosurface_mapper`.** The guest's mapper driver writes a descriptor
   table base into the IOSurface device; whether macOS 27's arm64 driver needs
   it for non-isolated tasks is unconfirmed.
4. **ARM64 guest on Linux.** reims-vgpu's Linux path is documented for x86-64
   guests under KVM and arm64 guests under HVF. An aarch64 guest under TCG (our
   bring-up) is new ground: memory views, dirty tracking and thread behaviour
   may differ.
5. **Display timing under TCG.** Software CPU emulation may make the guest's
   frame pacing and timeouts behave differently from hardware. A phase that
   passes under TCG should be rechecked under KVM/HVF where available.
6. **Bare-metal runtime.** `no_std` + allocator + cooperative threads + native
   GPU backend is the largest unknown. It does not block Phases 0–5.
7. **GPU choice for bare metal.** The backend needs a GPU with usable
   documentation and command-stream knowledge. That is a separate hardware
   decision, deliberately not made here.

---

## 11. References

- reims-vgpu: <https://github.com/steelbrain/reims-vgpu>
  - `docs/architecture.md` — the `Platform` boundary
  - `docs/api.md` — the C API, object lifetimes, threading
  - `docs/testing.md` §6 — the guest ABI reference
  - `docs/qemu.md` — the `apple-gfx-mmio` device and QEMU integration
- `trestle/docs/design.md` — the device-model contract
- `docs/bringup.md` — how the guest got to `launchd`
- `docs/ipsw.md` — the kernel collection and root image
