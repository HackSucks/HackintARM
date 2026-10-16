# Licensing

HackintARM is a mixed-licence tree. This file is the authoritative statement of
which licence applies to which part, and why the combination is lawful. It is
written to be read alongside [`LICENSE`](LICENSE) (the GNU GPL version 2 text).

## The rule

**Everything HackintARM authors is `GPL-2.0-or-later`** — the GNU General Public
License, version 2, *or any later version*. This is expressed per file with an
SPDX header:

```
SPDX-License-Identifier: GPL-2.0-or-later
```

The "or later" is deliberate and load-bearing; see *Why "or later"* below.

## Per-component breakdown

| Component | Path | Licence | Notes |
|-----------|------|---------|-------|
| Gatehouse (UEFI bootloader) | `gatehouse/` | `GPL-2.0-or-later` | our code |
| Trestle (hypervisor) | `trestle/` | `GPL-2.0-or-later` | our code |
| Host tooling | `tools/`, `qemu/` | `GPL-2.0-or-later` | our code |
| Acidanthera kexts (Lilu, WhateverGreen, AppleALC, VirtualSMC, …) built for ARM64 | `plugins/`, `kexts/` (when present) | `GPL-3.0-or-later` | third-party, verbatim upstream |
| Linux driver glue (`GPL-2.0-only`) | `drivers/linux/` (when present) | `GPL-2.0-only` | isolated; see below |

## Why "or later"

Acidanthera's kexts are licensed `GPL-3.0-or-later`. The GPL is a *copyleft*
licence, and copyleft licences only combine when their terms are compatible:

* `GPL-2.0-or-later` **+** `GPL-3.0-or-later` → **compatible.** The "or later"
  on both sides lets every party select GPLv3, so the combined work ships under
  **GPL-3.0-or-later**.
* `GPL-2.0-only` **+** `GPL-3.0-or-later` → **incompatible.** There is no version
  both sides can agree on. This combination is forbidden.

So the base licence for our own code is chosen as `GPL-2.0-or-later`, never
`GPL-2.0-only`. A build that links a GPLv3 plugin against the core is, as a
whole, distributed under **GPL-3.0-or-later** (the "or later" in the core's
licence is *exercised* by that build, it does not change the core's own terms).

## Linux `GPL-2.0-only` code stays isolated

Parts of the Linux kernel (and many in-tree drivers) are `GPL-2.0-only`. Code
that imports them therefore cannot be pulled into the GPLv3 combined work.

Rule: **any module that links `GPL-2.0-only` code lives in its own directory,
is its own independently-distributed binary (a loadable kernel module or a
separate process), and communicates with the rest of HackintARM only across a
stable, non-derived interface** (ioctl/uAPI, sysfs, a wire protocol, shared
memory with a documented ABI). It is never statically linked into the
GPLv3 core, and it is not a "work based on" the GPLv3 core.

## Third-party files

Files copied from another project keep that project's licence and its copyright
notice; do not rewrite them with the `GPL-2.0-or-later` header. When a file is
adapted (not copied verbatim), state the origin and the licence that applies to
the adaptation.

## The Apple binaries are not distributed

`kernel/` holds Apple firmware and kernel images extracted from an Apple IPSW
(`kernelcache.*`, `DeviceTree.*`, `*.im4p`). They are Apple's copyrighted
material and are **excluded** from version control (see `.gitignore`). Nothing
under `kernel/` is licensed to you by this project; obtain them yourself from a
legitimate IPSW.
