# HackintARM
an attempt at reviving Hackintosh in the form of ARM64 laptops, given Apple's switch to purely Apple Sillicon for macOS 27

# Currently working:
Patched XNU Kernel execution under QEMU virt machine with compiled ADT

Till now what is working: 

using bootloader to make 16KB page tables and pivot into XNU kernel code

XNU setting up its own MMU and proceeding execution in it's own Virtual Memory

# Bug Right Now:
XNU failing to parse boot-args from unmapped 0xfffffbffcaf86090

# NOT Working/Roadmap
~~Kernel mapping to MMU~~

~~other kernel patches...~~

Hypervisor for 16K memory map --> 4K map most commonly seen on ARM SoC

Same Hypervisor for AGX GPU --> Actual GPU to see display

Currently support is only for QEMU virt machine, despite All ARM SoC having similarities there will be efforts to make the project work on various other ARM laptops and devices once macOS can boot under QEMU more or less functional.

# How does it work?
Soon.

# ETA?
Also, Soon.

# Source Code?

When the project more or less is functional.
