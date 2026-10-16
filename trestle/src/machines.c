// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/machines.c - the machine descriptions (see include/machines.h).
#include "machines.h"

// ---------------------------------------------------------------------------
// Identity.
//
// These are Gatehouse's own strings: this is not an Apple-serialised machine,
// so the serial and model numbers are ours (iBoot fills the reference
// platform's in from the syscfg region on a real one).  Everything else --
// target types, model, manufacturer, the device-tree tag -- is the reference
// platform's, because the platform expert and the AVP kexts compare against
// them.
// ---------------------------------------------------------------------------
static const trestle_machine_identity g_identity = {
    .model = "VirtualMac2,1",
    .target_type = "VMA2MACOS",
    .target_sub_type = "VMA2MACOSAP",
    .manufacturer = "Apple Inc.",
    .device_tree_tag = "EmbeddedDeviceTrees-12661.1.5",
    .serial_number = "HACKINTARM0001",
    .mlb_serial_number = "HACKINTARMMLB0001",
    .region_info = "LL/A",
    .model_number = "HACKINTARM1",
    .config_number = "HACKINTARM0001",
    .regulatory_model_number = "HACKINTARM1",
    .country_of_origin = "US",
    .model_config = "HackintARM",
    .secure_root_prefix = "md",
    .time_stamp = "Thu Jan 1 00:00:00 UTC 2026",
    .boot_args =
        "debug=0x14e -v -noprogress serial=1 cpus=1 kextlog=0xfff keepsyms=1 "
        "exe_boothash_salt=0",
    .product_name = "Apple Virtual Machine 1",
    .unique_model = "VMA2MACOSAP",
    .fdr_product_type = "VirtualMac2,1",
};

// ---------------------------------------------------------------------------
// Boot entropy.
//
// PE_get_random_seed() (pexpert/gen/pe_gen.c) panics when /chosen
// "random-seed" is absent, empty or all zero, and its consumer
// (prng_random.c) needs the full 256 bytes.  This is the same deterministic
// generator gatehouse/dt/build_adt.py uses, so that the bring-up tree and
// Trestle's carry the same seed and two runs are comparable.  A machine port
// with real entropy -- on Apple Silicon iBoot takes it from the SEP -- supplies
// its own; this one exists so that a bring-up run is reproducible.
// ---------------------------------------------------------------------------
static u8  g_seed[256];
static int g_seed_ready;

static void machine_seed(u8 *out, usize size)
{
    u64 state = 0x5EED123456789ABCull;

    for (usize i = 0; i < size; i++) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (u8)(state >> 33);
    }
}

static void machine_seed_once(void)
{
    if (!g_seed_ready) {
        machine_seed(g_seed, sizeof(g_seed));
        g_seed_ready = 1;
    }
}

// ---------------------------------------------------------------------------
// QEMU virt: the bring-up target.
//
// The addresses are QEMU's own (hw/arm/virt.c); the offsets are relative to
// the SoC base, which is the form /arm-io "ranges" and every device "reg"
// publish.
// ---------------------------------------------------------------------------
static const trestle_machine_window g_qemu_windows[] = {
    // name             offset from soc_base   size     GIC interrupt id
    { "uart0",          0x01000000ull,         0x1000,  0 },
    { "pl031-rtc",      0x01010000ull,         0x1000,  0 },
    // QEMU wires the PL061 to SPI 7, and XNU's "interrupts" cells are raw GIC
    // ids, not SPI numbers: the architected PPI 7 that the cpu node publishes
    // is 0x17 = 23, and the reference tree's 0x25 for this same controller is
    // SPI 5.  So the id is 32 + 7.
    { "pl061-buttons",  0x01030000ull,         0x1000,  39 },
};

trestle_machine *trestle_machine_qemu_virt(void)
{
    static trestle_machine m;

    machine_seed_once();

    m.ram_base = 0x40000000ull;
    m.ram_size = 0x100000000ull;        // MEM=4G in qemu/run.sh

    m.soc_base = 0x08000000ull;         // QEMU virt's GIC base
    m.soc_size = 0x38000000ull;         // up to the RAM base: the /arm-io window

    m.gic_dist_offset = 0x00000000ull;
    m.gic_dist_size = 0x00010000ull;
    m.gic_redist_offset = 0x000a0000ull;
    m.gic_redist_size = 0x000f6000ull;

    m.windows = g_qemu_windows;
    m.window_count = TRESTLE_ARRAY_SIZE(g_qemu_windows);

    m.timebase_hz = 24000000;           // QEMU virt's architected timer

    // Gatehouse reserves this inside the boot-data window below
    // topOfKernelData (gh_panic_phys in gatehouse/main.c is the same value).
    m.panic_phys = 0x86804000ull;
    m.panic_size = 0x00080000ull;       // 512 KiB

    m.random_seed = g_seed;
    m.random_seed_size = sizeof(g_seed);
    m.identity = &g_identity;
    m.log_write = 0;
    return &m;
}

// ---------------------------------------------------------------------------
// The Apple virtual platform (VMA2MACOSAP).
//
// The windows are the offsets the reference device tree publishes -- they are
// relative to the SoC base, which is 0x10000000 on that platform -- and the
// devices behind them are the ones the AVP kexts bind to and Trestle has to
// emulate on real hardware.  The AVP's own panic port is the pvpanic-compatible
// device at 0x10070000.
// ---------------------------------------------------------------------------
static const trestle_machine_window g_avp_windows[] = {
    { "uart0",                0x10010000ull, 0x10000, 0 },
    { "pl031-rtc",            0x10050000ull, 0x1000,  0 },
    { "pl061-buttons",        0x10060000ull, 0x1000,  0x25 },
    { "pvpanic",              0x10070000ull, 0x1000,  0 },
    { "avp-rtc",              0x20240000ull, 0x1000,  0x33 },
    { "avp-ctrr",             0x20260000ull, 0x100,   0 },
    { "avp-sealed-registers", 0x20270000ull, 0x100,   0 },
};

trestle_machine *trestle_machine_avp(void)
{
    static trestle_machine m;

    machine_seed_once();

    // RAM, the device tree's placement and the panic reservation are boot
    // facts: on this platform they come out of boot_args and Gatehouse fills
    // them in.  The defaults below match the reference platform's own
    // declarations so that a tree built without that context is still
    // well-formed.
    m.ram_base = 0x40000000ull;
    m.ram_size = 0x100000000ull;

    m.soc_base = 0x10000000ull;
    m.soc_size = 0x70000000ull;

    m.gic_dist_offset = 0x00000000ull;
    m.gic_dist_size = 0x01000000ull;
    m.gic_redist_offset = 0x00010000ull;
    m.gic_redist_size = 0x00400000ull;

    m.windows = g_avp_windows;
    m.window_count = TRESTLE_ARRAY_SIZE(g_avp_windows);

    m.timebase_hz = 24000000;

    m.panic_phys = 0;
    m.panic_size = 0;

    m.random_seed = g_seed;
    m.random_seed_size = sizeof(g_seed);
    m.identity = &g_identity;
    m.log_write = 0;
    return &m;
}
