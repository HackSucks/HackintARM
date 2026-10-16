// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/tests/adt_test.c - host-side checks for the platform's device tree
// and its device models.
//
// Everything Trestle builds is machine-independent C, so the whole platform can
// be assembled and inspected on the host: this test builds the tree for the
// bring-up machine, asserts the properties the boot path actually depends on
// (the console phandle, the GIC's two regions, the panic log, the boot seed,
// the NVRAM store), then does the same for the Apple virtual platform's
// description and checks the AVP devices appear there and only there.  Finally
// it exercises the device models directly: the PL031's registers and match
// interrupt, and the PSCI conduit.
//
// Given a path argument it also writes the serialised bring-up tree there so
// tools/adt_diff.py can compare it property by property with the tree
// gatehouse/dt/build_adt.py generates.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/adt.h"
#include "../include/boot.h"
#include "../include/machines.h"
#include "../include/nvram.h"
#include "../include/platform_nodes.h"
#include "../include/pmgr.h"
#include "../include/rtc.h"

// The model's time source.  A test counter lets the clock be moved by hand
// instead of waiting for a real one.
static u64 g_counter;

static u64 test_counter(void)
{
    return g_counter;
}

static const u8 *prop(const trestle_adt *adt, const char *path,
                      const char *name, usize *length)
{
    int node = trestle_adt_find(adt, path);

    if (node == TRESTLE_ADT_NO_NODE)
        return 0;
    return trestle_adt_get(adt, node, name, length);
}

static u32 prop_u32(const trestle_adt *adt, const char *path, const char *name)
{
    usize     length = 0;
    const u8 *v = prop(adt, path, name, &length);

    assert(v != 0);
    assert(length == 4);
    return (u32)v[0] | ((u32)v[1] << 8) | ((u32)v[2] << 16) | ((u32)v[3] << 24);
}

// The first 64-bit cell of a property ("reg", "dram-base", ...).
static u64 prop_u64(const trestle_adt *adt, const char *path, const char *name)
{
    usize     length = 0;
    const u8 *v = prop(adt, path, name, &length);
    u64       value = 0;

    assert(v != 0);
    assert(length >= 8);
    for (int i = 7; i >= 0; i--)
        value = (value << 8) | v[i];
    return value;
}

static void build_into(trestle_adt *adt, const trestle_machine *m)
{
    trestle_boot_clock clock;

    g_counter = 0;
    clock.counter = test_counter;
    clock.counter_hz = 1000;
    clock.epoch = 0;
    assert(trestle_boot_platform(m, &clock, adt) == TRESTLE_OK);
}

static void check_platform_contract(trestle_adt *adt,
                                    const trestle_machine *m)
{
    const u8 *v;
    usize     length = 0;

    // The nodes the boot path looks up by path.
    assert(trestle_adt_find(adt, "/chosen") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/chosen/memory-map") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/chosen/manifest-properties") !=
           TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/chosen/manifest-object-properties") !=
           TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/arm-io/gic") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/arm-io/uart0") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/cpus/cpu0") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/defaults") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/product") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/product/util") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(adt, "/pmgr") != TRESTLE_ADT_NO_NODE);

    // The console: pe_serial.c resolves /defaults "serial-device" by phandle
    // and panics when nothing carries it, and pe_arm_get_soc_base_phys() takes
    // the SoC base out of /arm-io "ranges".
    assert(prop_u32(adt, "/defaults", "serial-device") ==
           TRESTLE_PHANDLE_UART0);
    assert(prop_u32(adt, "/arm-io/uart0", "AAPL,phandle") ==
           TRESTLE_PHANDLE_UART0);
    v = prop(adt, "/arm-io", "ranges", &length);
    assert(v != 0 && length == 24);
    v = prop(adt, "/arm-io/uart0", "reg", &length);
    assert(v != 0 && length == 16);

    // pe_init_fiq() requires exactly GICD then GICR in a 32-byte "reg", and
    // every interrupt-parent has to name it.
    v = prop(adt, "/arm-io/gic", "reg", &length);
    assert(v != 0 && length == 32);
    assert(prop_u32(adt, "/arm-io/gic", "AAPL,phandle") == TRESTLE_PHANDLE_GIC);
    assert(prop_u32(adt, "/cpus/cpu0", "interrupt-parent") ==
           TRESTLE_PHANDLE_GIC);
    v = prop(adt, "/arm-io/gic", "interrupt-controller", &length);
    assert(v != 0);
    v = prop(adt, "/arm-io/gic", "device_type", &length);
    assert(v != 0 && strcmp((const char *)v, "interrupt-controller") == 0);

    // arm_init() panics without both DRAM properties, and the panic path
    // needs a region to map.
    assert(prop_u64(adt, "/chosen", "dram-base") == m->ram_base);
    assert(prop_u64(adt, "/chosen", "dram-size") == m->ram_size);
    // The panic log's region is a *boot* fact -- Gatehouse reserves it inside
    // the boot-data window -- so it is only in the tree once the boot has
    // filled it in.
    if (m->panic_size != 0) {
        assert(prop_u32(adt, "/chosen", "embedded-panic-log-size") ==
               (u32)m->panic_size);
        assert(prop_u64(adt, "/pram", "reg") == m->panic_phys);
        assert(prop_u64(adt, "/pram", "reg") != 0);
    }

    // PE_get_random_seed(): present, the full 256 bytes, and not all zero.
    v = prop(adt, "/chosen", "random-seed", &length);
    assert(v != 0 && length == 256);
    {
        int nonzero = 0;

        for (usize i = 0; i < length; i++)
            nonzero |= v[i];
        assert(nonzero != 0);
    }

    // The NVRAM store has to be the V3 image: anything else has the factory
    // build a CHRP handler that faults on first use.
    v = prop(adt, "/chosen", "nvram-proxy-data", &length);
    assert(v != 0 && length == NVRAM_DEFAULT_SIZE);
    assert((u32)v[0] == (NVRAM_V3_MAGIC & 0xff));
    assert(v[0x0e] == NVRAM_V3_VERSION);
    assert(prop_u32(adt, "/chosen", "nvram-bank-size") == NVRAM_DEFAULT_SIZE);
    assert(prop_u32(adt, "/chosen", "nvram-bank-count") == 1);
    assert(prop_u32(adt, "/chosen", "nvram-current-bank") == 0);
    assert(prop_u32(adt, "/chosen", "nvram-raw") == 0);

    // The firmware policy the platform and Image4 read.
    assert(prop_u32(adt, "/chosen", "kernel-ctrr-to-be-enabled") == 0);
    assert(prop_u32(adt, "/chosen", "sepfw-load-at-boot") == 0);
    assert(prop_u32(adt, "/chosen", "#address-cells") == 2);
    v = prop(adt, "/chosen", "crypto-hash-method", &length);
    assert(v != 0 && strcmp((const char *)v, "sha2-384") == 0);

    // The reserved tables keep their shape, which is what their consumers
    // read (they fill the slots in themselves).
    v = prop(adt, "/chosen/manifest-properties", "UnusedIntegerProperty19",
             &length);
    assert(v != 0 && length == 8);
    v = prop(adt, "/chosen/manifest-properties", "UnusedBooleanProperty19",
             &length);
    assert(v != 0 && length == 4);
    v = prop(adt, "/chosen/manifest-properties", "UnusedStringProperty9",
             &length);
    assert(v != 0 && length == 64);
    v = prop(adt, "/chosen/memory-map", "MemoryMapReserved-15", &length);
    assert(v != 0 && length == 16);

    // The CPU node's time base, and the identity the platform expert reads.
    assert(prop_u64(adt, "/cpus/cpu0", "timebase-frequency") == m->timebase_hz);
    v = prop(adt, "/", "model", &length);
    assert(v != 0 && strcmp((const char *)v, "VirtualMac2,1") == 0);
    v = prop(adt, "/", "compatible", &length);
    assert(v != 0 && strcmp((const char *)v, "AppleVirtualPlatformARM") == 0);
    assert(prop_u32(adt, "/", "#address-cells") == 2);
    assert(prop_u32(adt, "/", "AAPL,phandle") == TRESTLE_PHANDLE_ROOT);
}

static void check_machine_specific(trestle_adt *adt,
                                   const trestle_machine *m)
{
    assert(strcmp(m->identity->model, "VirtualMac2,1") == 0);
    assert(prop_u64(adt, "/arm-io/pl031-rtc", "reg") != 0);
    assert(prop_u32(adt, "/arm-io/pl061-buttons", "interrupt-parent") ==
           TRESTLE_PHANDLE_GIC);
}

int main(int argc, char **argv)
{
    // The tree builder has no allocator, so its storage is caller-provided: a
    // tree's worth of arena (the NVRAM image alone is 8 KiB), plus the node and
    // property tables the platform's tree needs.
    static u8               data[512 * 1024];
    static trestle_adt_prop props[2048];
    static trestle_adt_node nodes[128];
    static u8               out[256 * 1024];
    static trestle_rtc      rtc;
    static trestle_pmgr     pmgr;

    trestle_adt                adt;
    trestle_machine           *m;
    const trestle_machine_window *w;
    usize                      written = 0;
    usize                      length = 0;
    const u8                  *v;
    u64                        value;
    u64                        base;

    // ------------------------------------------------------------------
    // The bring-up machine's tree.
    // ------------------------------------------------------------------
    assert(trestle_adt_init(&adt, data, sizeof(data), props,
                            TRESTLE_ARRAY_SIZE(props), nodes,
                            TRESTLE_ARRAY_SIZE(nodes)) == TRESTLE_OK);
    assert(trestle_adt_root(&adt) != TRESTLE_ADT_NO_NODE);

    m = trestle_machine_qemu_virt();
    build_into(&adt, m);
    check_platform_contract(&adt, m);
    check_machine_specific(&adt, m);

    assert(trestle_adt_serialize(&adt, out, sizeof(out), &written) ==
           TRESTLE_OK);
    assert(written > 0);
    assert(written == trestle_adt_size(&adt));

    // This machine has QEMU's devices and none of the AVP's: a device whose
    // window is absent must publish nothing at all.
    assert(trestle_adt_find(&adt, "/arm-io/avp-rtc") == TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/avp-ctrr") == TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/avp-sealed-registers") ==
           TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/pvpanic") == TRESTLE_ADT_NO_NODE);

    if (argc > 1) {
        FILE *f = fopen(argv[1], "wb");

        assert(f != 0);
        assert(fwrite(out, 1, written, f) == written);
        fclose(f);
    }

    // ------------------------------------------------------------------
    // The Apple virtual platform's tree: the same platform, a different
    // machine description, and the AVP's devices appear.
    // ------------------------------------------------------------------
    assert(trestle_adt_init(&adt, data, sizeof(data), props,
                            TRESTLE_ARRAY_SIZE(props), nodes,
                            TRESTLE_ARRAY_SIZE(nodes)) == TRESTLE_OK);
    m = trestle_machine_avp();
    build_into(&adt, m);
    check_platform_contract(&adt, m);

    assert(trestle_adt_find(&adt, "/arm-io/avp-rtc") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/avp-ctrr") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/avp-sealed-registers") !=
           TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/arm-io/pvpanic") != TRESTLE_ADT_NO_NODE);
    assert(trestle_adt_find(&adt, "/chosen/lock-regs") != TRESTLE_ADT_NO_NODE);
    assert(prop_u32(&adt, "/arm-io/avp-rtc", "AAPL,phandle") ==
           TRESTLE_PHANDLE_AVP_RTC);
    assert(prop_u32(&adt, "/arm-io/avp-ctrr", "AAPL,phandle") ==
           TRESTLE_PHANDLE_AVP_CTRR);
    assert(prop_u32(&adt, "/arm-io/avp-sealed-registers", "AAPL,phandle") ==
           TRESTLE_PHANDLE_AVP_SEALED_REGISTERS);
    v = prop(&adt, "/arm-io/avp-rtc", "interrupts", &length);
    assert(v != 0 && length == 8);

    // The AVP's RAM and measured panic region are boot facts, not machine
    // facts: the description has none until the boot fills it in, and the tree
    // follows.  This is exactly what Gatehouse does with the real machine.
    assert(trestle_adt_find(&adt, "/pram") == TRESTLE_ADT_NO_NODE);
    m->ram_base = 0x100000000ull;
    m->ram_size = 0x80000000ull;
    m->panic_phys = 0x80000000ull;
    m->panic_size = 0x80000;
    assert(trestle_adt_init(&adt, data, sizeof(data), props,
                            TRESTLE_ARRAY_SIZE(props), nodes,
                            TRESTLE_ARRAY_SIZE(nodes)) == TRESTLE_OK);
    build_into(&adt, m);
    assert(prop_u64(&adt, "/chosen", "dram-base") == 0x100000000ull);
    assert(prop_u64(&adt, "/pram", "reg") == 0x80000000ull);

    // ------------------------------------------------------------------
    // The models themselves.
    // ------------------------------------------------------------------
    m = trestle_machine_qemu_virt();
    w = trestle_machine_find_window(m, "pl031-rtc");
    assert(w != 0);
    base = m->soc_base + w->offset;

    g_counter = 0;
    assert(trestle_rtc_install(&rtc, test_counter, 1000, 0) == TRESTLE_OK);
    assert(trestle_rtc_start(&rtc.device, m) == TRESTLE_OK);

    // The clock counts seconds off the machine's counter.
    g_counter = 4096 * 1000;
    value = 0;
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0x000, 4, &value) ==
           TRESTLE_OK);
    assert(value == 4096);
    assert(trestle_rtc_now(&rtc) == 4096);

    // The PrimeCell identification registers, which a driver probes.
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0xfe0, 4, &value) ==
           TRESTLE_OK);
    assert(value == 0x31);
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0xffc, 4, &value) ==
           TRESTLE_OK);
    assert(value == 0xb1);

    // A match whose time has passed raises the interrupt once it is unmasked,
    // and ICR acknowledges it.
    assert(trestle_rtc_mmio_write(&rtc.device, base + 0x004, 4, 1000) ==
           TRESTLE_OK);
    value = 1;
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0x018, 4, &value) ==
           TRESTLE_OK);
    assert(value == 0);
    assert(trestle_rtc_mmio_write(&rtc.device, base + 0x010, 4, 1) ==
           TRESTLE_OK);
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0x018, 4, &value) ==
           TRESTLE_OK);
    assert(value == 1);
    assert(trestle_rtc_mmio_write(&rtc.device, base + 0x01c, 4, 1) ==
           TRESTLE_OK);
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0x014, 4, &value) ==
           TRESTLE_OK);
    assert(value == 0);

    // Loading the register restarts the second counter from there.
    assert(trestle_rtc_mmio_write(&rtc.device, base + 0x008, 4, 0x1000) ==
           TRESTLE_OK);
    assert(trestle_rtc_mmio_read(&rtc.device, base + 0x000, 4, &value) ==
           TRESTLE_OK);
    assert(value == 0x1000);

    // An access outside every window is not this device's, and a width the
    // device does not implement is refused outright.
    assert(trestle_rtc_mmio_read(&rtc.device, 0x1000, 4, &value) ==
           TRESTLE_ERR_NOTFOUND);
    assert(trestle_rtc_mmio_read(&rtc.device, base, 8, &value) ==
           TRESTLE_ERR_INVAL);

    // The power manager's PSCI conduit answers both calling conventions.
    assert(trestle_pmgr_install(&pmgr) == TRESTLE_OK);
    assert(trestle_pmgr_start(&pmgr.device, m) == TRESTLE_OK);
    assert(trestle_pmgr_psci(&pmgr, TRESTLE_PSCI_VERSION, 0, 0, 0) == 0x10001);
    assert(trestle_pmgr_psci(&pmgr, TRESTLE_PSCI_FEATURES, TRESTLE_PSCI_CPU_ON,
                             0, 0) == TRESTLE_PSCI_SUCCESS);
    assert(trestle_pmgr_psci(&pmgr, TRESTLE_PSCI_AFFINITY_INFO, 0, 0, 0) ==
           TRESTLE_PSCI_AFFINITY_ON);
    assert(trestle_pmgr_psci(&pmgr, TRESTLE_PSCI_CPU_ON, 0, 0, 0) ==
           TRESTLE_PSCI_ALREADY_ON);
    assert(trestle_pmgr_psci(&pmgr, 0x84000003u, 0, 0, 0) ==
           TRESTLE_PSCI_ALREADY_ON);
    assert(trestle_pmgr_psci(&pmgr, 0x03000000u, 0, 0, 0) ==
           TRESTLE_PSCI_NOT_SUPPORTED);

    printf("adt_test: OK (%lu bytes, %lu nodes, %lu props)\n",
           (unsigned long)written, (unsigned long)adt.node_count,
           (unsigned long)adt.prop_count);
    return 0;
}
