// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/platform_nodes.c - the platform's own device-tree nodes.
//
// The values here are the platform contract: iBoot publishes exactly these on a
// VMApple, and the platform kexts and the kernel's own pexpert code read them
// by path.  Anything *per machine* -- addresses, RAM size, the SoC window, the
// identity strings -- comes from the machine description; anything that is
// firmware policy is a literal, copied property for property from the
// reference platform's tree (kernel/DeviceTree.vma2macosap.adt), so that the
// bring-up tree in gatehouse/dt/build_adt.py and this one can be compared
// property by property (tools/adt_diff.py).
#include "platform_nodes.h"

#include "adt.h"

// ---------------------------------------------------------------------------
// Property-table helpers.
// ---------------------------------------------------------------------------
typedef struct {
    const char *name;
    const char *value;
} string_prop;

typedef struct {
    const char *name;
    u32         value;
} u32_prop;

typedef struct {
    const char *name;
    u32         length;
} blob_prop;

static int put_literal(char *dst, const char *s)
{
    int n = 0;

    while (s[n] != '\0') {
        dst[n] = s[n];
        n++;
    }
    return n;
}

// Decimal, which is the form iBoot's reserved slot names use.
static int put_number(char *dst, u32 value)
{
    char tmp[12];
    int  n = 0;
    int  i;

    if (value == 0) {
        dst[0] = '0';
        return 1;
    }
    while (value != 0 && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    for (i = 0; i < n; i++)
        dst[i] = tmp[n - 1 - i];
    return n;
}

#define STRING_LIST_MAX 256

// A "compatible"-style property: several NUL-terminated strings in one value.
static trestle_status set_string_list(trestle_adt *adt, int node,
                                      const char *name,
                                      const char *const *values, usize count)
{
    char  buf[STRING_LIST_MAX];
    usize used = 0;
    usize i;

    for (i = 0; i < count; i++) {
        const char *v = values[i];

        if (v == 0)
            continue;
        while (*v != '\0') {
            if (used + 1 >= STRING_LIST_MAX)
                return TRESTLE_ERR_NOMEM;
            buf[used++] = *v++;
        }
        buf[used++] = '\0';
    }
    return trestle_adt_set_data(adt, node, name, buf, used);
}

static trestle_status add_strings(trestle_adt *adt, int node,
                                  const string_prop *props, usize count)
{
    usize i;

    for (i = 0; i < count; i++) {
        trestle_status st = trestle_adt_set_string(adt, node, props[i].name,
                                                   props[i].value);
        if (st != TRESTLE_OK)
            return st;
    }
    return TRESTLE_OK;
}

static trestle_status add_u32s(trestle_adt *adt, int node,
                               const u32_prop *props, usize count)
{
    usize i;

    for (i = 0; i < count; i++) {
        trestle_status st = trestle_adt_set_u32(adt, node, props[i].name,
                                                props[i].value);
        if (st != TRESTLE_OK)
            return st;
    }
    return TRESTLE_OK;
}

// Zero-filled properties.  These are either fixed-size tables or firmware
// blobs whose *length* is what the consumer reads: iBoot frees the contents
// once the kernel has taken them, and the reference tree ships them zeroed.
static trestle_status add_zeroblobs(trestle_adt *adt, int node,
                                    const blob_prop *props, usize count)
{
    usize i;

    for (i = 0; i < count; i++) {
        trestle_status st = trestle_adt_set_data(adt, node, props[i].name, 0,
                                                 props[i].length);
        if (st != TRESTLE_OK)
            return st;
    }
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// The reserved tables.
// ---------------------------------------------------------------------------

// /chosen/manifest-properties and /chosen/manifest-object-properties:
// 20 64-bit integers, 20 booleans and 10 fixed-size strings, all zeroed.  It is
// the table's shape that matters: Image4 fills the slots in while it processes
// the boot manifest and the SFR manifest code reads them back by name.
static trestle_status add_reserved_manifest(trestle_adt *adt, int node)
{
    char name[40];
    u8   string_slot[64];
    int  i;

    for (i = 0; i < (int)sizeof(string_slot); i++)
        string_slot[i] = 0;

    for (i = 0; i < 20; i++) {
        int k = put_literal(name, "UnusedIntegerProperty");

        k += put_number(name + k, (u32)i);
        name[k] = '\0';
        if (trestle_adt_set_u64(adt, node, name, 0) != TRESTLE_OK)
            return TRESTLE_ERR_NOMEM;
    }
    for (i = 0; i < 20; i++) {
        int k = put_literal(name, "UnusedBooleanProperty");

        k += put_number(name + k, (u32)i);
        name[k] = '\0';
        if (trestle_adt_set_u32(adt, node, name, 0) != TRESTLE_OK)
            return TRESTLE_ERR_NOMEM;
    }
    for (i = 0; i < 10; i++) {
        int k = put_literal(name, "UnusedStringProperty");

        k += put_number(name + k, (u32)i);
        name[k] = '\0';
        if (trestle_adt_set_data(adt, node, name, string_slot,
                                 sizeof(string_slot)) != TRESTLE_OK) {
            return TRESTLE_ERR_NOMEM;
        }
    }
    return TRESTLE_OK;
}

// /chosen/memory-map: iBoot reserves 16 slots and fills them in with the
// physical ranges of the boot objects (TrustCache, AuxKC, ...).  XNU asserts
// that the *node* exists and then reads each object out of it by name, so the
// slots may stay zeroed.  "kernel-only" is the boolean the same code reads.
static trestle_status add_reserved_memory_map(trestle_adt *adt, int node)
{
    char name[40];
    int  i;

    if (trestle_adt_set_string(adt, node, "kernel-only", "true") !=
        TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    for (i = 0; i < 16; i++) {
        u64  slot[2] = { 0, 0 };
        int  k = put_literal(name, "MemoryMapReserved-");

        k += put_number(name + k, (u32)i);
        name[k] = '\0';
        if (trestle_adt_set_u64v(adt, node, name, slot, 2) != TRESTLE_OK)
            return TRESTLE_ERR_NOMEM;
    }
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// /chosen: the firmware policy properties.
//
// iBoot's own policy literals.  Some hold "syscfg/..." templates because this
// file is the *reference* platform's tree, in which iBoot resolves those out
// of the syscfg region at run time; they are inert strings here and are copied
// verbatim so that a consumer which parses them behaves as it would on the
// platform this contract was written for.
//
// Two deliberate deviations, both because this machine has no SEP:
//
//   * sepfw-load-at-boot is 0 (the reference ships 1), so the SEP manager does
//     not try to load firmware that does not exist;
//   * kernel-ctrr-to-be-enabled is 0, because the CTRR is emulated (aprr.c)
//     rather than real, and the kernel only uses it when this says so.
// ---------------------------------------------------------------------------
static const u32_prop chosen_zero_u32[] = {
    { "mix-n-match-prevention-status", 0 },
    { "max-env-var-data-size", 0 },
    { "repair-environment", 0 },
    { "effective-production-status-sep", 0 },
    { "disable-transport-rm", 0 },
    { "development-cert", 0 },
    { "isp-horizon", 0 },
    { "max-env-partition", 0 },
    { "system-trusted", 0 },
    { "display-rotation", 0 },
    { "amfi-allows-trust-cache-load", 0 },
    { "enable-sep-rm", 0 },
    { "dram-vendor-id", 0 },
    { "display-boot-rotation", 0 },
    { "debug-board-revision", 0 },
    { "certificate-security-mode", 0 },
    { "disable-av-content-protection", 0 },
    { "production-cert", 0 },
    { "ephemeral-storage", 0 },
    { "debug-enabled", 0 },
    { "effective-production-status-ap", 0 },
    { "image4-cert-type", 0 },
    { "darwinos-security-environment", 0 },
    { "display-scale", 0 },
    { "effective-security-mode-sep", 0 },
    { "certificate-production-status", 0 },
    { "darwinos-userspace-reboot", 0 },
    { "csr-allow-device-configuration", 0 },
    { "recovery-snag-key-pressed", 0 },
    { "enable-user-rm", 0 },
    { "max-env-var-name-size", 0 },
    { "unrestricted-subsystem-root", 0 },
    { "use-recovery-securityd", 0 },
    { "amfi-exec-req-tc", 0 },
    { "disable-accessory-firmware", 0 },
    { "display-corner-radius", 0 },
    { "effective-security-mode-ap", 0 },
    { "board-id", 0 },
    { "sepfw-load-at-boot", 0 },        // deviation: no SEP to load
};

static const u32_prop chosen_set_u32[] = {
    { "protected-data-access", 1 },
    { "allow-whitelist-disable", 1 },
    // The platform is running code Apple did not sign, and says so: AMFI would
    // otherwise expect Apple's signatures on everything it is asked to load.
    { "non-apple-or-untrusted-code", 1 },
    { "security-downgradable", 1 },
    { "#address-cells", 2 },
};

static const string_prop chosen_strings[] = {
    { "software-bundle-version", "syscfg/SBVr/0x10,zeroes/0x10" },
    { "repair-status", "syscfg/rpcp" },
    { "software-behavior", "syscfg/SwBh/0x10,zeroes/0x10" },
    { "mac-address-wifi0", "macaddr/wifiaddr,syscfg/WMac/6" },
    { "marketing-hardware-behavior", "syscfg/MkBH" },
    { "mac-address-ethernet1", "macaddr/ethaddr1,syscfg/EMc2/6" },
    { "cs-system-policy", "default" },
    { "coverglass-color", "syscfg/CLCG" },
    { "cryptex1-certificate-format", "x509" },
    { "secureboot-key-scheme", "rsa4096" },
    { "cryptex1-key-scheme", "rsa4096" },
    { "mac-address-bluetooth0", "macaddr/btaddr,syscfg/BMac/6" },
    { "mac-address-ethernet0", "macaddr/ethaddr,syscfg/EMac/6" },
    { "enclosure-material", "syscfg/EnMt" },
    { "marketing-software-behavior", "syscfg/MkBS" },
    { "backing-glass-material", "syscfg/BGMt" },
    { "allowed-boot-args",
      "trace,trace_wake,kperf,-x,-v,trm_enabled,trace_typefilter,nox86exec" },
    { "secureboot-certificate-format", "x509" },
    { "repair-history", "syscfg/RCHL" },
    { "cover-glass-material", "syscfg/CGMt" },
    { "housing-color", "syscfg/CLHS" },
    { "backing-color", "syscfg/CLBG" },
};

static const blob_prop chosen_blobs[] = {
    { "sidp-rom-manifest-hash", 48 },
    { "host-os-information", 128 },
    { "dram-vendor", 16 },
    { "bootp-response", 300 },
    { "cl4-entropy", 192 },
    { "firmware-version", 256 },
    { "apfs-preboot-uuid", 38 },
    { "osenvironment", 32 },
    { "boot-manifest-hash", 48 },
};

static const char *const chosen_boot_type = "local";
static const char *const root_compatible[] = {
    // The platform kext names its provider from compatible[0] and IODTCompareNubName
    // tests the property as well as the node's name, so the platform expert's
    // match name has to come first; the machine's own identity follows.
    "AppleVirtualPlatformARM",
    "VMA2MACOSAP",
    "VirtualMac2,1",
};
static const char *const cpu_compatible[] = { "ARM,v8" };
static const char *const gic_compatible[] = {
    "gic,vmappl1", "ARM,gicv3", "arm,gic-v3",
};

static trestle_status build_chosen(trestle_adt *adt, const trestle_machine *m)
{
    static const u64 zero_u64[2] = { 0, 0 };
    const trestle_machine_identity *id = m->identity;
    u8  boot_type[12];
    int chosen;
    int i;
    int node;

    chosen = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "chosen");
    if (chosen == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, chosen, "AAPL,phandle", TRESTLE_PHANDLE_CHOSEN);

    if (id != 0 && id->boot_args != 0)
        trestle_adt_set_string(adt, chosen, "boot-args", id->boot_args);

    // arm_init() panics unless both of these are present.
    trestle_adt_set_u64(adt, chosen, "dram-base", m->ram_base);
    trestle_adt_set_u64(adt, chosen, "dram-size", m->ram_size);

    // PE_get_random_seed(): mandatory, non-empty, and not all zero; its
    // consumer wants the whole seed.
    if (m->random_seed != 0 && m->random_seed_size != 0)
        trestle_adt_set_data(adt, chosen, "random-seed", m->random_seed,
                             m->random_seed_size);

    // ml_unsafe_kernel_text_init() reads this to decide whether the kernel text
    // is protected by the CTRR.  The CTRR here is emulated, so the honest value
    // is "not enabled" and the text stays writable.
    trestle_adt_set_u32(adt, chosen, "kernel-ctrr-to-be-enabled", 0);

    // AppleImage4 maps this to a digest; an empty value makes it panic with
    // "non-sensical crypto hash method".
    trestle_adt_set_string(adt, chosen, "crypto-hash-method", "sha2-384");

    // The machine's chip identity, as the reference platform publishes it.
    trestle_adt_set_u64(adt, chosen, "unique-chip-id", 0);
    trestle_adt_set_u32(adt, chosen, "secure-boot", 0);
    trestle_adt_set_u32(adt, chosen, "chip-id", 0);
    trestle_adt_set_u64(adt, chosen, "boot-nonce", 0);
    trestle_adt_set_u64(adt, chosen, "die-id", 0);
    trestle_adt_set_u64v(adt, chosen, "unique-device-id", zero_u64, 2);
    trestle_adt_set_u32(adt, chosen, "gid-aes-key", 0);
    trestle_adt_set_u32(adt, chosen, "uid-aes-key", 0);
    // Present and empty: the consumer tests for the property, not its length.
    trestle_adt_set_empty(adt, chosen, "image4-supported");
    trestle_adt_set_empty(adt, chosen, "allow-ap-nonce-retrieval");

    if (add_u32s(adt, chosen, chosen_zero_u32,
                 TRESTLE_ARRAY_SIZE(chosen_zero_u32)) != TRESTLE_OK ||
        add_u32s(adt, chosen, chosen_set_u32,
                 TRESTLE_ARRAY_SIZE(chosen_set_u32)) != TRESTLE_OK ||
        add_strings(adt, chosen, chosen_strings,
                    TRESTLE_ARRAY_SIZE(chosen_strings)) != TRESTLE_OK ||
        add_zeroblobs(adt, chosen, chosen_blobs,
                      TRESTLE_ARRAY_SIZE(chosen_blobs)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    trestle_adt_set_u64(adt, chosen, "consistent-debug-root", 0);

    // boot-type is "local" followed by zeroes: a fixed 12-byte field.
    for (i = 0; i < (int)sizeof(boot_type); i++)
        boot_type[i] = 0;
    for (i = 0; chosen_boot_type[i] != '\0'; i++)
        boot_type[i] = (u8)chosen_boot_type[i];
    trestle_adt_set_data(adt, chosen, "boot-type", boot_type,
                         sizeof(boot_type));

    // The subnodes.  memory-map is asserted to exist by
    // arm_vm_prot_init(); the rest are the boot-object tables AppleImage4 and
    // the SFR manifest code look up by path, and tolerate being unpopulated.
    node = trestle_adt_add_node(adt, chosen, "memory-map");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_MEMORY_MAP);
    if (add_reserved_memory_map(adt, node) != TRESTLE_OK)
        return TRESTLE_ERR_NOMEM;

    node = trestle_adt_add_node(adt, chosen, "manifest-properties");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_MANIFEST_PROPS);
    if (add_reserved_manifest(adt, node) != TRESTLE_OK)
        return TRESTLE_ERR_NOMEM;

    node = trestle_adt_add_node(adt, chosen, "manifest-object-properties");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_MANIFEST_OBJECT_PROPS);
    if (add_reserved_manifest(adt, node) != TRESTLE_OK)
        return TRESTLE_ERR_NOMEM;

    node = trestle_adt_add_node(adt, chosen, "asmb");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_ASMB);

    node = trestle_adt_add_node(adt, chosen, "boot-object-manifests");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_BOOT_OBJECT_MANIFESTS);

    node = trestle_adt_add_node(adt, chosen, "secure-boot-hashes");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_SECURE_BOOT_HASHES);

    node = trestle_adt_add_node(adt, chosen, "dynamic-object-map");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_DYNAMIC_OBJECT_MAP);

    node = trestle_adt_add_node(adt, chosen, "carveout-memory-map");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_CARVEOUT_MEMORY_MAP);

    // lock-regs is the configuration manager's (see aprr.c), so it is not
    // added here.

    node = trestle_adt_add_node(adt, chosen, "iBoot");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_IBOOT);
    trestle_adt_set_u32(adt, node, "load-kernel-start", 0);
    trestle_adt_set_u32(adt, node, "debug-wait-start", 0);
    trestle_adt_set_u32(adt, node, "start-time", 0);
    trestle_adt_set_u32(adt, node, "populate-registry-time", 0);

    node = trestle_adt_add_node(adt, chosen, "memory-report");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_MEMORY_REPORT);

    {
        int zero = trestle_adt_add_node(adt, node, "zeroization-report");

        if (zero == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_u32(adt, zero, "AAPL,phandle",
                            TRESTLE_PHANDLE_ZEROIZATION_REPORT);
    }
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// /defaults: platform tuning.  pe_serial.c reads "serial-device" (the uart0
// phandle) and panics without it.
// ---------------------------------------------------------------------------
static const u32_prop defaults_set_u32[] = {
    { "vmm-present", 1 },
    { "force-sep-nonce", 1 },
    { "avp-encryption-version", 0 },
    { "kern.vm_compressor", 4 },
    { "pmap-max-asids", 0x4000 },
    { "has-xart", 1 },
    { "sleep-disabled", 1 },
};

static trestle_status build_defaults(trestle_adt *adt)
{
    int node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "defaults");

    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_DEFAULTS);
    trestle_adt_set_u32(adt, node, "serial-device", TRESTLE_PHANDLE_UART0);
    if (add_u32s(adt, node, defaults_set_u32,
                 TRESTLE_ARRAY_SIZE(defaults_set_u32)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    // Present and empty ("this platform has no EAN storage").
    trestle_adt_set_empty(adt, node, "ean-storage-present");
    trestle_adt_set_empty(adt, node, "no-effaceable-storage");
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// /product: the machine's product identity.
// ---------------------------------------------------------------------------
static const u32_prop product_u32[] = {
    { "has-virtualization", 1 },
    { "location-reminders", 0 },
    { "device-perf-memory-class", 0x10 },
    { "has-applelpm", 0 },
    { "builtin-mics", 0 },
    { "artwork-device-subtype", 0 },
    { "allow-32bit-apps", 1 },
    { "has-boot-chime", 0 },
    { "sandman-support", 0 },
    { "atomic-firmware-update-support", 1 },
    { "RF-exposure-separation-distance", 5 },
    { "single-stage-boot", 1 },
    { "dali-mode", 0 },
    { "apple-guest-agent-port", 0x7b4da },
    { "ui-weather-quality", 0x64 },
    { "exclaves-enabled", 0 },
    { "dual-iboot-support", 1 },
    { "has-exclaves", 0 },
    { "assistant", 0 },
    { "udid-version", 2 },
    { "ephemeral-data-mode", 0 },
    { "lockdown-certtype", 0 },
    { "dictation", 0 },
    { "artwork-scale-factor", 2 },
};

static const string_prop product_strings[] = {
    { "graphics-featureset-fallbacks",
      "APPLE6:APPLE5:APPLE4:APPLE3:APPLE3v1:APPLE2:APPLE1:GLES2,0" },
    { "compatible-device-fallback", "iPad8,6" },
    { "app-macho-architecture", "arm64" },
    { "product-description",
      "virtual machine for ARM-v8.4 with Apple Silicon extensions" },
    { "chrome-identifier", "0" },
    { "framebuffer-identifier", "0" },
    { "mobiledevice-min-ver", "1853" },
    { "compatible-app-variant", "MacFamily20,1" },
    { "graphics-featureset-class", "APPLE7" },
    { "artwork-dynamic-displaymode", "0" },
    { "partition-style", "macOS" },
    { "artwork-device-idiom", "mac" },
    { "artwork-display-gamut", "P3" },
};

// The product identity is a 20-byte value in the reference tree; it is the
// machine's, not the firmware's.
static const u8 product_id[20] = {
    0x23, 0xf1, 0x7b, 0xc0, 0x0d, 0xc6, 0xea, 0xb8, 0x16, 0x2e,
    0x14, 0x03, 0x3b, 0xea, 0x91, 0xe0, 0x57, 0xf6, 0x15, 0x10,
};

// /product/util: the platform's util-storage region table.  iBoot's own
// descriptors are opaque -- the format is not understood yet -- so the
// reference tree's values are published verbatim, which is enough for
// AppleVirtualPlatformUtilStorage to find the node and bind.  This is the part
// that will be replaced once the format is reverse engineered.
static const u8 product_util_regions[84] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x50, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0xf0, 0x4f, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x50, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x00, 0x00, 0x60, 0x00,
};

static const u8 product_util_fw_regions[24] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x20, 0x00,
};

static trestle_status build_product(trestle_adt *adt, const trestle_machine *m)
{
    const trestle_machine_identity *id = m->identity;
    int product;
    int node;

    product = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "product");
    if (product == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, product, "AAPL,phandle", TRESTLE_PHANDLE_PRODUCT);

    if (add_u32s(adt, product, product_u32,
                 TRESTLE_ARRAY_SIZE(product_u32)) != TRESTLE_OK ||
        add_strings(adt, product, product_strings,
                    TRESTLE_ARRAY_SIZE(product_strings)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }

    trestle_adt_set_data(adt, product, "product-id", product_id,
                         sizeof(product_id));
    if (id != 0) {
        if (id->fdr_product_type != 0) {
            trestle_adt_set_string(adt, product, "fdr-product-type",
                                   id->fdr_product_type);
            trestle_adt_set_string(adt, product, "sub-product-type",
                                   id->fdr_product_type);
        }
        if (id->unique_model != 0)
            trestle_adt_set_string(adt, product, "unique-model",
                                   id->unique_model);
        if (id->product_name != 0)
            trestle_adt_set_string(adt, product, "product-name",
                                   id->product_name);
    }

    // util: the region table the platform's util-storage driver looks up by
    // path.  Its "reg" is empty; the descriptors carry the ranges.
    node = trestle_adt_add_node(adt, product, "util");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_PRODUCT_UTIL);
    trestle_adt_set_empty(adt, node, "reg");
    trestle_adt_set_u32(adt, node, "low-level-fw-device-info", 1);
    trestle_adt_set_data(adt, node, "regions", product_util_regions,
                         sizeof(product_util_regions));
    trestle_adt_set_data(adt, node, "fw-regions", product_util_fw_regions,
                         sizeof(product_util_fw_regions));

    // usb-device: the identity the virtual USB controller presents to the
    // host (NCM is network-control-model Ethernet over USB).  Apple's vendor
    // id, because that is what the host sees.
    node = trestle_adt_add_node(adt, product, "usb-device");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_PRODUCT_USB);
    trestle_adt_set_u32(adt, node, "ncm-self-name-unit", 0);
    trestle_adt_set_u32(adt, node, "ncm-interrupt-ep-disabled", 1);
    trestle_adt_set_u32(adt, node, "ncm-control-ecid-mac", 1);
    trestle_adt_set_string(adt, node, "configuration-string", "ncmAuxBringup");
    trestle_adt_set_string(adt, node, "product-string",
                           "macOS Virtual Machine");
    trestle_adt_set_u32(adt, node, "vendor-id", 0x5ac);
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// /arm-io: the SoC's device window, the interrupt controller and the console.
// ---------------------------------------------------------------------------
static trestle_status build_arm_io(trestle_adt *adt, const trestle_machine *m)
{
    u64 ranges[3];
    int arm_io;
    int node;

    arm_io = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "arm-io");
    if (arm_io == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, arm_io, "AAPL,phandle", TRESTLE_PHANDLE_ARM_IO);
    // pe_identify_machine() identifies the machine from this node.
    trestle_adt_set_string(adt, arm_io, "device_type", "vmapple");
    trestle_adt_set_string(adt, arm_io, "compatible", "arm-io,vmapple1");
    trestle_adt_set_string(adt, arm_io, "soc-generation", "VMApple2");
    trestle_adt_set_u32(adt, arm_io, "chip-revision", 0);
    trestle_adt_set_u32(adt, arm_io, "#address-cells", 2);
    trestle_adt_set_u32(adt, arm_io, "#size-cells", 2);

    // pe_arm_get_soc_base_phys() takes ranges[1] as the SoC base.  A base of
    // zero means "no SoC" and disables the serial console entirely.
    ranges[0] = 0;
    ranges[1] = m->soc_base;
    ranges[2] = m->soc_size;
    trestle_adt_set_u64v(adt, arm_io, "ranges", ranges, 3);

    // The interrupt controller.  pe_init_fiq() maps exactly GICD then GICR out
    // of this "reg", and the platform's own interrupt-controller driver
    // (AppleARMGIC on Apple Silicon, gic,vmappl1 on the AVP) matches on the
    // "interrupt-controller" and "device_type" properties: without them no
    // IOInterruptController is ever published and every IOService that calls
    // registerInterrupt waits for one.
    node = trestle_adt_add_node(adt, arm_io, "gic");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    if (set_string_list(adt, node, "compatible", gic_compatible,
                        TRESTLE_ARRAY_SIZE(gic_compatible)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    trestle_adt_set_string(adt, node, "interrupt-controller", "master");
    trestle_adt_set_string(adt, node, "device_type", "interrupt-controller");
    trestle_adt_set_u32(adt, node, "#interrupt-cells", 2);
    trestle_adt_set_u32(adt, node, "#address-cells", 0);
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_GIC);
    {
        u64 reg[4];

        reg[0] = m->gic_dist_offset;
        reg[1] = m->gic_dist_size;
        reg[2] = m->gic_redist_offset;
        reg[3] = m->gic_redist_size;
        trestle_adt_set_u64v(adt, node, "reg", reg, 4);
    }

    // The console.  pe_serial.c resolves /defaults "serial-device" through
    // SecureDTFindNodeWithPhandle and panics if the node is missing, then maps
    // soc_base + reg[0].
    {
        u64           reg[2];
        u64           offset = trestle_machine_window_offset(m, "uart0");
        const trestle_machine_window *w = trestle_machine_find_window(m, "uart0");

        if (w == 0)
            return TRESTLE_ERR_NOTFOUND;
        node = trestle_adt_add_node(adt, arm_io, "uart0");
        if (node == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, node, "compatible", "arm,pl011");
        trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_UART0);
        reg[0] = offset;
        reg[1] = w->size;
        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }

    // The buttons hang off a GPIO controller.  Only the part of it the platform
    // uses is described: the reference tree gives the node a role and one
    // interrupt, and no driver in the boot path reads its registers.
    {
        const trestle_machine_window *w =
            trestle_machine_find_window(m, "pl061-buttons");

        if (w != 0) {
            u64 reg[2];

            node = trestle_adt_add_node(adt, arm_io, "pl061-buttons");
            if (node == TRESTLE_ADT_NO_NODE)
                return TRESTLE_ERR_NOMEM;
            trestle_adt_set_string(adt, node, "compatible", "ARM,pl061");
            trestle_adt_set_string(adt, node, "role", "VMA1_BUTTONS");
            trestle_adt_set_u32(adt, node, "AAPL,phandle",
                                TRESTLE_PHANDLE_PL061_BUTTONS);
            reg[0] = w->offset;
            reg[1] = w->size;
            trestle_adt_set_u64v(adt, node, "reg", reg, 2);
            if (w->irq != 0) {
                u32 irq[2];

                irq[0] = w->irq;
                irq[1] = 0;
                trestle_adt_set_u32v(adt, node, "interrupts", irq, 2);
                trestle_adt_set_u32(adt, node, "interrupt-parent",
                                    TRESTLE_PHANDLE_GIC);
            }
        }
    }
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// /cpus.
// ---------------------------------------------------------------------------
static trestle_status build_cpus(trestle_adt *adt, const trestle_machine *m)
{
    u64 freq = m->timebase_hz;
    // The interrupt list iBoot publishes for a CPU: GIC id 1 twice and GIC id
    // 0x17 = PPI 7, the PMU overflow interrupt.  The ids are machine-neutral
    // -- the machine's own DTB wires PPI 7 to arm,armv8-pmuv3 as well.
    static const u32 cpu_interrupts[6] = { 1, 1, 0x17, 1, 1, 1 };
    int cpus;
    int cpu0;

    cpus = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "cpus");
    if (cpus == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, cpus, "AAPL,phandle", TRESTLE_PHANDLE_CPUS);
    trestle_adt_set_u32(adt, cpus, "#address-cells", 1);
    trestle_adt_set_u32(adt, cpus, "#size-cells", 0);

    cpu0 = trestle_adt_add_node(adt, cpus, "cpu0");
    if (cpu0 == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    // Only cpus whose state reads "running" are parsed.
    trestle_adt_set_string(adt, cpu0, "state", "running");
    if (set_string_list(adt, cpu0, "compatible", cpu_compatible,
                        TRESTLE_ARRAY_SIZE(cpu_compatible)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    trestle_adt_set_u32(adt, cpu0, "AAPL,phandle", TRESTLE_PHANDLE_CPU0);
    trestle_adt_set_string(adt, cpu0, "device_type", "cpu");
    trestle_adt_set_u32(adt, cpu0, "interrupt-parent", TRESTLE_PHANDLE_GIC);
    trestle_adt_set_u32v(adt, cpu0, "interrupts", cpu_interrupts,
                         TRESTLE_ARRAY_SIZE(cpu_interrupts));
    trestle_adt_set_u32(adt, cpu0, "cpu-id", 0);
    // reg is the *physical* cpu id (the masked MPIDR_EL1), which is what the
    // architected timer and cpu-local code compare against.
    trestle_adt_set_u32(adt, cpu0, "reg", 0);
    trestle_adt_set_u32(adt, cpu0, "cpu-version", 0);
    trestle_adt_set_u64(adt, cpu0, "timebase-frequency", freq);
    trestle_adt_set_u64(adt, cpu0, "clock-frequency", freq);
    trestle_adt_set_u64(adt, cpu0, "memory-frequency", freq);
    trestle_adt_set_u64(adt, cpu0, "peripheral-frequency", freq);
    trestle_adt_set_u64(adt, cpu0, "fixed-frequency", freq);
    trestle_adt_set_u64(adt, cpu0, "bus-frequency", freq);
    // An empty property: its presence is what is read.
    trestle_adt_set_empty(adt, cpu0, "function-enable_core");
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// The rest of the root: the nodes the platform drivers bind to.
// ---------------------------------------------------------------------------
#define TIMEOUT_SCALES(X)                    \
    X("lock-scale")                          \
    X("debug-ack-scale")                     \
    X("lock-panic-scale")                    \
    X("interrupt-masked-b-scale")             \
    X("interrupt-masked-scale")              \
    X("sched-preemption-disable-mode")       \
    X("gicr-wake-timeout-scale")             \
    X("sshot-interrupt-masked-scale")        \
    X("ticket-lock-scale")                   \
    X("interrupt-masked-debug-mode")

static const u32_prop machine_timeout_scales[] = {
#define X(name) { name, 0 },
    TIMEOUT_SCALES(X)
#undef X
};

static trestle_status build_machine_nodes(trestle_adt *adt)
{
    int node;

    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "aliases");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_ALIASES);

    // The scales XNU applies to locks and interrupt-masked sections.  Every
    // scale is zero on this platform ("no scaling"), but the node has to
    // exist for the code that reads it.
    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "machine-timeouts");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_MACHINE_TIMEOUTS);
    if (add_u32s(adt, node, machine_timeout_scales,
                 TRESTLE_ARRAY_SIZE(machine_timeout_scales)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }

    // reg is zeroed: the kernel takes the memory map from boot_args, and these
    // two nodes only mark the device types.
    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "memory");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_MEMORY);
    trestle_adt_set_string(adt, node, "device_type", "memory");
    trestle_adt_set_u64(adt, node, "reg", 0);

    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "vram");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_VRAM);
    trestle_adt_set_string(adt, node, "device_type", "vram");
    {
        u64 reg[2] = { 0, 0 };

        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }

    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE,
                                "filesystems-props");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_FILESYSTEMS_PROPS);
    trestle_adt_set_u32(adt, node, "isc_size", 0x1f400000);
    trestle_adt_set_u32(adt, node, "apfs-crypto-disabled", 1);

    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "buttons");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_BUTTONS);
    trestle_adt_set_u32(adt, node, "aot-power", 1);

    // The virtual USB port the platform exposes to its host.
    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "port-virtual-1");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_PORT_VIRTUAL_1);
    trestle_adt_set_u32(adt, node, "port-type", 1);
    trestle_adt_set_u32(adt, node, "transports-supported", 2);
    trestle_adt_set_u32(adt, node, "port-number", 1);
    trestle_adt_set_string(adt, node, "device_type", "port-virtual");

    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "osenvironments");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle",
                        TRESTLE_PHANDLE_OSENVIRONMENTS);

    // /options is an otherwise empty node: callers test for its existence.
    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "options");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_OPTIONS);
    return TRESTLE_OK;
}

static trestle_status build_root(trestle_adt *adt, const trestle_machine *m)
{
    const trestle_machine_identity *id = m->identity;
    int root = trestle_adt_root(adt);

    if (root == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_INVAL;

    trestle_adt_set_u32(adt, root, "AAPL,phandle", TRESTLE_PHANDLE_ROOT);
    trestle_adt_set_string(adt, root, "device_type", "bootrom");
    trestle_adt_set_u32(adt, root, "#address-cells", 2);
    trestle_adt_set_u32(adt, root, "#size-cells", 2);
    trestle_adt_set_u32(adt, root, "clock-frequency", 0);
    trestle_adt_set_data(adt, root, "platform-name", 0, 32);

    if (set_string_list(adt, root, "compatible", root_compatible,
                        TRESTLE_ARRAY_SIZE(root_compatible)) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }

    if (id != 0) {
        trestle_adt_set_string(adt, root, "model", id->model);
        trestle_adt_set_string(adt, root, "target-type", id->target_type);
        trestle_adt_set_string(adt, root, "target-sub-type",
                               id->target_sub_type);
        trestle_adt_set_string(adt, root, "manufacturer", id->manufacturer);
        trestle_adt_set_string(adt, root, "device-tree-tag",
                               id->device_tree_tag);
        trestle_adt_set_string(adt, root, "serial-number",
                               id->serial_number);
        trestle_adt_set_string(adt, root, "mlb-serial-number",
                               id->mlb_serial_number);
        trestle_adt_set_string(adt, root, "region-info", id->region_info);
        trestle_adt_set_string(adt, root, "model-number", id->model_number);
        trestle_adt_set_string(adt, root, "config-number",
                               id->config_number);
        trestle_adt_set_string(adt, root, "regulatory-model-number",
                               id->regulatory_model_number);
        trestle_adt_set_string(adt, root, "country-of-origin",
                               id->country_of_origin);
        trestle_adt_set_string(adt, root, "model-config", id->model_config);
        trestle_adt_set_string(adt, root, "secure-root-prefix",
                               id->secure_root_prefix);
        trestle_adt_set_string(adt, root, "time-stamp", id->time_stamp);
    }

    if (build_chosen(adt, m) != TRESTLE_OK ||
        build_defaults(adt) != TRESTLE_OK ||
        build_product(adt, m) != TRESTLE_OK ||
        build_arm_io(adt, m) != TRESTLE_OK ||
        build_cpus(adt, m) != TRESTLE_OK ||
        build_machine_nodes(adt) != TRESTLE_OK) {
        return TRESTLE_ERR_NOMEM;
    }
    return TRESTLE_OK;
}

trestle_status trestle_platform_nodes_build(trestle_adt *adt,
                                            const trestle_machine *m)
{
    if (adt == 0 || m == 0)
        return TRESTLE_ERR_INVAL;
    return build_root(adt, m);
}
