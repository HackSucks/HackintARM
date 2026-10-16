// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/adt.h - the device-tree builder.
//
// XNU does not read a flattened device tree.  boot_args->deviceTreeP points at
// Apple's own encoding -- what iBoot builds on an Apple SoC, which m1n1 calls
// the "ADT" -- and pexpert/gen/device_tree.c parses exactly that:
//
//     DeviceTreeNode         { u32 nProperties; u32 nChildren; }
//     DeviceTreeNodeProperty { char name[32]; u32 length; u8 value[length]; }
//
//     node := nProperties, nChildren, nProperties * property, nChildren * node
//
// Values are opaque bytes, each padded to 4 bytes, and integers are stored
// little-endian (this is a native structure built by firmware, not a
// big-endian .dtb).  Strings carry their NUL; iBoot additionally sets bit 31
// of the length word on string values, which XNU never tests.
//
// This module is the builder every device model contributes to: the platform
// owns the tree, the devices own their nodes, and nothing in either reaches
// for a fixed address -- addresses come from the machine description (see
// include/trestle.h).  The backend is caller-provided storage; Trestle has no
// allocator.
//
// See gatehouse/dt/build_adt.py for the same tree built at bring-up time
// (Gatehouse hands XNU that one until Trestle owns the boot), and
// tools/adt_diff.py for the checker that compares the two.
#ifndef TRESTLE_ADT_H
#define TRESTLE_ADT_H

#include "trestle.h"

#define TRESTLE_ADT_NODE_NAME_MAX  32   // longest node name is 31 + NUL
#define TRESTLE_ADT_PROP_NAME_MAX  32   // the encoding gives the name 32 bytes
#define TRESTLE_ADT_NO_NODE       (-1)

typedef struct {
    char  name[TRESTLE_ADT_PROP_NAME_MAX];
    u32   length;                       // byte length of the value
    u32   offset;                       // into the byte arena
    int   next;                         // next property of the same node
} trestle_adt_prop;

typedef struct {
    char  name[TRESTLE_ADT_NODE_NAME_MAX];
    int   parent;
    int   first_prop;                   // head of the property chain
    int   last_prop;                    // tail, so appends stay O(1)
    int   first_child;
    int   last_child;
    int   next_sibling;
} trestle_adt_node;

// Declared (not defined) in trestle.h, so devices can take a builder pointer
// without including this header.
struct trestle_adt {
    u8                *data;            // byte arena for property values
    usize              data_size;
    usize              data_used;

    trestle_adt_prop  *props;
    usize              prop_capacity;
    usize              prop_count;

    trestle_adt_node  *nodes;
    usize              node_capacity;
    usize              node_count;

    int                root;
};

// Bind `adt` to caller-provided storage.  `data`, `props` and `nodes` must
// stay alive for as long as the tree is used.
trestle_status trestle_adt_init(trestle_adt *adt,
                                u8 *data, usize data_size,
                                trestle_adt_prop *props, usize prop_capacity,
                                trestle_adt_node *nodes, usize node_capacity);

// The root node, "device-tree".  Called by trestle_adt_init(); available so
// callers can read its index.
int trestle_adt_root(const trestle_adt *adt);

// Add a child node under `parent` (TRESTLE_ADT_NO_NODE selects the root) and
// return its index, or TRESTLE_ADT_NO_NODE.
int trestle_adt_add_node(trestle_adt *adt, int parent, const char *name);

// Resolve a node by path ("/", "/chosen", "/arm-io/gic").  A leading '/' is
// optional.  Returns TRESTLE_ADT_NO_NODE when the path does not resolve.
int trestle_adt_find(const trestle_adt *adt, const char *path);

// Node name, or NULL.  The name is the node's own name, not the value of its
// "name" property (which is added by trestle_adt_add_node()).
const char *trestle_adt_node_name(const trestle_adt *adt, int node);

// Property accessors.  Values are copied into the arena.
trestle_status trestle_adt_set_data(trestle_adt *adt, int node,
                                    const char *name, const void *value,
                                    usize length);
trestle_status trestle_adt_set_u32(trestle_adt *adt, int node,
                                   const char *name, u32 value);
trestle_status trestle_adt_set_u64(trestle_adt *adt, int node,
                                   const char *name, u64 value);
// A list of little-endian values: "reg", "ranges" and "interrupts" are all
// encoded that way.
trestle_status trestle_adt_set_u32v(trestle_adt *adt, int node,
                                    const char *name, const u32 *values,
                                    usize count);
trestle_status trestle_adt_set_u64v(trestle_adt *adt, int node,
                                    const char *name, const u64 *values,
                                    usize count);
// A string property: the NUL is part of the value, as the parser expects.
trestle_status trestle_adt_set_string(trestle_adt *adt, int node,
                                      const char *name, const char *value);
// An empty property (present, zero bytes long).
trestle_status trestle_adt_set_empty(trestle_adt *adt, int node,
                                     const char *name);

// Look a property up on a node: returns its value and length, or NULL.
const u8 *trestle_adt_get(const trestle_adt *adt, int node, const char *name,
                          usize *length);

// Serialise the tree into `out`.  `written` (optional) receives the byte
// count.  Fails with TRESTLE_ERR_NOMEM when `out` is too small.
trestle_status trestle_adt_serialize(const trestle_adt *adt, u8 *out,
                                     usize out_size, usize *written);

// The size the tree will serialise to.
usize trestle_adt_size(const trestle_adt *adt);

#endif // TRESTLE_ADT_H
