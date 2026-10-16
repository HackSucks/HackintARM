// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/adt.c - the device-tree builder.
//
// A tree of nodes, each with a chain of properties.  The backing storage is
// provided by the caller (Trestle has no allocator), and serialisation walks
// the tree in the exact order XNU's parser does:
//
//     nProperties, nChildren, properties..., children...
//
// Nothing here is machine specific: the shape comes from the device models and
// the addresses come from the machine description.
#include "adt.h"

// ---------------------------------------------------------------------------
// Small freestanding helpers.  Trestle links against no runtime.
// ---------------------------------------------------------------------------
static void adt_zero(void *dst, usize n)
{
    u8 *d = (u8 *)dst;

    while (n--)
        *d++ = 0;
}

static void adt_copy(void *dst, const void *src, usize n)
{
    u8       *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;

    while (n--)
        *d++ = *s++;
}

static int adt_strlen(const char *s)
{
    int n = 0;

    while (s[n] != '\0')
        n++;
    return n;
}

static int adt_streq(const char *a, const char *b)
{
    int i = 0;

    while (a[i] != '\0' && a[i] == b[i])
        i++;
    return a[i] == b[i];
}

// The property name occupies a fixed 32-byte field in the encoding.
static int adt_name_ok(const char *name)
{
    return name != 0 && adt_strlen(name) < TRESTLE_ADT_PROP_NAME_MAX;
}

// ---------------------------------------------------------------------------
// Nodes and properties.
// ---------------------------------------------------------------------------
static trestle_adt_prop *adt_prop(trestle_adt *adt, int index)
{
    return &adt->props[index];
}

static trestle_adt_node *adt_node(trestle_adt *adt, int index)
{
    return &adt->nodes[index];
}

static int adt_node_ok(const trestle_adt *adt, int index)
{
    return index >= 0 && (usize)index < adt->node_count;
}

// Find a property by name on a node, or NULL.
static int adt_find_prop(const trestle_adt *adt, int node, const char *name)
{
    int p;

    if (!adt_node_ok(adt, node))
        return -1;
    for (p = adt->nodes[node].first_prop; p != -1; p = adt->props[p].next) {
        if (adt_streq(adt->props[p].name, name))
            return p;
    }
    return -1;
}

// Reserve `length` bytes in the arena, 4-byte aligned, and return the offset.
static int adt_alloc(trestle_adt *adt, usize length, u32 *offset)
{
    usize aligned = (adt->data_used + 3u) & ~(usize)3u;

    if (aligned + length > adt->data_size)
        return -1;
    *offset = (u32)aligned;
    adt->data_used = aligned + length;
    return 0;
}

static trestle_status adt_set(trestle_adt *adt, int node, const char *name,
                              const void *value, usize length)
{
    int              index;
    trestle_adt_prop *prop;
    u32              offset;

    if (adt == 0 || !adt_node_ok(adt, node) || !adt_name_ok(name))
        return TRESTLE_ERR_INVAL;
    if (adt_alloc(adt, length, &offset) != 0)
        return TRESTLE_ERR_NOMEM;
    if (value != 0 && length != 0)
        adt_copy(adt->data + offset, value, length);

    index = adt_find_prop(adt, node, name);
    if (index < 0) {
        if (adt->prop_count >= adt->prop_capacity)
            return TRESTLE_ERR_NOMEM;
        index = (int)adt->prop_count++;
        prop = adt_prop(adt, index);
        adt_zero(prop, sizeof(*prop));
        adt_copy(prop->name, name, (usize)adt_strlen(name));
        prop->next = -1;

        // Append to the node's chain so the properties keep the order the
        // device models published them in.
        if (adt->nodes[node].last_prop < 0)
            adt->nodes[node].first_prop = index;
        else
            adt->props[adt->nodes[node].last_prop].next = index;
        adt->nodes[node].last_prop = index;
    } else {
        // Re-publishing a property replaces its value in place, which keeps
        // device initialisation idempotent.
        prop = adt_prop(adt, index);
    }
    prop->length = (u32)length;
    prop->offset = offset;
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// Public interface.
// ---------------------------------------------------------------------------
trestle_status trestle_adt_init(trestle_adt *adt,
                                u8 *data, usize data_size,
                                trestle_adt_prop *props, usize prop_capacity,
                                trestle_adt_node *nodes, usize node_capacity)
{
    if (adt == 0 || data == 0 || props == 0 || nodes == 0 ||
        data_size == 0 || prop_capacity == 0 || node_capacity == 0) {
        return TRESTLE_ERR_INVAL;
    }
    adt->data = data;
    adt->data_size = data_size;
    adt->data_used = 0;
    adt->props = props;
    adt->prop_capacity = prop_capacity;
    adt->prop_count = 0;
    adt->nodes = nodes;
    adt->node_capacity = node_capacity;
    adt->node_count = 0;
    adt->root = TRESTLE_ADT_NO_NODE;

    adt->root = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "device-tree");
    if (adt->root == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    return TRESTLE_OK;
}

int trestle_adt_root(const trestle_adt *adt)
{
    return adt != 0 ? adt->root : TRESTLE_ADT_NO_NODE;
}

int trestle_adt_add_node(trestle_adt *adt, int parent, const char *name)
{
    int                  index;
    trestle_adt_node    *node;
    trestle_adt_node    *pnode;

    if (adt == 0 || !adt_name_ok(name))
        return TRESTLE_ADT_NO_NODE;
    if (parent == TRESTLE_ADT_NO_NODE) {
        // The first node allocated becomes the root.
        parent = adt->node_count == 0 ? TRESTLE_ADT_NO_NODE : adt->root;
    }
    if (parent != TRESTLE_ADT_NO_NODE && !adt_node_ok(adt, parent))
        return TRESTLE_ADT_NO_NODE;
    if (adt->node_count >= adt->node_capacity)
        return TRESTLE_ADT_NO_NODE;

    index = (int)adt->node_count++;
    node = adt_node(adt, index);
    adt_zero(node, sizeof(*node));
    adt_copy(node->name, name, (usize)adt_strlen(name));
    node->parent = parent;
    node->first_prop = node->last_prop = -1;
    node->first_child = node->last_child = -1;
    node->next_sibling = -1;

    if (parent != TRESTLE_ADT_NO_NODE) {
        pnode = adt_node(adt, parent);
        if (pnode->last_child < 0)
            pnode->first_child = index;
        else
            adt->nodes[pnode->last_child].next_sibling = index;
        pnode->last_child = index;
    }

    // XNU's FindChild() compares the child's "name" property, not a name
    // field, so every node carries its name as a property.
    if (adt_set(adt, index, "name", name, (usize)adt_strlen(name) + 1) !=
        TRESTLE_OK) {
        adt->node_count--;
        if (parent != TRESTLE_ADT_NO_NODE)
            adt_node(adt, parent)->last_child = -1;
        return TRESTLE_ADT_NO_NODE;
    }
    return index;
}

int trestle_adt_find(const trestle_adt *adt, const char *path)
{
    int node;

    if (adt == 0 || path == 0)
        return TRESTLE_ADT_NO_NODE;
    if (path[0] == '/')
        path++;
    node = adt->root;
    if (path[0] == '\0')
        return node;

    while (path[0] != '\0') {
        int           child;
        const char   *slash;
        int           length = 0;

        slash = path;
        while (slash[length] != '\0' && slash[length] != '/')
            length++;
        for (child = adt->nodes[node].first_child; child != -1;
             child = adt->nodes[child].next_sibling) {
            const char *name = adt->nodes[child].name;
            int         i = 0;

            while (i < length && name[i] != '\0' && name[i] == path[i])
                i++;
            if (i == length && name[i] == '\0')
                break;
        }
        if (child == -1)
            return TRESTLE_ADT_NO_NODE;
        node = child;
        path = slash + length;
        if (path[0] == '/')
            path++;
    }
    return node;
}

const char *trestle_adt_node_name(const trestle_adt *adt, int node)
{
    if (adt == 0 || !adt_node_ok(adt, node))
        return 0;
    return adt->nodes[node].name;
}

trestle_status trestle_adt_set_data(trestle_adt *adt, int node,
                                    const char *name, const void *value,
                                    usize length)
{
    return adt_set(adt, node, name, value, length);
}

trestle_status trestle_adt_set_u32(trestle_adt *adt, int node,
                                   const char *name, u32 value)
{
    u8 bytes[4];

    bytes[0] = (u8)(value);
    bytes[1] = (u8)(value >> 8);
    bytes[2] = (u8)(value >> 16);
    bytes[3] = (u8)(value >> 24);
    return adt_set(adt, node, name, bytes, sizeof(bytes));
}

trestle_status trestle_adt_set_u64(trestle_adt *adt, int node,
                                   const char *name, u64 value)
{
    u8 bytes[8];
    int i;

    for (i = 0; i < 8; i++)
        bytes[i] = (u8)(value >> (8 * i));
    return adt_set(adt, node, name, bytes, sizeof(bytes));
}

trestle_status trestle_adt_set_string(trestle_adt *adt, int node,
                                      const char *name, const char *value)
{
    int length;

    if (value == 0)
        return TRESTLE_ERR_INVAL;
    length = adt_strlen(value);
    // The NUL is part of the value: XNU's string lookups compare
    // length == strlen + 1.
    return adt_set(adt, node, name, value, (usize)length + 1);
}

// Lists are small in practice -- "reg" and "ranges" are a handful of cells --
// so they are encoded through a bounded stack buffer rather than a second
// arena.
#define ADT_LIST_MAX 32

trestle_status trestle_adt_set_u32v(trestle_adt *adt, int node,
                                    const char *name, const u32 *values,
                                    usize count)
{
    u8 bytes[ADT_LIST_MAX * 4];
    usize i;

    if (values == 0 || count == 0 || count > ADT_LIST_MAX)
        return TRESTLE_ERR_INVAL;
    for (i = 0; i < count; i++) {
        bytes[i * 4 + 0] = (u8)(values[i]);
        bytes[i * 4 + 1] = (u8)(values[i] >> 8);
        bytes[i * 4 + 2] = (u8)(values[i] >> 16);
        bytes[i * 4 + 3] = (u8)(values[i] >> 24);
    }
    return adt_set(adt, node, name, bytes, count * 4);
}

trestle_status trestle_adt_set_u64v(trestle_adt *adt, int node,
                                    const char *name, const u64 *values,
                                    usize count)
{
    u8 bytes[ADT_LIST_MAX * 8];
    usize i;

    if (values == 0 || count == 0 || count > ADT_LIST_MAX)
        return TRESTLE_ERR_INVAL;
    for (i = 0; i < count; i++) {
        int b;

        for (b = 0; b < 8; b++)
            bytes[i * 8 + b] = (u8)(values[i] >> (8 * b));
    }
    return adt_set(adt, node, name, bytes, count * 8);
}

trestle_status trestle_adt_set_empty(trestle_adt *adt, int node,
                                     const char *name)
{
    return adt_set(adt, node, name, 0, 0);
}

const u8 *trestle_adt_get(const trestle_adt *adt, int node, const char *name,
                          usize *length)
{
    int index;

    index = adt_find_prop(adt, node, name);
    if (index < 0)
        return 0;
    if (length != 0)
        *length = adt->props[index].length;
    return adt->data + adt->props[index].offset;
}

// ---------------------------------------------------------------------------
// Serialisation.
// ---------------------------------------------------------------------------
typedef struct {
    u8    *out;        // NULL while only measuring
    u8    *end;
    usize  written;
    int    overflow;
} adt_writer;

static void adt_writer_put(adt_writer *w, const void *src, usize n)
{
    if (w->out != 0) {
        if (w->out + n > w->end) {
            w->overflow = 1;
            return;
        }
        adt_copy(w->out, src, n);
        w->out += n;
    }
    w->written += n;
}

static void adt_writer_u32(adt_writer *w, u32 value)
{
    u8 bytes[4];

    bytes[0] = (u8)(value);
    bytes[1] = (u8)(value >> 8);
    bytes[2] = (u8)(value >> 16);
    bytes[3] = (u8)(value >> 24);
    adt_writer_put(w, bytes, sizeof(bytes));
}

static u32 adt_count_chain(const trestle_adt *adt, int first)
{
    u32 n = 0;
    int i;

    for (i = first; i != -1; i = adt->props[i].next)
        n++;
    return n;
}

static u32 adt_count_children(const trestle_adt *adt, int first)
{
    u32 n = 0;
    int i;

    for (i = first; i != -1; i = adt->nodes[i].next_sibling)
        n++;
    return n;
}

static void adt_emit_node(const trestle_adt *adt, int node, adt_writer *w)
{
    static const u8 zeros[4] = { 0, 0, 0, 0 };
    const trestle_adt_node *n = &adt->nodes[node];
    int                     p;
    int                     c;

    adt_writer_u32(w, adt_count_chain(adt, n->first_prop));
    adt_writer_u32(w, adt_count_children(adt, n->first_child));

    for (p = n->first_prop; p != -1; p = adt->props[p].next) {
        const trestle_adt_prop *prop = &adt->props[p];
        u8                      name[TRESTLE_ADT_PROP_NAME_MAX];
        usize                   pad;

        // Property names are a fixed 32-byte, NUL-padded field.
        adt_zero(name, sizeof(name));
        adt_copy(name, prop->name, (usize)adt_strlen(prop->name));
        adt_writer_put(w, name, sizeof(name));

        adt_writer_u32(w, prop->length);
        adt_writer_put(w, adt->data + prop->offset, prop->length);

        pad = (4u - (prop->length & 3u)) & 3u;
        if (pad != 0)
            adt_writer_put(w, zeros, pad);
    }

    for (c = n->first_child; c != -1; c = adt->nodes[c].next_sibling)
        adt_emit_node(adt, c, w);
}

usize trestle_adt_size(const trestle_adt *adt)
{
    adt_writer w;

    if (adt == 0 || adt->root == TRESTLE_ADT_NO_NODE)
        return 0;
    w.out = 0;
    w.end = 0;
    w.written = 0;
    w.overflow = 0;
    adt_emit_node(adt, adt->root, &w);
    return w.written;
}

trestle_status trestle_adt_serialize(const trestle_adt *adt, u8 *out,
                                     usize out_size, usize *written)
{
    adt_writer w;

    if (adt == 0 || out == 0 || adt->root == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_INVAL;
    w.out = out;
    w.end = out + out_size;
    w.written = 0;
    w.overflow = 0;
    adt_emit_node(adt, adt->root, &w);
    if (w.overflow)
        return TRESTLE_ERR_NOMEM;
    if (written != 0)
        *written = w.written;
    return TRESTLE_OK;
}
