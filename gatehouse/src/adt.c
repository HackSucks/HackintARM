// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/adt.c - edit the device tree Gatehouse hands to XNU.
 *
 * The tree iBoot builds is not a static artifact.  /chosen/memory-map in
 * particular is the table of *named physical ranges* iBoot fills in as it
 * loads each boot object (TrustCache, AuxKC, the boot manifests, ...); that is
 * why the authentic /chosen/memory-map carries nothing but zeroed
 * MemoryMapReserved-N placeholders.  A loader that plays iBoot has to be able
 * to add those entries, so this file implements the one operation that needs:
 * find a node by path and append a property to it.
 *
 * Apple's encoding (pexpert/pexpert/device_tree.h) has no node length field:
 *
 *     DeviceTreeNode         { u32 nProperties; u32 nChildren; }
 *     DeviceTreeNodeProperty { char name[32]; u32 length; u8 value[length]; }
 *
 * A node's extent is implied by its property and child counts, so adding a
 * property is an insert at the end of the node's property block plus one
 * increment -- there are no ancestor lengths to fix up, and the tree grows by
 * exactly the property's own size.  Values are padded to 4 bytes and a string
 * carries its NUL; bit 31 of the length is iBoot's "this is a string" flag,
 * which neither XNU nor build_adt.py sets, but we mask it when walking.
 */
#include "gh.h"

#define ADT_PROP_HDR   36          /* name[32] + length */
#define ADT_MAX_DEPTH  32

static u32 adt_rd32(const u8 *p)
{
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static void adt_wr32(u8 *p, u32 v)
{
	p[0] = (u8)v;
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
}

static u32 adt_prop_len(const u8 *dt, u64 p)
{
	return adt_rd32(dt + p + 32) & 0x7FFFFFFF;
}

static u64 adt_prop_advance(const u8 *dt, u64 p)
{
	return ADT_PROP_HDR + (((u64)adt_prop_len(dt, p) + 3) & ~3ULL);
}

/* Offset just past the node's property block, i.e. where its children begin. */
static u64 adt_prop_block_end(const u8 *dt, u64 size, u64 node)
{
	u64 p = node + 8;
	u32 n = adt_rd32(dt + node);
	u32 i;

	for (i = 0; i < n; i++) {
		u64 adv;

		if (p + ADT_PROP_HDR > size)
			return 0;
		adv = adt_prop_advance(dt, p);
		if (p + adv > size)
			return 0;
		p += adv;
	}
	return p;
}

/* Offset just past the node (properties and all descendants), or 0 on error. */
static u64 adt_node_end(const u8 *dt, u64 size, u64 node, unsigned depth)
{
	u64 p;
	u32 nchild, i;

	if (depth > ADT_MAX_DEPTH || node + 8 > size)
		return 0;
	p = adt_prop_block_end(dt, size, node);
	if (!p)
		return 0;
	nchild = adt_rd32(dt + node + 4);
	for (i = 0; i < nchild; i++) {
		p = adt_node_end(dt, size, p, depth + 1);
		if (!p)
			return 0;
	}
	return p;
}

static int adt_name_is(const u8 *dt, u64 size, u64 node, const char *want)
{
	u64 p = node + 8;
	u64 want_len = gh_strlen(want) + 1;   /* the value carries its NUL */
	u32 n = adt_rd32(dt + node);
	u32 i;

	for (i = 0; i < n; i++) {
		u32 len;

		if (p + ADT_PROP_HDR > size)
			return 0;
		len = adt_prop_len(dt, p);
		if (!gh_memcmp(dt + p, "name", 5) && len == want_len &&
		    p + ADT_PROP_HDR + len <= size &&
		    !gh_memcmp(dt + p + ADT_PROP_HDR, want, len))
			return 1;
		p += adt_prop_advance(dt, p);
	}
	return 0;
}

static u64 adt_find_child(const u8 *dt, u64 size, u64 parent, const char *name)
{
	u64 p;
	u32 n, i;

	p = adt_prop_block_end(dt, size, parent);
	if (!p)
		return 0;
	n = adt_rd32(dt + parent + 4);
	for (i = 0; i < n; i++) {
		if (adt_name_is(dt, size, p, name))
			return p;
		p = adt_node_end(dt, size, p, 0);
		if (!p)
			return 0;
	}
	return 0;
}

/* The root node is at offset 0; its name is "device-tree", not part of a path. */
static u64 adt_find_path(const u8 *dt, u64 size, const char *path)
{
	char comp[64];
	u64 node = 0;

	while (*path) {
		u64 n = 0, i;

		while (path[n] && path[n] != '/')
			n++;
		if (n == 0 || n >= sizeof(comp))
			return 0;
		for (i = 0; i < n; i++)
			comp[i] = path[i];
		comp[n] = 0;
		node = adt_find_child(dt, size, node, comp);
		if (!node)
			return 0;
		path += n;
		if (*path == '/')
			path++;
	}
	return node;
}

static int adt_get_prop(const u8 *dt, u64 size, u64 node, const char *name,
    const u8 **val, u32 *len)
{
	u64 p = node + 8;
	u32 n = adt_rd32(dt + node);
	u32 i;

	for (i = 0; i < n; i++) {
		u32 l;

		if (p + ADT_PROP_HDR > size)
			return -1;
		l = adt_prop_len(dt, p);
		if (!gh_memcmp(dt + p, name, gh_strlen(name) + 1) &&
		    p + ADT_PROP_HDR + l <= size) {
			if (val)
				*val = dt + p + ADT_PROP_HDR;
			if (len)
				*len = l;
			return 0;
		}
		p += adt_prop_advance(dt, p);
	}
	return -1;
}

/*
 * Append a property to the node at `path` (e.g. "chosen/memory-map").
 *
 * `size` is the tree's current byte length in and its new length out; `cap`
 * bounds the buffer the tree lives in (the boot-data window, GH_DT_MAX in
 * main.c).  Returns 0 on success -- including when the property is already
 * present, so a repeated call is harmless -- or -1 if the tree does not parse
 * or the edit would not fit.
 */
int gh_adt_add_property(u8 *dt, u64 cap, const char *path, const char *name,
    const void *value, u32 len, u64 *size)
{
	u64 node, p, ins, total;
	u32 nprop;
	u64 name_len;

	if (!dt || !size || !path || !name || !value)
		return -1;
	if (*size > cap || adt_node_end(dt, *size, 0, 0) != *size)
		return -1;

	name_len = gh_strlen(name);
	if (name_len == 0 || name_len > 31 || len > 0x7FFFFFFF)
		return -1;

	node = adt_find_path(dt, *size, path);
	if (!node)
		return -1;
	if (adt_get_prop(dt, *size, node, name, 0, 0) == 0)
		return 0;                       /* already published */

	p = adt_prop_block_end(dt, *size, node);
	if (!p)
		return -1;
	ins = ADT_PROP_HDR + (((u64)len + 3) & ~3ULL);
	total = *size + ins;
	if (total > cap)
		return -1;

	/* Make room at the end of the property block; the children follow it. */
	{
		u64 i;

		for (i = *size; i > p; i--)
			dt[i - 1 + ins] = dt[i - 1];
	}

	gh_memset(dt + p, 0, ins);
	gh_memcpy(dt + p, name, name_len);
	adt_wr32(dt + p + 32, len);
	gh_memcpy(dt + p + ADT_PROP_HDR, value, len);
	nprop = adt_rd32(dt + node);
	adt_wr32(dt + node, nprop + 1);
	*size = total;

	/* The edit has to leave a well-formed tree behind. */
	if (adt_node_end(dt, *size, 0, 0) != *size)
		return -1;
	return 0;
}
