// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/lib.c - freestanding string/memory helpers + logging.
 */
#include "gh.h"

void *gh_memset(void *d, int c, u64 n)
{
	u8 *p = (u8 *)d;
	while (n--) {
		*p++ = (u8)c;
	}
	return d;
}

void *gh_memcpy(void *d, const void *s, u64 n)
{
	u8 *dp = (u8 *)d;
	const u8 *sp = (const u8 *)s;
	while (n--) {
		*dp++ = *sp++;
	}
	return d;
}

int gh_memcmp(const void *a, const void *b, u64 n)
{
	const u8 *x = (const u8 *)a, *y = (const u8 *)b;
	while (n--) {
		if (*x != *y) {
			return (int)*x - (int)*y;
		}
		x++;
		y++;
	}
	return 0;
}

u64 gh_strlen(const char *s)
{
	u64 n = 0;
	while (s[n]) {
		n++;
	}
	return n;
}

void gh_log(const char *s)
{
	gh_uart_puts(s);
}

void gh_loghex(const char *tag, u64 v)
{
	gh_uart_puts(tag);
	gh_uart_puthex(v);
	gh_uart_putc('\n');
}

/* clang for the aarch64-windows target may emit this for big frames. */
void __chkstk(void) { }
void _chkstk(void) { }

/*
 * Force lld to emit a .reloc section.  Our code addresses data PC-relatively
 * (ADRP/ADD), so without an absolute reference lld produces a PE with
 * DYNAMIC_BASE set and no relocation directory -- which the EDK2 PE loader
 * refuses to load at a non-preferred base.
 */
extern void gh_jump_to_kernel(u64, u64, u64, u64, u64);
__attribute__((used)) const unsigned long long gh_reloc_anchor =
    (unsigned long long)&gh_jump_to_kernel;
