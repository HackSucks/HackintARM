// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/lib.c - freestanding string/memory helpers + logging.
 */
#include "gh.h"
#include "version.h"

/*
 * Build the build number from __DATE__, which C guarantees is "Mmm DD YYYY"
 * (the day is space-padded, not zero-padded, for single digits).  We want
 * DDMMYY followed by the stage suffix.
 */
const char *gh_version_string(char *buf)
{
	static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	const char *d = __DATE__;
	const char *p = months;
	int mon = 1, day, year, i = 0;

	for (; p < months + 36; p += 3) {
		if (p[0] == d[0] && p[1] == d[1] && p[2] == d[2]) {
			mon = (int)((p - months) / 3) + 1;
			break;
		}
	}
	day = (d[4] == ' ' ? 0 : d[4] - '0') * 10 + (d[5] - '0');
	year = (d[7] - '0') * 1000 + (d[8] - '0') * 100 +
	    (d[9] - '0') * 10 + (d[10] - '0');

	buf[i++] = (char)('0' + day / 10);
	buf[i++] = (char)('0' + day % 10);
	buf[i++] = (char)('0' + mon / 10);
	buf[i++] = (char)('0' + mon % 10);
	buf[i++] = (char)('0' + (year / 10) % 10);
	buf[i++] = (char)('0' + year % 10);

	for (p = GH_VERSION_STAGE; *p; p++) {
		buf[i++] = *p;
	}
	buf[i] = 0;
	return buf;
}

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
