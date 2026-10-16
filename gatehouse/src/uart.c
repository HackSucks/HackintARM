// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/uart.c
 *
 * PL011 UART driver (QEMU `virt` UART0 @ 0x0900_0000).
 *
 * Owned by Gatehouse on purpose: we never rely on the UEFI console, so the
 * same code path works after we leave Boot Services and before XNU has any
 * console of its own.
 */
#include "gh.h"

#define PL011_BASE 0x09000000ULL

#define UART_DR   0x00
#define UART_FR   0x18
#define UART_IBRD 0x24
#define UART_FBRD 0x28
#define UART_LCRH 0x2c
#define UART_CR   0x30
#define UART_IMSC 0x38
#define UART_ICR  0x44

#define FR_TXFF   (1u << 5)
#define FR_BUSY   (1u << 3)
#define CR_UARTEN (1u << 0)
#define CR_TXE    (1u << 8)
#define CR_RXE    (1u << 9)
#define LCRH_FEN  (1u << 4)
#define LCRH_WLEN_8 (3u << 5)

static inline void mmio_w32(u64 a, u32 v) { *(volatile u32 *)a = v; }
static inline u32  mmio_r32(u64 a) { return *(volatile u32 *)a; }

void gh_uart_init(void)
{
	mmio_w32(PL011_BASE + UART_CR, 0);
	/* wait for any in-flight transmission to drain */
	while (mmio_r32(PL011_BASE + UART_FR) & FR_BUSY) { }
	mmio_w32(PL011_BASE + UART_ICR, 0x7ff);
	/* 24 MHz reference -> 115200 baud (QEMU ignores the divisors) */
	mmio_w32(PL011_BASE + UART_IBRD, 13);
	mmio_w32(PL011_BASE + UART_FBRD, 1);
	mmio_w32(PL011_BASE + UART_LCRH, LCRH_FEN | LCRH_WLEN_8);
	mmio_w32(PL011_BASE + UART_IMSC, 0);
	mmio_w32(PL011_BASE + UART_CR, CR_UARTEN | CR_TXE | CR_RXE);
}

void gh_uart_putc(char c)
{
	if (c == '\n') {
		gh_uart_putc('\r');
	}
	while (mmio_r32(PL011_BASE + UART_FR) & FR_TXFF) { }
	mmio_w32(PL011_BASE + UART_DR, (u32)(unsigned char)c);
}

void gh_uart_puts(const char *s)
{
	while (*s) {
		gh_uart_putc(*s++);
	}
}

void gh_uart_puthex(u64 v)
{
	static const char d[] = "0123456789abcdef";
	char buf[16];
	int i;
	gh_uart_puts("0x");
	for (i = 15; i >= 0; i--) {
		buf[i] = d[v & 0xf];
		v >>= 4;
	}
	for (i = 0; i < 16; i++) {
		gh_uart_putc(buf[i]);
	}
}

void gh_uart_putdec(u64 v)
{
	char buf[24];
	int i = 0;
	if (v == 0) {
		gh_uart_putc('0');
		return;
	}
	while (v && i < (int)sizeof(buf)) {
		buf[i++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (i--) {
		gh_uart_putc(buf[i]);
	}
}
