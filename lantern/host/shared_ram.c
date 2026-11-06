/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * lantern/host/shared_ram.c - the QEMU shared-file adapter.
 *
 * QEMU's memory-backend-file,share=on hands the guest's RAM to the host as a
 * plain shared file whose byte 0 is the guest's first physical byte.  This
 * adapter maps it, finds Gatehouse's mailbox by its magic, and hands the
 * consumer the guest's DRAM window and the mailbox.
 *
 * Nothing here knows a RAM base or a capacity: the mailbox carries both, so
 * the same binary works with -m 1G or -m 8G, and a different machine only
 * needs a different adapter that maps its own guest RAM (a hypervisor
 * mapping, a shared-memory object, or a bare-metal host's window) and calls
 * lantern_host_consume() with the same mailbox.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "consumer.h"

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

static int parse_address(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !text[0] || !end || *end)
		return -1;
	*value = (uint64_t)parsed;
	return 0;
}

/*
 * Find the mailbox and validate the geometry it publishes.  The mailbox rides
 * in Gatehouse's reserved boot-data window inside the guest's DRAM, so the
 * address the host maps it at must equal self_phys minus the window base, and
 * the window itself must be a subrange of this file.
 */
static volatile struct lantern_mailbox *find_mailbox(void *ram, uint64_t ram_bytes,
						     uint64_t *ram_base,
						     uint64_t *ram_size,
						     uint64_t expect_base,
						     int have_expect)
{
	unsigned char *resident = NULL;
	uint64_t pos;
	long host_page_size = sysconf(_SC_PAGESIZE);
	size_t scan_page_count = 4096;

	if (host_page_size < 4096 || host_page_size % 4096) {
		fprintf(stderr, "lantern-host: unsupported host page size\n");
		return NULL;
	}
	resident = calloc(scan_page_count, 1);
	if (!resident) {
		perror("lantern-host: allocate mailbox scan map");
		return NULL;
	}

	while (!stopping) {
		for (pos = 0; pos < ram_bytes && !stopping; pos +=
		     scan_page_count * (size_t)host_page_size) {
			size_t bytes = scan_page_count * (size_t)host_page_size;
			size_t count, i, within;

			if (bytes > ram_bytes - pos)
				bytes = (size_t)(ram_bytes - pos);
			count = (bytes + (size_t)host_page_size - 1) /
				(size_t)host_page_size;
			if (mincore((char *)ram + pos, bytes, resident) != 0) {
				perror("lantern-host: inspect shared RAM residency");
				free(resident);
				return NULL;
			}
			for (i = 0; i < count && !stopping; i++) {
				if (!(resident[i] & 1))
					continue;
				for (within = 0; within < (size_t)host_page_size;
				     within += 4096) {
					volatile struct lantern_mailbox *m =
						(volatile struct lantern_mailbox *)
						((char *)ram + pos +
						 i * (size_t)host_page_size +
						 within);
					uint64_t base, size, found;

					if (__atomic_load_n(&m->magic,
					    __ATOMIC_ACQUIRE) !=
					    LANTERN_MAILBOX_MAGIC)
						continue;
					base = m->ram_base;
					size = m->ram_size;
					found = m->self_phys;
					if (m->abi_version != LANTERN_ABI_VERSION ||
					    m->struct_size != sizeof(*m) ||
					    size == 0 || base + size < base ||
					    found < base || found >= base + size ||
					    pos + i * (size_t)host_page_size +
					    within != found - base) {
						fprintf(stderr,
							"lantern-host: mailbox at %#" PRIx64
							" does not describe this RAM "
							"(abi %u size %u)\n",
							found, m->abi_version,
							m->struct_size);
						free(resident);
						return NULL;
					}
					if (have_expect && base != expect_base) {
						fprintf(stderr,
							"lantern-host: mailbox says RAM "
							"base %#" PRIx64 ", expected "
							"%#" PRIx64 "\n", base,
							expect_base);
						free(resident);
						return NULL;
					}
					if (found - base > ram_bytes ||
					    size > ram_bytes) {
						fprintf(stderr,
							"lantern-host: mailbox RAM window "
							"is outside the file\n");
						free(resident);
						return NULL;
					}
					*ram_base = base;
					*ram_size = size;
					free(resident);
					return m;
				}
			}
		}
		{
			struct timespec pause = {0, 1000000};

			nanosleep(&pause, NULL);
		}
	}
	free(resident);
	return NULL;
}

int main(int argc, char **argv)
{
	int fd = -1, result = 1;
	struct stat st;
	uint64_t ram_size = 0, ram_base = 0, expect_base = 0;
	int have_expect = 0;
	unsigned char *ram = NULL;
	RvgMemoryRange range;
	RvgMemoryRangeFile file;
	RvgMemoryMap map;
	struct lantern_host_transport transport;
	volatile struct lantern_mailbox *mailbox;

	if (argc < 2 || argc > 3 ||
	    (argc == 3 && parse_address(argv[2], &expect_base))) {
		fprintf(stderr, "usage: %s SHARED-RAM-FILE [GUEST-PHYSICAL-BASE]\n",
			argv[0]);
		return 2;
	}
	have_expect = argc == 3;
	fd = open(argv[1], O_RDWR | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st)) {
		perror("lantern-host: open shared RAM");
		goto done;
	}
	if (st.st_size < (off_t)(1ull << 20) ||
	    (uint64_t)st.st_size > SIZE_MAX) {
		fprintf(stderr, "lantern-host: invalid RAM mapping\n");
		goto done;
	}
	ram = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	if (ram == MAP_FAILED) {
		perror("lantern-host: mmap shared RAM");
		ram = NULL;
		goto done;
	}
	signal(SIGINT, stop);
	signal(SIGTERM, stop);

	fprintf(stderr, "lantern-host: waiting for the guest mailbox\n");
	mailbox = find_mailbox(ram, (uint64_t)st.st_size, &ram_base, &ram_size,
			       expect_base, have_expect);
	if (!mailbox)
		goto done;

	fprintf(stderr, "lantern-host: shared RAM [%#" PRIx64 ", %#" PRIx64
		"), mailbox %#" PRIx64 "\n", ram_base, ram_base + ram_size,
		(uint64_t)mailbox->self_phys);

	range = (RvgMemoryRange){ram_base, ram_size, ram};
	map = (RvgMemoryMap){&range, 1};
	file = (RvgMemoryRangeFile){fd, 0, 0};
	transport.memory_map = &map;
	transport.memory_files = &file;
	transport.mailbox = mailbox;
	result = lantern_host_consume(&transport);

done:
	if (fd >= 0)
		close(fd);
	return result;
}
