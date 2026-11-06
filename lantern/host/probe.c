/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * Host-side probe for the pinned reims-vgpu C API.
 *
 * This exercises the GPU and IOSurface device models against file-backed RAM.
 * It is a library/API smoke tool; it does not connect to QEMU or emulate the
 * EL2 transport yet.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <reims_vgpu.h>

#define DEFAULT_RAM_SIZE (64ull << 20)
#define DEFAULT_RAM_BASE 0x40000000ull

struct ram {
	int fd;
	void *mapping;
	uint64_t size;
	bool unlink_on_close;
	char *path;
};

static void log_line(void *ctx, RvgLogLevel level, const char *target,
		     size_t target_length, const char *message,
		     size_t message_length)
{
	(void)ctx;
	fprintf(stderr, "rvg[%u] %.*s: %.*s\n", level,
		(int)target_length, target, (int)message_length, message);
}

static void irq(void *ctx, uint32_t vector)
{
	const char *device = ctx;
	fprintf(stderr, "lantern-probe: %s interrupt vector %" PRIu32 "\n",
		device, vector);
}

static int parse_u64(const char *arg, uint64_t *out)
{
	char *end = NULL;
	unsigned long long value;

	errno = 0;
	value = strtoull(arg, &end, 0);
	if (errno || !arg[0] || !end || *end)
		return -1;
	*out = (uint64_t)value;
	return 0;
}

static int ram_open(struct ram *ram, const char *path, uint64_t size)
{
	struct stat st;
	int flags = O_RDWR | O_CLOEXEC;

	memset(ram, 0, sizeof(*ram));
	ram->fd = -1;
	ram->size = size;
	if (path) {
		ram->fd = open(path, flags);
		if (ram->fd < 0) {
			fprintf(stderr, "open %s: %s\n", path, strerror(errno));
			return -1;
		}
		if (fstat(ram->fd, &st) || st.st_size < 0 ||
		    (uint64_t)st.st_size < size) {
			fprintf(stderr, "%s must contain at least %" PRIu64
				" bytes\n", path, size);
			close(ram->fd);
			ram->fd = -1;
			return -1;
		}
		ram->path = strdup(path);
	} else {
		char name[] = "/tmp/lantern-ram-XXXXXX";
		ram->fd = mkstemp(name);
		if (ram->fd < 0) {
			fprintf(stderr, "mkstemp: %s\n", strerror(errno));
			return -1;
		}
		(void)fcntl(ram->fd, F_SETFD, FD_CLOEXEC);
		ram->path = strdup(name);
		ram->unlink_on_close = true;
		if (ftruncate(ram->fd, (off_t)size)) {
			fprintf(stderr, "ftruncate: %s\n", strerror(errno));
			close(ram->fd);
			unlink(name);
			return -1;
		}
	}

	ram->mapping = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, ram->fd, 0);
	if (ram->mapping == MAP_FAILED) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));
		close(ram->fd);
		ram->fd = -1;
		if (ram->unlink_on_close)
			unlink(ram->path);
		return -1;
	}
	return 0;
}

static void ram_close(struct ram *ram)
{
	if (ram->mapping && ram->mapping != MAP_FAILED)
		munmap(ram->mapping, (size_t)ram->size);
	if (ram->fd >= 0)
		close(ram->fd);
	if (ram->unlink_on_close && ram->path)
		unlink(ram->path);
	free(ram->path);
}

static void print_status(const char *what, RvgStatus status)
{
	fprintf(stderr, "lantern-probe: %s: %" PRIu32 " (%s)\n", what,
		status, rvg_status_message(status));
}

int main(int argc, char **argv)
{
	const char *ram_path = NULL;
	uint64_t ram_size = DEFAULT_RAM_SIZE;
	RvgMemoryRange range;
	RvgMemoryRangeFile memory_file;
	RvgMemoryMap map;
	RvgHostCallbacks gfx_callbacks;
	RvgIOSurfaceCallbacks iosfc_callbacks;
	RvgDeviceConfig gfx_config;
	RvgIOSurfaceDeviceConfig iosfc_config;
	RvgDevice *gfx = NULL;
	RvgIOSurfaceDevice *iosfc = NULL;
	RvgStatus status;
	struct ram ram;
	int i;
	int result = 1;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--ram-file") && i + 1 < argc) {
			ram_path = argv[++i];
		} else if (!strcmp(argv[i], "--ram-size") && i + 1 < argc) {
			if (parse_u64(argv[++i], &ram_size) || ram_size == 0) {
				fprintf(stderr, "invalid --ram-size\n");
				return 2;
			}
		} else {
			fprintf(stderr, "usage: %s [--ram-file PATH] [--ram-size BYTES]\n",
				argv[0]);
			return 2;
		}
	}

	if (ram_size > SIZE_MAX || ram_size > (uint64_t)INT64_MAX) {
		fprintf(stderr, "RAM size is too large for this host\n");
		return 2;
	}
	if (ram_open(&ram, ram_path, ram_size))
		return 1;

	range.physical_address = DEFAULT_RAM_BASE;
	range.physical_length = ram_size;
	range.host_address = ram.mapping;
	map.ranges = &range;
	map.range_count = 1;
	memory_file.fd = ram.fd;
	memory_file.flags = 0;
	memory_file.offset = 0;

	rvg_log_set_handler(log_line, NULL, RVG_LOG_INFO);

	memset(&iosfc_callbacks, 0, sizeof(iosfc_callbacks));
	iosfc_callbacks.struct_size = sizeof(iosfc_callbacks);
	iosfc_callbacks.ctx = (void *)"iosurface";
	iosfc_callbacks.raise_interrupt = irq;

	memset(&iosfc_config, 0, sizeof(iosfc_config));
	iosfc_config.struct_size = sizeof(iosfc_config);
	iosfc_config.memory_map = &map;
	iosfc_config.callbacks = &iosfc_callbacks;

	status = rvg_iosurface_device_create(&iosfc_config, &iosfc);
	print_status("create iosurface", status);
	if (status != RVG_OK)
		goto done;

	memset(&gfx_callbacks, 0, sizeof(gfx_callbacks));
	gfx_callbacks.struct_size = sizeof(gfx_callbacks);
	gfx_callbacks.ctx = (void *)"gfx";
	gfx_callbacks.raise_interrupt = irq;

	memset(&gfx_config, 0, sizeof(gfx_config));
	gfx_config.struct_size = sizeof(gfx_config);
	gfx_config.display_port_count = 1;
	gfx_config.feature_level = 0;
	gfx_config.use_iosurface_mapper = true;
	gfx_config.memory_map = &map;
	gfx_config.memory_files = &memory_file;
	gfx_config.callbacks = &gfx_callbacks;

	status = rvg_device_create(&gfx_config, &gfx);
	print_status("create gfx", status);
	if (status != RVG_OK)
		goto done;

	printf("gfx:    version=%08" PRIx32 " base=%08" PRIx32 "\n",
	       rvg_device_mmio_read(gfx, 0x1034),
	       rvg_device_mmio_read(gfx, 0x1030));
	printf("iosfc:  reg[0x1000]=%016" PRIx64 "\n",
	       rvg_iosurface_device_mmio_read(iosfc, 0x1000));
	fflush(stdout);
	result = 0;

done:
	if (gfx)
		rvg_device_release(gfx);
	if (iosfc)
		rvg_iosurface_device_release(iosfc);
	ram_close(&ram);
	return result;
}
