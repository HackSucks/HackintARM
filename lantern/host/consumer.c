/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <reims_vgpu.h>
#include "consumer.h"

static volatile sig_atomic_t stopping;
struct irq_context {
	const struct lantern_host_transport *transport;
	uint32_t device;
};
static void stop(int sig) { (void)sig; stopping = 1; }

static void log_line(void *ctx, RvgLogLevel level, const char *target,
		     size_t target_length, const char *message,
		     size_t message_length)
{
	(void)ctx;
	fprintf(stderr, "rvg[%u] %.*s: %.*s\n", level,
		(int)target_length, target, (int)message_length, message);
}

static unsigned long irq_raised[2];
static unsigned char seen_rd[2][0x20000 / 8];
static unsigned char seen_wr[2][0x20000 / 8];
static unsigned long probe_reads[0x40];

static void note_access(uint32_t device, int write, uint64_t offset, uint64_t value)
{
	unsigned char *seen = (write ? seen_wr : seen_rd)[device];
	const char *dev = device == LANTERN_DEVICE_GFX ? "gfx" : "ios";
	unsigned long i;
	unsigned char b;

	if (offset >= 0x20000) {
		fprintf(stderr, "lantern-host: %s %s off %#llx large = %#llx\n",
			dev, write ? "wr" : "rd",
			(unsigned long long)offset, (unsigned long long)value);
		return;
	}
	i = (unsigned long)(offset >> 3);
	b = (unsigned char)(1u << (offset & 7));
	if (!(seen[i] & b)) {
		seen[i] |= b;
		fprintf(stderr, "lantern-host: %s %s off %#llx first = %#llx\n",
			dev, write ? "wr" : "rd",
			(unsigned long long)offset, (unsigned long long)value);
	}
}

static void raise_irq(void *ctx, uint32_t vector)
{
	const struct irq_context *irq = ctx;
	unsigned long n = __atomic_add_fetch(&irq_raised[irq->device], 1,
					     __ATOMIC_RELAXED);
	if (n <= 64)
		fprintf(stderr, "lantern-host: raise_irq device=%u vector=%u #%lu\n",
			irq->device, vector, n);
	__atomic_fetch_or(&irq->transport->mailbox->irq_pending,
			  irq->device == LANTERN_DEVICE_IOSFC ?
			  LANTERN_IRQ_IOSFC : LANTERN_IRQ_GFX,
			  __ATOMIC_RELEASE);
}

int lantern_host_consume(const struct lantern_host_transport *transport)
{
	RvgHostCallbacks gfx_callbacks = {0};
	RvgIOSurfaceCallbacks iosfc_callbacks = {0};
	RvgDeviceConfig gfx_config = {0};
	RvgIOSurfaceDeviceConfig iosfc_config = {0};
	RvgWindowConfig window_config = {0};
	RvgDisplayConfig display_config = {0};
	RvgDevice *gfx = NULL;
	RvgIOSurfaceDevice *iosfc = NULL;
	RvgDisplay *display = NULL;
	struct timespec pause = {0, 100000};
	RvgStatus status;
	struct irq_context gfx_irq = {transport, LANTERN_DEVICE_GFX};
	struct irq_context iosfc_irq = {transport, LANTERN_DEVICE_IOSFC};
	uint32_t last_fifo_read = UINT32_MAX;
	uint64_t last_guest_presents = 0;
	time_t last_present_poll = 0;
	int result = 1;

	if (!transport || !transport->mailbox || !transport->memory_map ||
	    !transport->memory_files)
		return 2;
	signal(SIGINT, stop);
	signal(SIGTERM, stop);
	rvg_log_set_handler(log_line, NULL, RVG_LOG_TRACE);

	iosfc_callbacks.struct_size = sizeof(iosfc_callbacks);
	iosfc_callbacks.ctx = &iosfc_irq;
	iosfc_callbacks.raise_interrupt = raise_irq;
	iosfc_config.struct_size = sizeof(iosfc_config);
	iosfc_config.memory_map = transport->memory_map;
	iosfc_config.callbacks = &iosfc_callbacks;
	status = rvg_iosurface_device_create(&iosfc_config, &iosfc);
	if (status != RVG_OK) {
		fprintf(stderr, "lantern-host: create IOSurface: %s\n",
			rvg_status_message(status));
		goto done;
	}

	gfx_callbacks.struct_size = sizeof(gfx_callbacks);
	gfx_callbacks.ctx = &gfx_irq;
	gfx_callbacks.raise_interrupt = raise_irq;
	gfx_config.struct_size = sizeof(gfx_config);
	gfx_config.display_port_count = 1;
	gfx_config.feature_level = 0;
	gfx_config.use_iosurface_mapper = true;
	/*
	 * Apple's arm64 GPU driver makes a user task only through the
	 * isolated-task service: in-process there is no writable cursor for
	 * the task's info replies, and the guest waits forever for the task
	 * handshake.  QEMU's apple-gfx-pci sets both of these, and with
	 * process_isolation_follows_guest a task is isolated exactly when the
	 * guest has given the IOSurface mapper a descriptor table, which its
	 * arm64 mapper driver does before the GPU driver makes a task.
	 */
	gfx_config.process_isolation = true;
	gfx_config.process_isolation_follows_guest = true;
	gfx_config.memory_map = transport->memory_map;
	gfx_config.memory_files = transport->memory_files;
	gfx_config.callbacks = &gfx_callbacks;
	status = rvg_device_create(&gfx_config, &gfx);
	if (status != RVG_OK) {
		fprintf(stderr, "lantern-host: create GPU: %s\n",
			rvg_status_message(status));
		goto done;
	}

	window_config.struct_size = sizeof(window_config);
	window_config.flags = RVG_WINDOW_MATCH_HOST_SCREEN;
	/* The reference wiring offers 1920x1080 first. */
	window_config.mode_width = 1920;
	window_config.mode_height = 1080;
	display_config.struct_size = sizeof(display_config);
	display_config.serial_number = 1;
	display_config.port = 0;
	display_config.name = "Lantern";
	display_config.name_length = 7;
	/* QEMU's apple-gfx uses a 400x300 mm panel; a window adopts the screen's. */
	display_config.width_millimeters = 400.0;
	display_config.height_millimeters = 300.0;
	display_config.window = &window_config;
	status = rvg_display_create(gfx, &display_config, &display);
	if (status != RVG_OK)
		fprintf(stderr, "lantern-host: create display: %s (headless mode)\n",
			rvg_status_message(status));
	else
		fprintf(stderr, "lantern-host: display created (windowed)\n");

	/*
	 * Both devices exist now, so the guest may talk to us.  This is the
	 * last field it waits on; publish it with release so the devices'
	 * state is visible before the first request arrives.
	 */
	__atomic_store_n(&transport->mailbox->host_ready, 1, __ATOMIC_RELEASE);
	fprintf(stderr, "lantern-host: consuming guest MMIO and FIFO requests\n");
	while (!stopping) {
		volatile struct lantern_mailbox *mailbox = transport->mailbox;
		if (__atomic_load_n(&mailbox->state, __ATOMIC_ACQUIRE) ==
		    LANTERN_REQ_READY) {
			uint64_t value = mailbox->value;
			uint64_t offset = mailbox->offset;
			uint64_t result_value = 0;
			uint32_t device = mailbox->device;
			uint32_t write = mailbox->write;

			if (device == LANTERN_DEVICE_GFX) {
				if (write) {
					if (offset >= 0x1000 && offset <= 0x103c)
						fprintf(stderr,
							"lantern-host: gfx  wr %#04"
							PRIx64 " = %#"
							PRIx64 "\n", offset,
							value);
					rvg_device_mmio_write(gfx, offset,
							     (uint32_t)value);
					note_access(device, 1, offset, value);
				} else {
					result_value = rvg_device_mmio_read(gfx, offset);
					note_access(device, 0, offset, result_value);
					/*
					 * FIFO_READ is the guest's completion
					 * counter.  Print it only when it
					 * moves, so a stalled ring is
					 * obvious without flooding the log.
					 */
					if (offset == 0x100c &&
					    result_value != last_fifo_read) {
						last_fifo_read = result_value;
						fprintf(stderr,
							"lantern-host: fifo read %#"
							PRIx64 "\n",
							result_value);
					}
					/*
					 * The display interrupt bits are the
					 * guest's mode-change/present-complete
					 * source; log the value answered so a
					 * missed connect is visible.
					 */
					if ((offset == 0x1014 || offset == 0x1018) &&
					    probe_reads[offset == 0x1014 ? 0 : 1] < 128) {
						probe_reads[offset == 0x1014 ? 0 : 1]++;
						fprintf(stderr,
							"lantern-host: gfx rd off %#llx = %#llx\n",
							(unsigned long long)offset,
							(unsigned long long)result_value);
					}
				}
			} else if (device == LANTERN_DEVICE_IOSFC) {
				if (write) {
					rvg_iosurface_device_mmio_write(iosfc,
								       offset, value);
					note_access(device, 1, offset, value);
				} else {
					result_value = rvg_iosurface_device_mmio_read(
						iosfc, offset);
					note_access(device, 0, offset, result_value);
				}
			} else {
				fprintf(stderr, "lantern-host: invalid device %u\n", device);
			}
			mailbox->result = result_value;
			__atomic_store_n(&mailbox->state, LANTERN_REQ_DONE,
					 __ATOMIC_RELEASE);
		} else {
			/*
			 * The guest's presents only reach this process through
			 * the FIFO, so a change here is the one signal that
			 * something on the guest actually drew a frame.
			 */
			if (display) {
				struct timespec now;

				clock_gettime(CLOCK_MONOTONIC, &now);
				if (now.tv_sec != last_present_poll) {
					uint64_t guest_presents = 0;

					rvg_display_present_counts(
						display, &guest_presents, NULL);
					if (guest_presents != last_guest_presents) {
						last_guest_presents = guest_presents;
						fprintf(stderr,
							"lantern-host: guest presents = %"
							PRIu64 "\n",
							guest_presents);
					}
					last_present_poll = now.tv_sec;
				}
			}
			nanosleep(&pause, NULL);
		}
	}
	result = 0;

done:
	__atomic_store_n(&transport->mailbox->host_ready, 0, __ATOMIC_RELEASE);
	if (display)
		rvg_display_release(display);
	if (gfx)
		rvg_device_release(gfx);
	if (iosfc)
		rvg_iosurface_device_release(iosfc);
	return result;
}
