/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * gatehouse/src/lantern.c - the guest-facing side of Lantern.
 *
 * Lantern translates VMApple's paravirtualised GPU protocol into a real GPU.
 * Stage 2 leaves the GPU and IOSurface windows unmapped, so every guest
 * access to them arrives here through gh_el2_trap_c().  This file is the
 * seam between that trap layer and the PVG device model.
 *
 * The device model itself is not in this image: reims-vgpu needs Vulkan and
 * an OS, neither of which exists at EL2.  It runs on the host behind a
 * transport, and this file becomes the front-end that turns a trapped
 * access into a transport request.  Until that transport is wired up, the
 * accesses are traced and answered from a small register file.  That is
 * deliberate: an access at these addresses means the guest really did reach
 * the device, so the trap, the syndrome decode, the ADT contract and the
 * register file can be validated before any GPU is involved.
 *
 * Guest contract (docs/lantern.md section 4.2): the GPU window's registers
 * are 32-bit and start at offset 0x1000; the IOSurface window's are 64-bit
 * and live at 0x1000-0x1030 of its own 64 KiB region.  Both windows are
 * trapped whole, so the offsets arrive unchanged.
 *
 * The register file here is a stand-in, not a model.  It does exactly three
 * things, so that the driver can get past probe and show what it does next:
 *
 *   - 0x1034 (binary version) echoes what the guest last wrote: the guest
 *     writes the version it wants and reads back what the host negotiated;
 *   - registers that only hold configuration (FIFO enable, length, start,
 *     interrupt mask, root page, base) read back what was written;
 *   - everything else reads as zero, as the core does for unhandled
 *     registers, and writes to it are ignored.
 *
 * Nothing here raises an interrupt or completes a command: a doorbell write
 * is traced and dropped.  Every access is traced with the guest PC, so the
 * first few lines of a boot are enough to name the kernel function that
 * made them (tools/kcsym.py).
 */
#include "gh.h"

/*
 * The machine's Lantern facts.  These start as the bring-up machine's values
 * and are replaced from the ADT after Gatehouse loads it, so the front-end,
 * stage 2 and interrupt delivery all agree with whatever the machine
 * description says.  A machine that does not describe Lantern keeps these.
 */
static u64 lantern_window_base[2] = {
	GH_LANTERN_GFX_BASE, GH_LANTERN_IOSFC_BASE
};
static u64 lantern_window_size[2] = {
	GH_LANTERN_WINDOW_SIZE, GH_LANTERN_WINDOW_SIZE
};
static u32 lantern_irq_id[2] = { GH_LANTERN_IRQ_GFX, 0x30u };
static u64 lantern_gicd = GH_GICD_BASE;

void gh_lantern_set_window(u32 which, u64 phys, u64 size)
{
	if (which < 2 && size) {
		lantern_window_base[which] = phys;
		lantern_window_size[which] = size;
	}
}

u64 gh_lantern_window_base(u32 which)
{
	return which < 2 ? lantern_window_base[which] : 0;
}

u64 gh_lantern_window_size(u32 which)
{
	return which < 2 ? lantern_window_size[which] : 0;
}

void gh_lantern_set_irq(u32 which, u32 id)
{
	if (which < 2)
		lantern_irq_id[which] = id;
}

u32 gh_lantern_irq(u32 which)
{
	return which < 2 ? lantern_irq_id[which] : 0;
}

void gh_lantern_set_gicd(u64 phys)
{
	if (phys)
		lantern_gicd = phys;
}

u64 gh_gicd_base(void)
{
	return lantern_gicd;
}

int gh_lantern_owns(u64 ipa)
{
	return (ipa >= gh_lantern_window_base(GH_LANTERN_GFX) &&
		ipa < gh_lantern_window_base(GH_LANTERN_GFX) +
		gh_lantern_window_size(GH_LANTERN_GFX)) ||
	       (ipa >= gh_lantern_window_base(GH_LANTERN_IOSFC) &&
		ipa < gh_lantern_window_base(GH_LANTERN_IOSFC) +
		gh_lantern_window_size(GH_LANTERN_IOSFC));
}

static u64 lantern_rd64le(const u8 *p)
{
	u64 v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static u32 lantern_rd32le(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
	       ((u32)p[3] << 24);
}

static int lantern_reg(const u8 *dt, u64 size, const char *path, u64 soc,
    u32 which)
{
	const u8 *reg = 0;
	u32 len = 0;

	if (gh_adt_get_property(dt, size, path, "reg", &reg, &len) != 0 ||
	    !reg || len < 16)
		return -1;
	gh_lantern_set_window(which, soc + lantern_rd64le(reg),
	    lantern_rd64le(reg + 8));
	return 0;
}

static void lantern_irq(const u8 *dt, u64 size, const char *path, u32 which)
{
	const u8 *irq = 0;
	u32 len = 0;

	if (gh_adt_get_property(dt, size, path, "interrupts", &irq, &len) == 0 &&
	    irq && len >= 4)
		gh_lantern_set_irq(which, lantern_rd32le(irq));
}

/*
 * Take the machine's Lantern facts from the device tree it is about to hand
 * XNU, rather than from the bring-up constants.  Everything is optional: a
 * tree without the nodes, or with a property this loader cannot read, keeps
 * the default, so the same binary serves a machine description with the
 * windows somewhere else -- the real 0x30200000 pair, for instance -- and a
 * tree that does not describe Lantern at all.
 *
 * `reg` is SoC-relative, resolved through /arm-io/ranges exactly as XNU
 * resolves it; `interrupts` is the GIC id the node publishes.
 */
int gh_lantern_configure_adt(const u8 *dt, u64 size)
{
	const u8 *ranges = 0;
	u32 len = 0;
	u64 soc = 0;

	if (!dt || !size)
		return -1;
	if (gh_adt_get_property(dt, size, "arm-io", "ranges", &ranges, &len) == 0 &&
	    ranges && len >= 16)
		soc = lantern_rd64le(ranges + 8);

	lantern_reg(dt, size, "arm-io/gfx", soc, GH_LANTERN_GFX);
	lantern_reg(dt, size, "arm-io/iosurface-mapper", soc,
	    GH_LANTERN_IOSFC);
	lantern_irq(dt, size, "arm-io/gfx", GH_LANTERN_GFX);
	lantern_irq(dt, size, "arm-io/iosurface-mapper", GH_LANTERN_IOSFC);

	if (gh_adt_get_property(dt, size, "arm-io/gic", "reg", &ranges,
	    &len) == 0 && ranges && len >= 8)
		gh_lantern_set_gicd(soc + lantern_rd64le(ranges));

	gh_loghex("lantern gfx     : ", gh_lantern_window_base(GH_LANTERN_GFX));
	gh_loghex("lantern iosfc   : ",
	    gh_lantern_window_base(GH_LANTERN_IOSFC));
	gh_loghex("lantern irq gfx : ", gh_lantern_irq(GH_LANTERN_GFX));
	gh_loghex("lantern irq ios : ", gh_lantern_irq(GH_LANTERN_IOSFC));
	gh_loghex("lantern gicd    : ", gh_gicd_base());
	return 0;
}

/* Lines traced per device before only a periodic count is printed. */
#define LANTERN_TRACE_LIMIT     96u
#define LANTERN_TRACE_PERIOD    0x3ffu

#define LANTERN_REG_BASE        0x1000u

/* GPU window registers (32-bit), from docs/lantern.md section 4.2. */
#define GFX_FIFO_ENABLE         0x1000u
#define GFX_FIFO_LENGTH         0x1004u
#define GFX_FIFO_WRITTEN        0x1008u
#define GFX_FIFO_READ           0x100cu
#define GFX_FIFO_START          0x1010u
#define GFX_DISPLAY_IRQ_MASK    0x1014u
#define GFX_STAMP_IRQ_MASK      0x1018u		/* read-to-clear */
#define GFX_ROOT_PAGE           0x101cu
#define GFX_DOORBELL            0x1020u
#define GFX_RESUME_LO           0x1024u
#define GFX_RESUME_HI           0x1028u
#define GFX_FAULT_FLAG          0x102cu
#define GFX_BASE                0x1030u
#define GFX_VERSION             0x1034u
#define GFX_EFI_DISPLAY         0x1200u

/* One slot per 32-bit register in [0x1000, 0x1040). */
#define GFX_SHADOW_SLOTS        16u
/* One slot per 64-bit register in [0x1000, 0x1040). */
#define IOSFC_SHADOW_SLOTS      8u

struct lantern_dev {
	const char *name;
	u64 base;
	u32 reads;
	u32 writes;
};

static struct lantern_dev lantern_gfx   = { "gfx  ", GH_LANTERN_GFX_BASE,   0, 0 };
static struct lantern_dev lantern_iosfc = { "iosfc", GH_LANTERN_IOSFC_BASE, 0, 0 };

static u32 gfx_shadow[GFX_SHADOW_SLOTS];
static u64 iosfc_shadow[IOSFC_SHADOW_SLOTS];
static u32 lantern_version;
static u32 lantern_doorbells;

static struct lantern_dev *lantern_decode(u64 ipa, u32 *off)
{
	if (ipa >= gh_lantern_window_base(GH_LANTERN_GFX) &&
	    ipa < gh_lantern_window_base(GH_LANTERN_GFX) +
	    gh_lantern_window_size(GH_LANTERN_GFX)) {
		*off = (u32)(ipa - gh_lantern_window_base(GH_LANTERN_GFX));
		return &lantern_gfx;
	}
	if (ipa >= gh_lantern_window_base(GH_LANTERN_IOSFC) &&
	    ipa < gh_lantern_window_base(GH_LANTERN_IOSFC) +
	    gh_lantern_window_size(GH_LANTERN_IOSFC)) {
		*off = (u32)(ipa - gh_lantern_window_base(GH_LANTERN_IOSFC));
		return &lantern_iosfc;
	}
	return 0;
}

static const char *gfx_reg_name(u32 off)
{
	switch (off) {
	case GFX_FIFO_ENABLE:		return "FIFO_ENABLE";
	case GFX_FIFO_LENGTH:		return "FIFO_LENGTH";
	case GFX_FIFO_WRITTEN:		return "FIFO_WRITTEN";
	case GFX_FIFO_READ:		return "FIFO_READ";
	case GFX_FIFO_START:		return "FIFO_START";
	case GFX_DISPLAY_IRQ_MASK:	return "DISPLAY_IRQ_MASK";
	case GFX_STAMP_IRQ_MASK:	return "STAMP_IRQ_MASK";
	case GFX_ROOT_PAGE:		return "ROOT_PAGE";
	case GFX_DOORBELL:		return "DOORBELL";
	case GFX_RESUME_LO:		return "RESUME_LO";
	case GFX_RESUME_HI:		return "RESUME_HI";
	case GFX_FAULT_FLAG:		return "FAULT_FLAG";
	case GFX_BASE:			return "BASE";
	case GFX_VERSION:		return "VERSION";
	default:
		if (off >= GFX_EFI_DISPLAY)
			return "EFI_DISPLAY";
		if (off < LANTERN_REG_BASE)
			return "below-register-file";
		return "unknown";
	}
}

/* Registers that only hold what the guest wrote. */
static int gfx_is_storage(u32 off)
{
	switch (off) {
	case GFX_FIFO_ENABLE:
	case GFX_FIFO_LENGTH:
	case GFX_FIFO_START:
	case GFX_DISPLAY_IRQ_MASK:
	case GFX_ROOT_PAGE:
	case GFX_BASE:
		return 1;
	default:
		return 0;
	}
}

static int gfx_shadow_slot(u32 off)
{
	if (off < LANTERN_REG_BASE || (off & 3u))
		return -1;
	off = (off - LANTERN_REG_BASE) >> 2;
	return off < GFX_SHADOW_SLOTS ? (int)off : -1;
}

static int iosfc_shadow_slot(u32 off)
{
	if (off < LANTERN_REG_BASE || (off & 7u))
		return -1;
	off = (off - LANTERN_REG_BASE) >> 3;
	return off < IOSFC_SHADOW_SLOTS ? (int)off : -1;
}

/* ------------------------------------------------------------------ */
/* Host transport                                                      */
/* ------------------------------------------------------------------ */

/*
 * With a host attached, every trapped access becomes a request in the shared
 * mailbox.  The host owns the PVG device model (reims-vgpu) and answers with
 * the register's value; interrupts come back as irq_pending bits that the
 * trap layer turns into GIC SPIs.
 *
 * The path is optional at run time, not just at build time.  A machine can
 * boot with Lantern compiled in and no host consuming the mailbox (a failed
 * host start, a debug session, real hardware before its GPU runtime exists),
 * and the guest must still boot.  So the wait is bounded: if the host never
 * raises host_ready, or stops answering, this front-end falls back to the
 * local register file below and says so once.  The shadow is kept in step
 * with successful requests, so the fallback still reads back the register
 * values the guest wrote instead of zeros.
 *
 * The mailbox's location and the DRAM window are published by Gatehouse in
 * the mailbox itself, so the host adapter needs no out-of-band RAM base.
 */
#ifdef GH_LANTERN_HOST_TRANSPORT
#include "transport.h"

static volatile struct lantern_mailbox *mailbox;
static int lantern_host_dead;

/* A host that never comes up costs one boot delay, not a hang.  The first
 * wait is generous because the host may still be creating its Vulkan device;
 * later requests are local calls and should be immediate. */
#define LANTERN_WAIT_FIRST_NS   (30ull * 1000 * 1000 * 1000)
#define LANTERN_WAIT_NS         (2ull * 1000 * 1000 * 1000)

static u64 lantern_counter(void)
{
	u64 v;

	__asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(v));
	return v;
}

static u64 lantern_counter_hz(void)
{
	u64 v;

	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v ? v : 62500000ull;	/* QEMU virt's default */
}

static int lantern_wait(volatile u32 *p, u32 want, u64 ns)
{
	u64 ticks = (lantern_counter_hz() / 1000000ull) * (ns / 1000ull);
	u64 start = lantern_counter();

	while (*p != want) {
		if (lantern_counter() - start > ticks)
			return -1;
	}
	return 0;
}

static void lantern_shadow_write(struct lantern_dev *dev, u32 off, u64 value)
{
	int slot;

	if (dev == &lantern_gfx) {
		if (off == GFX_VERSION)
			lantern_version = (u32)value;
		else if (gfx_is_storage(off) &&
		    (slot = gfx_shadow_slot(off)) >= 0)
			gfx_shadow[slot] = (u32)value;
	} else {
		slot = iosfc_shadow_slot(off);
		if (slot >= 0)
			iosfc_shadow[slot] = value;
	}
}

static int lantern_rpc(u32 device, u32 write, u32 size, u64 offset, u64 value,
    u64 *out)
{
	if (lantern_host_dead)
		return -1;
	if (!mailbox || mailbox->magic != LANTERN_MAILBOX_MAGIC) {
		lantern_host_dead = 1;
		gh_log("lantern: no host mailbox, using the register file\n");
		return -1;
	}
	if (!mailbox->host_ready &&
	    lantern_wait(&mailbox->host_ready, 1, LANTERN_WAIT_FIRST_NS) != 0) {
		lantern_host_dead = 1;
		gh_log("lantern: host did not start, using the register file\n");
		return -1;
	}
	if (lantern_wait(&mailbox->state, LANTERN_REQ_EMPTY,
	    LANTERN_WAIT_NS) != 0)
		goto lost;

	mailbox->device = device;
	mailbox->write = write;
	mailbox->reg_size = size;
	mailbox->offset = offset;
	mailbox->value = value;
	__asm__ volatile("dmb sy" ::: "memory");
	__atomic_store_n(&mailbox->state, LANTERN_REQ_READY, __ATOMIC_RELEASE);

	if (lantern_wait(&mailbox->state, LANTERN_REQ_DONE,
	    LANTERN_WAIT_NS) != 0)
		goto lost;
	__asm__ volatile("dmb sy" ::: "memory");
	*out = mailbox->result;
	__atomic_store_n(&mailbox->state, LANTERN_REQ_EMPTY, __ATOMIC_RELEASE);
	return 0;

lost:
	/*
	 * Do not try to reclaim the transaction: the host may still complete
	 * it, and a later request must not read that stale answer.  Retiring
	 * the transport for the rest of the boot is the only safe outcome.
	 */
	lantern_host_dead = 1;
	gh_log("lantern: host stopped answering, using the register file\n");
	return -1;
}

int gh_lantern_mailbox_init(u64 phys)
{
	/*
	 * The mailbox lives in Gatehouse's reserved boot-data window, in the
	 * page the caller added to that allocation, not in memory XNU will
	 * hand to the VM allocator.  That is the one place a loader may keep
	 * state for the life of the guest without inventing a hole in DRAM:
	 * everything below topOfKernelData belongs to the boot, and XNU is
	 * told not to reuse it.  It is also why this function allocates
	 * nothing: the page is already part of the kernel window.
	 */
	if (!phys || (phys & (GH_PAGE - 1)))
		return -1;

	mailbox = (volatile struct lantern_mailbox *)(u64)phys;
	gh_memset((void *)mailbox, 0, GH_EFI_PAGE);
	mailbox->abi_version = LANTERN_ABI_VERSION;
	mailbox->struct_size = (u32)sizeof(*mailbox);
	mailbox->self_phys = phys;
	mailbox->ram_base = gh_memory_base();
	mailbox->ram_size = gh_memory_size();
	mailbox->state = LANTERN_REQ_EMPTY;
	__asm__ volatile("dmb sy" ::: "memory");
	/* Last: the host attaches as soon as it sees the magic. */
	__atomic_store_n(&mailbox->magic, LANTERN_MAILBOX_MAGIC,
	    __ATOMIC_RELEASE);

	gh_loghex("lantern mailbox  : ", phys);
	gh_loghex("lantern RAM base : ", mailbox->ram_base);
	gh_loghex("lantern RAM size : ", mailbox->ram_size);
	return 0;
}

void gh_lantern_deliver_irqs(void)
{
	volatile u32 *ispendr;
	u32 pending, id;

	if (!mailbox || lantern_host_dead)
		return;
	__asm__ volatile("dmb sy" ::: "memory");
	pending = mailbox->irq_pending;
	if (!pending)
		return;
	mailbox->irq_pending = 0;
	__asm__ volatile("dmb sy" ::: "memory");
	for (id = 0; id < 2; id++) {
		u32 irq = gh_lantern_irq(id ? GH_LANTERN_IOSFC : GH_LANTERN_GFX);

		if (!(pending & (1u << id)))
			continue;
		ispendr = (volatile u32 *)(gh_gicd_base() + 0x200u +
			4u * (irq / 32u));
		*ispendr = 1u << (irq % 32u);
	}
}
#else
void gh_lantern_deliver_irqs(void) { }
#endif


/*
 * One line per access:
 *   lantern: gfx   rd  off 0x...1034 VERSION          size 4 val 0x... pc 0x...
 */
static void lantern_trace(struct lantern_dev *dev, int write, u32 off,
			  u32 size, u64 value, u64 pc, const char *name)
{
	gh_uart_puts("lantern: ");
	gh_uart_puts(dev->name);
	gh_uart_puts(write ? " wr  off " : " rd  off ");
	gh_uart_puthex(off);
	gh_uart_puts(" ");
	gh_uart_puts(name);
	gh_uart_puts(" size ");
	gh_uart_puthex(size);
	gh_uart_puts(" val ");
	gh_uart_puthex(value);
	gh_uart_puts(" pc ");
	gh_uart_puthex(pc);
	gh_uart_putc('\n');
}

static void lantern_count(struct lantern_dev *dev, int write)
{
	u32 n = write ? dev->writes : dev->reads;

	if (n >= LANTERN_TRACE_LIMIT && (n & LANTERN_TRACE_PERIOD) == 0) {
		gh_uart_puts("lantern: ");
		gh_uart_puts(dev->name);
		gh_uart_puts(write ? " writes so far " : " reads so far  ");
		gh_uart_puthex(n);
		gh_uart_putc('\n');
	}
}

/*
 * Pending an SPI in the GIC distributor.  HCR_EL2.IMO is 0, so a physical
 * IRQ is delivered straight to the guest at EL1; Trestle has to do nothing
 * else on the return path.  The guest's driver installed its handler before
 * it configured the device, so the next instruction at EL1 can take it.
 */
static void lantern_pend_gic(u32 id)
{
	volatile u32 *ispendr =
	    (volatile u32 *)(gh_gicd_base() + 0x200u + 4u * (id / 32u));

	*ispendr = 1u << (id % 32u);
	gh_uart_puts("lantern: pended irq ");
	gh_uart_puthex(id);
	gh_uart_putc('\n');
}

u64 gh_lantern_mmio_read(u64 ipa, u32 size, u64 pc)
{
	u32 off = 0;
	struct lantern_dev *dev = lantern_decode(ipa, &off);
	const char *name = "register";
	u64 value = 0;
	int slot;

	if (!dev)
		return 0;
#ifdef GH_LANTERN_HOST_TRANSPORT
	{
		u64 host_value;

		(void)pc;
		if (lantern_rpc(dev == &lantern_gfx ? LANTERN_DEVICE_GFX :
		    LANTERN_DEVICE_IOSFC, 0, size, off, 0, &host_value) == 0)
			return host_value;
	}
#endif

	if (dev == &lantern_gfx) {
		name = gfx_reg_name(off);
		if (off == GFX_VERSION) {
			value = lantern_version;
		} else if (gfx_is_storage(off) &&
			   (slot = gfx_shadow_slot(off)) >= 0) {
			value = gfx_shadow[slot];
		}
		/* STAMP_IRQ_MASK is read-to-clear; with no interrupt ever
		 * raised there is nothing pending to clear. */
	} else {
		slot = iosfc_shadow_slot(off);
		if (slot >= 0)
			value = iosfc_shadow[slot];
	}

	if (dev->reads < LANTERN_TRACE_LIMIT)
		lantern_trace(dev, 0, off, size, value, pc, name);
	else
		lantern_count(dev, 0);
	dev->reads++;
	return value;
}

void gh_lantern_mmio_write(u64 ipa, u32 size, u64 value, u64 pc)
{
	u32 off = 0;
	struct lantern_dev *dev = lantern_decode(ipa, &off);
	const char *name = "register";
	int slot;

	if (!dev)
		return;
#ifdef GH_LANTERN_HOST_TRANSPORT
	{
		u64 ignored;

		(void)pc;
		if (lantern_rpc(dev == &lantern_gfx ? LANTERN_DEVICE_GFX :
		    LANTERN_DEVICE_IOSFC, 1, size, off, value, &ignored) == 0) {
			/* Keep the local fallback coherent with what the guest
			 * wrote, in case the host disappears later. */
			lantern_shadow_write(dev, off, value);
			return;
		}
	}
#endif

	if (dev == &lantern_gfx) {
		name = gfx_reg_name(off);
		if (off == GFX_VERSION) {
			lantern_version = (u32)value;
		} else if (off == GFX_DOORBELL) {
			/* Nothing consumes the FIFO yet: say so once, then
			 * count, so a guest that spins on it is visible. */
			if (lantern_doorbells == 0)
				gh_log("lantern: first doorbell; no host to "
				       "service it yet\n");
			lantern_doorbells++;
		} else if (off == GFX_FIFO_ENABLE && (u32)value == 1u) {
			/* Probe the interrupt path: the driver has set up
			 * its handler and is about to block on a stamp.
			 * Pending the SPI proves EL2 -> GIC -> EL1 delivery
			 * without the virtual CPU interface. */
			if ((slot = gfx_shadow_slot(off)) >= 0)
				gfx_shadow[slot] = (u32)value;
			lantern_pend_gic(gh_lantern_irq(GH_LANTERN_GFX));
		} else if (gfx_is_storage(off) &&
			   (slot = gfx_shadow_slot(off)) >= 0) {
			gfx_shadow[slot] = (u32)value;
		}
	} else {
		slot = iosfc_shadow_slot(off);
		if (slot >= 0)
			iosfc_shadow[slot] = value;
	}

	if (dev->writes < LANTERN_TRACE_LIMIT)
		lantern_trace(dev, 1, off, size, value, pc, name);
	else
		lantern_count(dev, 1);
	dev->writes++;
}
