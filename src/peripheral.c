/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static u_int8_t		*peripheral_mtime_io(struct peripheral_io_req *);
static u_int8_t		*peripheral_mtimecmp_io(struct peripheral_io_req *);

/*
 * Initializes the peripheral list and adds the default ones.
 */
void
riskie_peripheral_init(void)
{
	LIST_INIT(&soc->peripherals);

	(void)riskie_peripheral_add(RISKIE_MEM_REG_MTIME, 8,
	    peripheral_mtime_io);

	(void)riskie_peripheral_add(RISKIE_MEM_REG_MTIMECMP, 8,
	    peripheral_mtimecmp_io);
}

/*
 * Execute the "tick" function for each peripheral, if set.
 */
void
riskie_peripheral_tick(void)
{
#if 0
	LIST_FOREACH(perp, &peripherals, list) {
		if (perp->tick)
			perp->tick(perp);
	}
#endif
}

/*
 * Load a dynamic module from the given path and add it as a peripheral mapped
 * at the specified address.
 */
void
riskie_peripheral_load(const char *path, u_int64_t addr, size_t len)
{
	struct peripheral	*perp;
	void			*handle, *ptr;
	void			(*init)(struct peripheral *);
	u_int8_t		*(*io)(struct peripheral_io_req *);

	PRECOND(path != NULL);

	if ((handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL)) == NULL)
		fatal("%s", dlerror());

	if ((ptr = dlsym(handle, "peripheral_io")) == NULL)
		fatal("no 'peripheral_io` function in '%s'", path);

	*(void **)&(io) = ptr;

	perp = riskie_peripheral_add(addr, len, io);

	if ((ptr = dlsym(handle, "peripheral_init")) == NULL)
		fatal("no 'peripheral_init` function in '%s'", path);

	*(void **)&(init) = ptr;
	init(perp);
}

/*
 * Add a new peripheral available at the given `addr` for `len` bytes.
 * The callback is called when access at these address range occurs.
 */
struct peripheral *
riskie_peripheral_add(u_int64_t addr, size_t len,
    u_int8_t *(*io)(struct peripheral_io_req *))
{
	struct peripheral	*perp;

	PRECOND(io != NULL);

	if ((perp = riskie_peripheral_from_addr(addr)) != NULL)
		fatal("overlapping peripheral for 0x%" PRIx64, addr);

	if ((perp = calloc(1, sizeof(*perp))) == NULL)
		fatal("failed to allocate new peripheral");

	perp->io = io;
	perp->mem.size = len;
	perp->mem.base = addr;

	/* XXX - must be in shm later when doing multiple harts. */
	if ((perp->mem.ptr = calloc(1, perp->mem.size)) == NULL)
		fatal("failed to allocate peripheral memory");

	LIST_INSERT_HEAD(&soc->peripherals, perp, list);

	return (perp);
}

/*
 * Lookup a peripheral based on the given address.
 */
struct peripheral *
riskie_peripheral_from_addr(u_int64_t addr)
{
	struct peripheral	*perp;

	LIST_FOREACH(perp, &soc->peripherals, list) {
		if (addr >= perp->mem.base &&
		    addr <= perp->mem.base + perp->mem.size) {
			return (perp);
		}
	}

	return (NULL);
}

/*
 * Access to mtime for the given hart.
 */
static u_int8_t *
peripheral_mtime_io(struct peripheral_io_req *io)
{
	u_int8_t	*ptr;

	PRECOND(io != NULL);
	PRECOND(io->ht != NULL);
	PRECOND(io->addr == RISKIE_MEM_REG_MTIME);

	ptr = NULL;

	if (io->ht->mode == RISKIE_HART_MACHINE_MODE)
		ptr = (u_int8_t *)&io->ht->mregs.mtime;

	return (ptr);
}

/*
 * Access to mtimecmp for the given hart.
 */
static u_int8_t *
peripheral_mtimecmp_io(struct peripheral_io_req *io)
{
	u_int8_t	*ptr;

	PRECOND(io != NULL);
	PRECOND(io->ht != NULL);

	ptr = NULL;

	if (io->ht->mode == RISKIE_HART_MACHINE_MODE) {
		if (io->ls == RISKIE_MEM_STORE) {
			riskie_bit_set(&io->ht->flags,
			    RISKIE_HART_FLAG_MTIMECMP);
		}

		ptr = (u_int8_t *)&io->ht->mregs.mtimecmp;
	}

	return (ptr);
}
