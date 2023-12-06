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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static u_int8_t	*peripheral_mtime(struct hart *, u_int64_t, size_t, int);
static u_int8_t	*peripheral_mtimecmp(struct hart *, u_int64_t, size_t, int);

LIST_HEAD(, peripheral)		peripherals;

/*
 * Initializes the peripheral list and adds the default ones.
 */
void
riskie_peripheral_init(void)
{
	LIST_INIT(&peripherals);

	riskie_peripheral_add(RISKIE_MEM_REG_MTIME, 8, peripheral_mtime);
	riskie_peripheral_add(RISKIE_MEM_REG_MTIMECMP, 8, peripheral_mtimecmp);
}

/*
 * Load a dynamic module from the given path and add it as a peripheral mapped
 * at the specified address.
 */
void
riskie_peripheral_load(const char *path, u_int64_t addr, size_t len)
{
	PRECOND(path != NULL);
}

/*
 * Add a new peripheral available at the given `addr` for `len` bytes.
 * The callback is called when access at these address range occurs.
 */
void
riskie_peripheral_add(u_int64_t addr, size_t len,
    u_int8_t *(*cb)(struct hart *, u_int64_t, size_t, int))
{
	struct peripheral	*perp;

	PRECOND(cb != NULL);

	if ((perp = riskie_peripheral_from_addr(addr)) != NULL)
		fatal("overlapping peripheral for 0x%" PRIx64, addr);

	if ((perp = calloc(1, sizeof(*perp))) == NULL)
		fatal("failed to allocate new peripheral");

	perp->mem.size = len;
	perp->mem.base = addr;
	perp->validate_mem_access = cb;

	LIST_INSERT_HEAD(&peripherals, perp, list);
}

/*
 * Lookup a peripheral based on the given address.
 */
struct peripheral *
riskie_peripheral_from_addr(u_int64_t addr)
{
	struct peripheral	*perp;

	LIST_FOREACH(perp, &peripherals, list) {
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
peripheral_mtime(struct hart *ht, u_int64_t addr, size_t len, int ls)
{
	u_int8_t	*ptr;

	PRECOND(ht != NULL);
	PRECOND(addr == RISKIE_MEM_REG_MTIME);

	ptr = NULL;

	if (ht->mode == RISKIE_HART_MACHINE_MODE)
		ptr = (u_int8_t *)&ht->mregs.mtime;

	return (ptr);
}

/*
 * Access to mtimecmp for the given hart.
 */
static u_int8_t *
peripheral_mtimecmp(struct hart *ht, u_int64_t addr, size_t len, int ls)
{
	u_int8_t	*ptr;

	PRECOND(ht != NULL);
	PRECOND(addr == RISKIE_MEM_REG_MTIMECMP);

	ptr = NULL;

	if (ht->mode == RISKIE_HART_MACHINE_MODE) {
		if (ls == RISKIE_MEM_STORE)
			riskie_bit_set(&ht->flags, RISKIE_HART_FLAG_MTIMECMP);
		ptr = (u_int8_t *)&ht->mregs.mtimecmp;
	}

	return (ptr);
}
