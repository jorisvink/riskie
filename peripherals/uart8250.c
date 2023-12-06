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

#include "riskie.h"

/*
 * A UART8250 peripheral for use in Riskie.
 */

#define UART8250_REG_SIZE	8

struct state {
	u_int64_t	regs[UART8250_REG_SIZE];
};

/*
 * Riskie will call us when we are loaded, passing the peripheral context.
 */
void
peripheral_init(struct peripheral *perp)
{
	struct state	*st;

	PRECOND(perp != NULL);

	if (perp->mem.size < sizeof(*st))
		fatal("uart8250: size too small, want %zu bytes", sizeof(*st));

	st = (struct state *)perp->mem.ptr;

	/* Set transmit hold-register empty. */
	st->regs[5] = 1 << 5;
}

/*
 * Riskie will call this function when I/O access access occurs on an address
 * that we are responsible for.
 *
 * We return a pointer to the memory location of the requested register.
 * We may return NULL for access violations.
 */
u_int8_t *
peripheral_io(struct peripheral_io_req *io)
{
	u_int8_t	reg;
	struct state	*st;

	PRECOND(io != NULL);
	PRECOND(io->ht != NULL);
	PRECOND(io->perp != NULL);

	if (io->ht->mode != RISKIE_HART_MACHINE_MODE)
		return (NULL);

	st = (struct state *)io->perp->mem.ptr;

	printf("0x%lx, %zu (%d)\n", io->addr, io->len, io->ls);
	reg = (io->addr - io->perp->mem.base) & 0xff;

	switch (reg) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		break;
	default:
		fatal("%s: unknown register %u\n", __func__, reg);
	}

	printf("returning register %u, 0x%lx\n", reg, io->addr);

	return ((u_int8_t *)&st->regs[reg]);
}
