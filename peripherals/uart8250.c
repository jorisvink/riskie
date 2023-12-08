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

#include <time.h>
#include <inttypes.h>
#include <stdio.h>

#include "riskie.h"

/*
 * A UART8250 peripheral for use in Riskie.
 * Implements the *bare* minimum to dump data to screen.
 */

/* Number of registers we have. */
#define UART8250_REG_SIZE		8

/* The Transmission Holding Register. */
#define UART8250_REG_THR		0

/* The Line Status Register. */
#define UART8250_REG_LSR		0x05

/* LSR, there is data to be read. */
#define UART8250_LSR_DATA_READY		0x01

/* LSR, transmit holding register empty. */
#define UART8250_LSR_TX_REG_EMPTY	0x20

/* LSR, transmitter empty. */
#define UART8250_LSR_TX_EMPTY		0x40

struct state {
	u_int64_t	regs[UART8250_REG_SIZE];
};

static void	uart8250_tick(struct peripheral *);
static void	uart8250_transmission_ready(struct state *);

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

	/* Allow transmission. */
	uart8250_transmission_ready(st);

	/* We setup a callback so we're executed every emulation step. */
	perp->tick = uart8250_tick;
}

/*
 * Riskie will call this function when I/O access occurs on an address
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

	if (io->ht->mode == RISKIE_HART_USER_MODE)
		return (NULL);

	st = (struct state *)io->perp->mem.ptr;
	reg = (io->addr - io->perp->mem.base) & 0xff;

	/*
	 * Indicate that the TX is busy so that we can pick it up
	 * at the next uart8250_tick and dump it.
	 */
	if (io->ls == RISKIE_MEM_STORE && reg == UART8250_REG_THR)
		st->regs[UART8250_REG_LSR] = 0;

	if (io->ls == RISKIE_MEM_LOAD && reg == UART8250_REG_THR)
		st->regs[UART8250_REG_LSR] &= ~UART8250_LSR_DATA_READY;

	return ((u_int8_t *)&st->regs[reg]);
}

/*
 * Helper function that sets the required bits so drivers know
 * they can transmit the next byte.
 */
static void
uart8250_transmission_ready(struct state *st)
{
	PRECOND(st != NULL);

	st->regs[UART8250_REG_LSR] = UART8250_LSR_TX_REG_EMPTY |
	    UART8250_LSR_TX_EMPTY;
}

/*
 * Called for each emulation step, we handle some business.
 */
static void
uart8250_tick(struct peripheral *perp)
{
	struct state	*st;
	u_int8_t	input;

	PRECOND(perp != NULL);

	st = (struct state *)perp->mem.ptr;

	/*
	 * If we have data in our TX holding register, print it and
	 * allow for the next byte.
	 */
	if ((st->regs[UART8250_REG_LSR] & UART8250_LSR_TX_REG_EMPTY) == 0) {
		printf("%c", (u_int8_t)st->regs[0]);
		fflush(stdout);
		uart8250_transmission_ready(st);
	}

	/* If there is input pending, make it available for transfer. */
	if (riskie_input_pending(&input) != -1) {
		st->regs[0] = input;
		st->regs[UART8250_REG_LSR] |= UART8250_LSR_DATA_READY;
	}
}
