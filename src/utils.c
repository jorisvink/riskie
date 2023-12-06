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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

/*
 * Sign extend the 32-bit value to a 64-bit value.
 */
u_int64_t
riskie_sign_extend(u_int32_t value, u_int8_t bit)
{
	u_int32_t	idx;
	u_int64_t	extended;

	PRECOND(bit <= 32);

	if (value & ((u_int32_t)1 << bit)) {
		extended = value;
		for (idx = bit + 1; idx <= 63; idx++)
			extended |= ((u_int64_t)1 << idx);
		return (extended);
	}

	return ((u_int64_t)value);
}

/*
 * Set the given bit in the given 64-bit bitmap.
 */
void
riskie_bit_set(u_int64_t *bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	*bitmap |= ((u_int64_t)1 << bit);
}

/*
 * Clear the given bit in the given 64-bit bitmap.
 */
void
riskie_bit_clear(u_int64_t *bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	*bitmap &= ~((u_int64_t)1 << bit);
}

/*
 * Get the given bit from the given 64-bit bitmap.
 */
u_int8_t
riskie_bit_get(u_int64_t bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	return ((bitmap >> bit) & 0x01);
}

/*
 * Output debug info on stdout if the debug flag was given.
 */
void
riskie_log(struct hart *ht, const char *fmt, ...)
{
	va_list		args;

	PRECOND(ht != NULL);
	PRECOND(fmt != NULL);

	if (soc->debug == 0)
		return;

	printf("[%02d] ", (u_int8_t)ht->csr[RISCV_CSR_MRO_HART_ID]);

	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		printf("[M] ");
		break;
	case RISKIE_HART_USER_MODE:
		printf("[U] ");
		break;
	default:
		printf("[?] ");
		break;
	}

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}
