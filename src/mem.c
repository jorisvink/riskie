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
 * Fetch 8 bits from the given address in our memory and return it.
 */
u_int8_t
riskie_mem_fetch8(struct hart *ht, u_int64_t addr)
{
	return ((u_int8_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 16 bits from the given address in our memory and return it.
 */
u_int16_t
riskie_mem_fetch16(struct hart *ht, u_int64_t addr)
{
	return ((u_int16_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 32 bits from the given address in our memory and return it.
 */
u_int32_t
riskie_mem_fetch32(struct hart *ht, u_int64_t addr)
{
	return ((u_int32_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 64 bits from address in our memory and return it.
 */
u_int64_t
riskie_mem_fetch64(struct hart *ht, u_int64_t addr)
{
	u_int64_t	v;
	u_int8_t	*ptr;

	PRECOND(ht != NULL);

	ptr = riskie_mem_validate_access(ht, addr, 8, RISKIE_MEM_LOAD);
	if (ptr == NULL)
		return (0);

	v = (u_int64_t)ptr[0] |
	    (u_int64_t)ptr[1] << 8 |
	    (u_int64_t)ptr[2] << 16 |
	    (u_int64_t)ptr[3] << 24 |
	    (u_int64_t)ptr[4] << 32 |
	    (u_int64_t)ptr[5] << 40 |
	    (u_int64_t)ptr[6] << 48 |
	    (u_int64_t)ptr[7] << 56;

	return (v);
}

/*
 * Fetch given amount of bits from our memory and return it.
 *
 * The memory access check is done by riskie_mem_fetch64() which is
 * called for each type.
 */
u_int64_t
riskie_mem_fetch(struct hart *ht, u_int64_t addr, u_int16_t bits)
{
	u_int64_t	v;

	PRECOND(ht != NULL);

	riskie_log(ht,
	    "MEM-FETCH: addr=0x%" PRIx64 ", bits=%u\n", addr, bits);

	switch (bits) {
	case 8:
		v = riskie_mem_fetch8(ht, addr);
		break;
	case 16:
		v = riskie_mem_fetch16(ht, addr);
		break;
	case 32:
		v = riskie_mem_fetch32(ht, addr);
		break;
	case 64:
		v = riskie_mem_fetch64(ht, addr);
		break;
	default:
		riskie_hart_fatal(ht, "%s: unknown bits %u", __func__, bits);
	}

	return (v);
}

/*
 * Store 8 bits at the given address.
 */
void
riskie_mem_store8(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_mem_validate_access(ht, addr, 1, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
}

/*
 * Store 16 bits at the given address.
 */
void
riskie_mem_store16(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_mem_validate_access(ht, addr, 2, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
	ptr[1] = (u_int8_t)((value >> 8) & 0xff);
}

/*
 * Store 32 bits at the given address.
 */
void
riskie_mem_store32(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_mem_validate_access(ht, addr, 4, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
	ptr[1] = (u_int8_t)((value >> 8) & 0xff);
	ptr[2] = (u_int8_t)((value >> 16) & 0xff);
	ptr[3] = (u_int8_t)((value >> 24) & 0xff);
}

/*
 * Store 64 bits at the given address.
 */
void
riskie_mem_store64(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_mem_validate_access(ht, addr, 8, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
	ptr[1] = (u_int8_t)((value >> 8) & 0xff);
	ptr[2] = (u_int8_t)((value >> 16) & 0xff);
	ptr[3] = (u_int8_t)((value >> 24) & 0xff);
	ptr[4] = (u_int8_t)((value >> 32) & 0xff);
	ptr[5] = (u_int8_t)((value >> 40) & 0xff);
	ptr[6] = (u_int8_t)((value >> 48) & 0xff);
	ptr[7] = (u_int8_t)((value >> 56) & 0xff);
}

/*
 * Store the given amount of bits into memory.
 */
void
riskie_mem_store(struct hart *ht, u_int64_t addr, u_int64_t value, size_t bits)
{
	PRECOND(ht != NULL);

	riskie_log(ht,
	    "MEM-STORE: addr=0x%" PRIx64 ", value=0x%" PRIx64 ", bits=%zu\n",
	    addr, value, bits);

	if (ht->lr.valid == 1 &&
	    (addr >= ht->lr.addr && addr <= ht->lr.addr + sizeof(u_int64_t))) {
		ht->lr.addr = 0;
		ht->lr.valid = 0;
		ht->lr.value = 0;
	}

	switch (bits) {
	case 8:
		riskie_mem_store8(ht, addr, value);
		break;
	case 16:
		riskie_mem_store16(ht, addr, value);
		break;
	case 32:
		riskie_mem_store32(ht, addr, value);
		break;
	case 64:
		riskie_mem_store64(ht, addr, value);
		break;
	default:
		riskie_hart_fatal(ht, "%s: unknown bits %zu", __func__, bits);
	}
}

/*
 * Check if we can access memory at addr for the given amount of bytes.
 * XXX - The privilege accesses should be checked here later.
 *
 * This will return a pointer to where the data can be written, which
 * is essentially &ht->mem[addr] unless addr was a memory mapped register,
 * in which case a pointer to the correct mreg is returned.
 */
u_int8_t *
riskie_mem_validate_access(struct hart *ht, u_int64_t addr, size_t len, int ls)
{
	u_int8_t	*ptr;

	PRECOND(ht != NULL);
	PRECOND(ls == RISKIE_MEM_STORE || ls == RISKIE_MEM_LOAD);

	ptr = NULL;

	/*
	 * Check for memory mapped registers or any other peripheral
	 * memory space first.
	 */
	switch (addr) {
	case RISKIE_MEM_REG_MTIME:
		if (ht->mode == RISKIE_HART_MACHINE_MODE)
			ptr = (u_int8_t *)&ht->mregs.mtime;
		break;
	case RISKIE_MEM_REG_MTIMECMP:
		if (ht->mode == RISKIE_HART_MACHINE_MODE) {
			if (ls == RISKIE_MEM_STORE) {
				riskie_bit_set(&ht->flags,
				    RISKIE_HART_FLAG_MTIMECMP);
			}
			ptr = (u_int8_t *)&ht->mregs.mtimecmp;
		}
		break;
	}

	if (ptr != NULL)
		return (ptr);

	/*
	 * If the address requested is not located in main memory we don't
	 * know what to do with it at this point.
	 */
	if (addr < RISKIE_MEM_BASE_ADDR) {
		riskie_hart_fatal(ht,
		    "memory address 0x%" PRIx64 " invalid", addr);
	}

	if (addr >= (RISKIE_MEM_BASE_ADDR + RISKIE_MEM_SIZE)) {
		riskie_hart_fatal(ht,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}

	if (addr + len < addr)
		riskie_hart_fatal(ht, "memory access overflow");

	if ((addr + len) > (RISKIE_MEM_BASE_ADDR + RISKIE_MEM_SIZE)) {
		riskie_hart_fatal(ht,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}

	ptr = &ht->mem[addr - RISKIE_MEM_BASE_ADDR];

	return (ptr);
}
