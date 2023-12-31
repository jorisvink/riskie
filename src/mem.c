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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "riskie.h"

/*
 * Allocate the amount of memory we would like.
 */
void
riskie_mem_init(void)
{
	PRECOND(soc->mem.ptr == NULL);

	if ((soc->mem.ptr = calloc(1, soc->mem.size)) == NULL)
		fatal("calloc: failed to allocate %zu", soc->mem.size);

	printf("setup %lu MB\n", soc->mem.size / 1024 / 1024);
}

/*
 * Prepopulate our memory from a given file.
 * The address given is translated using soc->mem.base.
 */
void
riskie_mem_populate(const char *path, u_int64_t addr)
{
	int			fd;
	struct stat		st;
	ssize_t			ret;
	u_int64_t		offset;

	PRECOND(path != NULL);

	if (addr < soc->mem.base)
		fatal("%s: addr %" PRIx64 "too low", __func__, addr);

	if (addr > (soc->mem.base + soc->mem.size))
		fatal("%s: addr %" PRIx64 " too high", __func__, addr);

	offset = addr - soc->mem.base;

	if ((fd = open(path, O_RDONLY)) == -1)
		fatal("open(%s): %s", path, strerror(errno));

	if (fstat(fd, &st) == -1)
		fatal("fstat(%s): %s", path, strerror(errno));

	if ((size_t)st.st_size > soc->mem.size - offset)
		fatal("file '%s' doesn't fit in memory", path);

	if ((ret = read(fd, soc->mem.ptr + offset, st.st_size)) == -1)
		fatal("read(%s): %s", path, strerror(errno));

	close(fd);

	if (ret != st.st_size)
		fatal("failed to read, only got %zd/%zd", ret, st.st_size);
}

/*
 * Dump memory to disk for inspection later. If we cannot dump, we print
 * out errors, we cannot call fatal (we may be coming from there).
 */
void
riskie_mem_dump(void)
{
	int		fd;
	ssize_t		ret;

	PRECOND(soc != NULL);

	if (soc->mem.ptr == NULL)
		return;

	fd = open("riskie.mem", O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd != -1) {
		ret = write(fd, soc->mem.ptr, soc->mem.size);
		if (ret == -1) {
			printf("error writing memory to disk: %s\n",
			    strerror(errno));
		} else if ((size_t)ret != soc->mem.size) {
			printf("failed to write all memory (%zd/%zu)\n",
			    ret, soc->mem.size);
		}

		(void)close(fd);
	}
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
 *
 * This will return a pointer to where the data can be written, either
 * in main memory, or from a peripheral. NULL may be returned to indicate
 * a memory violation.
 *
 * XXX - The privilege accesses should be checked here later.
 */
u_int8_t *
riskie_mem_validate_access(struct hart *ht, u_int64_t addr, size_t len, int ls)
{
	struct peripheral_io_req	io;
	u_int8_t			*ptr;
	struct peripheral		*perp;

	PRECOND(ht != NULL);
	PRECOND(ls == RISKIE_MEM_STORE || ls == RISKIE_MEM_LOAD);

	ptr = NULL;

	/* Check peripherals first. */
	if ((perp = riskie_peripheral_from_addr(addr)) != NULL) {
		io.ht = ht;
		io.ls = ls;
		io.len = len;
		io.addr = addr;
		io.perp = perp;

		if ((ptr = perp->io(&io)) == NULL) {
			riskie_bit_set(&ht->flags,
			    RISKIE_HART_FLAG_MEM_VIOLATION);
		}

		return (ptr);
	}

	/*
	 * If the address requested is not located in main memory we don't
	 * know what to do with it at this point.
	 */
	if (addr < soc->mem.base) {
		riskie_log(ht, "MEM: 0x%" PRIx64 " out of bounds (lo)\n", addr);
		riskie_bit_set(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		return (NULL);
	}

	if (addr >= (soc->mem.base + soc->mem.size)) {
		riskie_log(ht, "MEM: 0x%" PRIx64 " out of bounds (hi)\n", addr);
		riskie_bit_set(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		return (NULL);
	}

	if (addr + len < addr)
		riskie_hart_fatal(ht, "memory access overflow");

	if ((addr + len) > (soc->mem.base + soc->mem.size)) {
		riskie_log(ht, "MEM: 0x%" PRIx64 " out of range\n", addr);
		riskie_bit_set(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		return (NULL);
	}

	ptr = &soc->mem.ptr[addr - soc->mem.base];

	return (ptr);
}
