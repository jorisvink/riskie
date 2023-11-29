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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static u_int16_t	instr_validate_csr(struct hart *, u_int16_t);
static u_int8_t		instr_validate_register(struct hart *, u_int8_t);

/*
 * Extracts the "shamt" part of the given I-TYPE instruction.
 * For RV64I implementations these are bits 25..20.
 */
u_int8_t
riskie_instr_shamt(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return ((instr >> 20) & 0x3f);
}

/*
 * Extract the "csr" part of the given instruction. (bits 31 .. 20)
 */
u_int16_t
riskie_instr_csr(struct hart *ht, u_int32_t instr)
{
	u_int16_t	csr;

	PRECOND(ht != NULL);

	csr = (instr >> 20) & 0xfff;

	return (instr_validate_csr(ht, csr));
}

/*
 * Extract the "rd" part of the given instruction (bits 11 .. 7).
 * Present in R, I, S, U and J instructions.
 */
u_int8_t
riskie_instr_rd(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (instr_validate_register(ht, (instr >> 7) & 0x1f));
}

/*
 * Extract the "rs1" part of the given instruction (bits 19 .. 15).
 * Present in R, I, S and B instructions.
 */
u_int8_t
riskie_instr_rs1(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (instr_validate_register(ht, (instr >> 15) & 0x1f));
}

/*
 * Extract the "rs2" part of the given instruction (bits 24 .. 20).
 * Present in R, S and B instructions.
 */
u_int8_t
riskie_instr_rs2(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (instr_validate_register(ht, (instr >> 20) & 0x1f));
}

/*
 * Extract the immediate value from a B-type instruction.
 * imm[12|10:5|4:1|11] = inst[31|30:25|11:8|7]
 */
u_int64_t
riskie_instr_imm_b(struct hart *ht, u_int32_t instr)
{
	u_int32_t		imm;

	PRECOND(ht != NULL);

	imm = ((instr >> 31) & 0x01) << 12;
	imm |= ((instr >> 7) & 0x01) << 11;
	imm |= ((instr >> 30) & 0x01) << 10;
	imm |= ((instr >> 29) & 0x01) << 9;
	imm |= ((instr >> 28) & 0x01) << 8;
	imm |= ((instr >> 27) & 0x01) << 7;
	imm |= ((instr >> 26) & 0x01) << 6;
	imm |= ((instr >> 25) & 0x01) << 5;
	imm |= ((instr >> 11) & 0x01) << 4;
	imm |= ((instr >> 10) & 0x01) << 3;
	imm |= ((instr >> 9) & 0x01) << 2;
	imm |= ((instr >> 8) & 0x01) << 1;

	return (riskie_sign_extend(imm, 12));
}

/*
 * Extract the immediate value from a U-type instruction.
 * imm[31:12] = inst[31:12]
 */
u_int64_t
riskie_instr_imm_u(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_sign_extend(instr & 0xfffff000, 31));
}

/*
 * Extract the immediate value from a I-type instruction.
 * imm[11:0] = inst[31:20]
 */
u_int64_t
riskie_instr_imm_i(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_sign_extend(instr >> 20, 11));
}

/*
 * Extract the immediate value from a J-type instruction.
 * imm[20|10:1|11|19:12] = inst[31|30:21|20|19:12]
 */
u_int64_t
riskie_instr_imm_j(struct hart *ht, u_int32_t instr)
{
	size_t			idx;
	u_int32_t		imm;

	PRECOND(ht != NULL);

	imm = ((instr >> 31) & 0x01) << 20;

	for (idx = 19; idx >= 12; idx--)
		imm |= ((instr >> idx) & 0x01) << idx;

	imm |= ((instr >> 20) & 0x01) << 11;

	for (idx = 10; idx >= 1; idx--)
		imm |= ((instr >> (idx + 20)) & 0x01) << idx;

	return (riskie_sign_extend(imm, 20));
}

/*
 * Extract the immediate value from an S-type instruction.
 * imm[11:5] = inst[31:25], imm[4:0] = inst[11:7]
 */
u_int64_t
riskie_instr_imm_s(struct hart *ht, u_int32_t instr)
{
	u_int32_t		imm;

	PRECOND(ht != NULL);

	imm = ((instr & 0xfe000000) >> 20) | ((instr >> 7) & 0x1f);

	return (riskie_sign_extend(imm, 11));
}

/*
 * Validate the given CSR to be a valid one.
 */
static u_int16_t
instr_validate_csr(struct hart *ht, u_int16_t csr)
{
	if (csr >= RISCV_CSR_COUNT)
		riskie_hart_fatal(ht, "csr out of bounds (%u)", csr);

	return (csr);
}

/*
 * Validate the given register to be a valid one.
 */
static u_int8_t
instr_validate_register(struct hart *ht, u_int8_t reg)
{
	PRECOND(ht != NULL);

	if (reg >= RISCV_REGISTER_COUNT)
		riskie_hart_fatal(ht, "reg out of bounds (%u)", reg);

	return (reg);
}


