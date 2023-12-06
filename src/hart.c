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

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "riskie.h"

#define MISA(c)		(c - 'A')

static int	hart_csr_known(u_int16_t);
static void	hart_timer_next(struct hart *);
static void	hart_validate_pc(struct hart *);
static void	hart_environment_call(struct hart *);
static void	hart_trap_machine(struct hart *, u_int8_t);

static void	hart_interrupt_execute(struct hart *);
static void	hart_interrupt_set_pending(struct hart *, u_int8_t);
static void	hart_interrupt_clear_pending(struct hart *, u_int8_t);

static void	hart_opcode_lui(struct hart *, u_int32_t);
static void	hart_opcode_jal(struct hart *, u_int32_t);
static void	hart_opcode_jalr(struct hart *, u_int32_t);
static void	hart_opcode_load(struct hart *, u_int32_t);
static void	hart_opcode_mret(struct hart *, u_int32_t);
static void	hart_opcode_store(struct hart *, u_int32_t);
static void	hart_opcode_auipc(struct hart *, u_int32_t);
static void	hart_opcode_system(struct hart *, u_int32_t);
static void	hart_opcode_atomic(struct hart *, u_int32_t);
static void	hart_opcode_b_type(struct hart *, u_int32_t);
static void	hart_opcode_r_type_32(struct hart *, u_int32_t);
static void	hart_opcode_r_type_64(struct hart *, u_int32_t);
static void	hart_opcode_i_type_32(struct hart *, u_int32_t);
static void	hart_opcode_i_type_64(struct hart *, u_int32_t);

static void	hart_next_instruction(struct hart *);
static int	hart_csr_access(struct hart *, u_int16_t, u_int64_t, int);

/*
 * Prepare the hart by setting up the initial execution environment.
 */
void
riskie_hart_init(struct hart *ht, u_int64_t pc, u_int16_t hid)
{
	PRECOND(ht != NULL);

	memset(ht, 0, sizeof(*ht));

	ht->regs.pc = pc;
	ht->mode = RISKIE_HART_MACHINE_MODE;

	ht->csr[RISCV_CSR_MRO_HART_ID] = hid;
	ht->csr[RISCV_CSR_MRO_VENDOR_ID] = 0x20231021;

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], 63);

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], MISA('A'));
	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], MISA('I'));
	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], MISA('M'));
	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], MISA('U'));
	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MISA], MISA('S'));

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], RISCV_STATUS_BIT_MPIE);
}

/*
 * Cleanup the hart.
 */
void
riskie_hart_cleanup(struct hart *ht)
{
	PRECOND(ht != NULL);

	free(ht->mem);
}

/*
 * Execute one "tick" for the hart.
 */
void
riskie_hart_tick(struct hart *ht)
{
	hart_timer_next(ht);
	hart_interrupt_execute(ht);

	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_WFI) == 0)
		hart_next_instruction(ht);

	ht->csr[RISCV_CSR_URO_CYCLE]++;
}

/*
 * A non-recoverable error occurred in a hart, riskie dies.
 */
void
riskie_hart_fatal(struct hart *ht, const char *fmt, ...)
{
	va_list		args;

	PRECOND(ht != NULL);

	fprintf(stderr, "hart fatal: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	riskie_hart_dump(ht);
	riskie_hart_cleanup(ht);

	fatal("hart gave up");
}

/*
 * Dump the given hart its registers.
 */
void
riskie_hart_dump(struct hart *ht)
{
	int		idx;

	PRECOND(ht != NULL);

	fprintf(stderr, "id=%" PRIu64 "\n", ht->csr[RISCV_CSR_MRO_HART_ID]);
	fprintf(stderr, "pc=0x%" PRIx64 "\n", ht->regs.pc - sizeof(u_int32_t));

	for (idx = 0; idx < RISCV_REGISTER_COUNT; idx++)
		fprintf(stderr, "x%d=0x%" PRIx64 "\n", idx, ht->regs.x[idx]);
}

/*
 * Validate the current value in the PC register, make sure it can
 * be executed in the correct privilege mode.
 */
static void
hart_validate_pc(struct hart *ht)
{
	PRECOND(ht != NULL);

	if ((ht->regs.pc % 4) != 0)
		riskie_hart_fatal(ht, "unaligned instruction access");

	if (ht->regs.pc + sizeof(u_int32_t) < ht->regs.pc)
		riskie_hart_fatal(ht, "pc wrap around");

	if (ht->regs.pc < soc->mem.base ||
	    ht->regs.pc > soc->mem.base + soc->mem.size)
		riskie_hart_fatal(ht, "pc out of bounds");

	/* XXX - todo, check R and X bit. */
	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		break;
	}
}

/*
 * Check permissions for the given CSR against our current privilege
 * mode and wether or not we are trying to read / write.
 */
static int
hart_csr_access(struct hart *ht, u_int16_t csr, u_int64_t bits, int ls)
{
	int		fail;
	u_int8_t	perm, privilege;

	PRECOND(ht != NULL);

	/* We only allow access to CSRs we know. */
	if (hart_csr_known(csr) == -1) {
		riskie_log(ht, "CSR: invalid CSR 0x%04x\n", csr);
		hart_trap_machine(ht, 1);
		return (-1);
	}

	perm = (csr >> 10) & 0x03;
	privilege = (csr >> 8) & 0x03;

	if (ht->mode < privilege) {
		riskie_log(ht, "CSR: unprivileged access to 0x%04x\n", csr);
		hart_trap_machine(ht, 1);
		return (-1);
	}

	switch (ls) {
	case RISKIE_MEM_STORE:
		if (perm == 3) {
			riskie_log(ht, "CSR: write to ro csr 0x%04x\n", csr);
			hart_trap_machine(ht, 1);
			return (-1);
		}
		break;
	case RISKIE_MEM_LOAD:
		break;
	default:
		riskie_hart_fatal(ht, "unknown ls %d", ls);
	}

	if (bits == 0)
		return (0);

	fail = 0;

	/*
	 * Different CSRs have protected bits that cannot be set
	 * by software.
	 */
	switch (csr) {
	case RISCV_CSR_MRW_MISA:
		fail++;
		break;
	case RISCV_CSR_MRW_MIP:
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MEI))
			fail++;
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MTI))
			fail++;
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MSI))
			fail++;
		break;
	}

	if (fail) {
		riskie_log(ht, "CSR: write to ro-bit csr 0x%04x\n", csr);
		hart_trap_machine(ht, 1);
		return (-1);
	}

	return (0);
}

/*
 * Execute an environment call into M-mode, this happens immediately.
 */
static void
hart_environment_call(struct hart *ht)
{
	u_int8_t	exception;

	PRECOND(ht != NULL);

	/* Global M-mode interrupts enabled. */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_STATUS_BIT_MIE) == 0)
		return;

	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		exception = 11;
		break;
	default:
		riskie_hart_fatal(ht, "invalid mode %u", ht->mode);
	}

	hart_trap_machine(ht, exception);
}

/*
 * Get current nanoseconds since boot and store it into the mtime memory
 * register. Check mtimecmp and set MTI to pending if mtime >= mtimecmp.
 */
static void
hart_timer_next(struct hart *ht)
{
	struct timespec		ts;

	PRECOND(ht != NULL);

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	ht->csr[RISCV_CSR_URO_TIME] = ts.tv_sec;
	ht->mregs.mtime = ts.tv_nsec + (ts.tv_sec * 1000000000);

	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MTIMECMP)) {
		if (ht->mregs.mtimecmp > ht->mregs.mtime)
			hart_interrupt_clear_pending(ht, RISCV_TRAP_BIT_MTI);
		else
			hart_interrupt_set_pending(ht, RISCV_TRAP_BIT_MTI);
	}
}

/*
 * Clear the given interrupt bit from the mpi register.
 */
static void
hart_interrupt_clear_pending(struct hart *ht, u_int8_t irq)
{
	PRECOND(ht != NULL);
	PRECOND(irq <= 15);

	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MIP], irq);
}

/*
 * Mark the given interrupt bit as pending in the mpi register.
 */
static void
hart_interrupt_set_pending(struct hart *ht, u_int8_t irq)
{
	PRECOND(ht != NULL);
	PRECOND(irq <= 15);

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MIP], irq);
}

/*
 * Execute pending interrupts in priority order:
 *	-> MEI, MSI, MTI, SEI, SSI, STI.
 *
 * XXX - rework this so that we call into the correct mode interrupt
 * execution. Where in supervisor, we always execute M-mode.
 */
static void
hart_interrupt_execute(struct hart *ht)
{
	PRECOND(ht != NULL);

	/* Are interrupts enabled. */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_STATUS_BIT_MIE) == 0)
		return;

	/* MIE */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MEI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MEI)) {
		hart_trap_machine(ht, RISCV_TRAP_BIT_MEI);
		return;
	}

	/* MSI */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MSI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MSI)) {
		hart_trap_machine(ht, RISCV_TRAP_BIT_MSI);
		return;
	}

	/* MTI */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MTI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MTI)) {
		hart_trap_machine(ht, RISCV_TRAP_BIT_MTI);
		return;
	}
}

/*
 * Let a trap into M-mode occur on the given hart.
 *
 * A few things happen here:
 *	- save the current privilege level in MPP.
 *	- save the current MIE bit in MPIE.
 *	- set MIE to 0 (disabling interrupts).
 *	- save the current PC into the mepc CSR.
 *	- jump to mtvec base address.
 *
 * If the trap was set to be delegated to S-mode, we do that here.
 */
static void
hart_trap_machine(struct hart *ht, u_int8_t trap)
{
	int		delegate;
	u_int8_t	target, iebit, piebit;
	u_int16_t	status, cause, val, epc, vec;

	PRECOND(ht != NULL);
	PRECOND(trap < RISCV_TRAP_MAX);

	riskie_log(ht, "MTRAP, mode=%u, trap=%u, mpi=0x%" PRIx64
	    ", mie=0x%" PRIx64 "\n", ht->mode, trap,
	    ht->csr[RISCV_CSR_MRW_MIP], ht->csr[RISCV_CSR_MRW_MIE]);

	/* The default trap target is machine mode. */
	delegate = 0;

	epc = RISCV_CSR_MRW_MEPC;
	vec = RISCV_CSR_MRW_MTVEC;
	val = RISCV_CSR_MRW_MTVAL;
	cause = RISCV_CSR_MRW_MCAUSE;
	iebit = RISCV_STATUS_BIT_MIE;
	status = RISCV_CSR_MRW_MSTATUS;
	piebit = RISCV_STATUS_BIT_MPIE;
	target = RISKIE_HART_MACHINE_MODE;

	/* Clear the WFI flag if this was an interrupt. */
	if (trap < RISCV_TRAP_INTERRUPT_MAX)
		riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_WFI);

	/* Check if we delegate into S-mode instead. */
	if (trap < RISCV_TRAP_INTERRUPT_MAX) {
		if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MEDELEG], trap))
			delegate = 1;
	} else {
		if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MEDELEG], trap))
			delegate = 1;
	}

	/* Set MPP, or SPP. */
	if (delegate) {
		epc = RISCV_CSR_SRW_SEPC;
		vec = RISCV_CSR_SRW_STVEC;
		val = RISCV_CSR_SRW_STVAL;
		iebit = RISCV_STATUS_BIT_SIE;
		piebit = RISCV_STATUS_BIT_SPIE;
		status = RISCV_CSR_SRW_SSTATUS;
		target = RISKIE_HART_SUPERVISOR_MODE;

		switch (ht->mode) {
		case RISKIE_HART_USER_MODE:
			riskie_bit_clear(&ht->csr[status], 8);
			riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 8);
			break;
		case RISKIE_HART_MACHINE_MODE:
		case RISKIE_HART_SUPERVISOR_MODE:
			riskie_bit_set(&ht->csr[status], 8);
			riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], 8);
			break;
		default:
			riskie_hart_fatal(ht, "invalid mode %u", ht->mode);
		}

		riskie_bit_clone(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_STATUS_BIT_SPIE, RISCV_STATUS_BIT_SIE);
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_STATUS_BIT_SIE);
	} else {
		switch (ht->mode) {
		case RISKIE_HART_MACHINE_MODE:
			riskie_bit_set(&ht->csr[status], 11);
			riskie_bit_set(&ht->csr[status], 12);
			break;
		case RISKIE_HART_SUPERVISOR_MODE:
			riskie_bit_set(&ht->csr[status], 11);
			riskie_bit_clear(&ht->csr[status], 12);
			break;
		case RISKIE_HART_USER_MODE:
			riskie_bit_clear(&ht->csr[status], 11);
			riskie_bit_clear(&ht->csr[status], 12);
			break;
		default:
			riskie_hart_fatal(ht, "invalid mode %u", ht->mode);
		}
	}

	/* Swap mode and clear clone xIE into xPIE, and clear xIE. */
	ht->mode = target;

	riskie_bit_clone(&ht->csr[status], piebit, iebit);
	riskie_bit_clear(&ht->csr[status], iebit);

	/* Finally call trap handler. */
	ht->csr[val] = 0;
	ht->csr[cause] = trap;
	ht->csr[epc] = ht->regs.pc;

	if (trap < RISCV_TRAP_INTERRUPT_MAX)
		riskie_bit_set(&ht->csr[cause], 63);

	ht->regs.pc = ht->csr[vec];
}

/*
 * Fetch the next instruction, decode it and execute it.
 */
static void
hart_next_instruction(struct hart *ht)
{
	u_int32_t	instr;
	u_int8_t	opcode;

	PRECOND(ht != NULL);

	hart_validate_pc(ht);
	instr = riskie_mem_fetch32(ht, ht->regs.pc);
	ht->regs.pc += sizeof(instr);

	ht->regs.x[0] = 0;
	opcode = instr & 0x7f;

	switch (opcode) {
	case RISCV_RV32I_OPCODE_LOAD:
		hart_opcode_load(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_STORE:
		hart_opcode_store(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_SYSTEM:
		hart_opcode_system(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_B_TYPE:
		hart_opcode_b_type(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_I_TYPE:
		hart_opcode_i_type_32(ht, instr);
		break;
	case RISCV_RV64I_OPCODE_I_TYPE:
		hart_opcode_i_type_64(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_R_TYPE:
		hart_opcode_r_type_32(ht, instr);
		break;
	case RISCV_RV64I_OPCODE_R_TYPE:
		hart_opcode_r_type_64(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_AUIPC:
		hart_opcode_auipc(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_LUI:
		hart_opcode_lui(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JAL:
		hart_opcode_jal(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JALR:
		hart_opcode_jalr(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_FENCE:
		break;
	case RISCV_EXT_OPCODE_ATOMIC:
		hart_opcode_atomic(ht, instr);
		break;
	default:
		riskie_hart_fatal(ht, "illegal instruction 0x%08x", instr);
	}
}

/*
 * A load instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
hart_opcode_load(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd, rs1;
	u_int32_t	funct3, v32;
	u_int64_t	off, addr, v64;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	off = riskie_instr_imm_i(ht, instr);

	addr = ht->regs.x[rs1] + (int64_t)off;

	riskie_log(ht, "LOAD, funct3=0x%02x, rd=%u, rs1=%u, addr=0x%"
	    PRIx64 "\n", funct3, rd, rs1, addr);

	riskie_log(ht, "    <- reg.%u = %" PRIx64 "\n", rs1, ht->regs.x[rs1]);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_LB:
		v32 = riskie_mem_fetch(ht, addr, 8);
		v64 = riskie_sign_extend(v32, 7);
		break;
	case RISCV_RV32I_INSTRUCTION_LH:
		v32 = riskie_mem_fetch(ht, addr, 16);
		v64 = riskie_sign_extend(v32, 15);
		break;
	case RISCV_RV32I_INSTRUCTION_LW:
		v32 = riskie_mem_fetch(ht, addr, 32);
		v64 = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV32I_INSTRUCTION_LBU:
		v64 = riskie_mem_fetch(ht, addr, 8);
		break;
	case RISCV_RV32I_INSTRUCTION_LHU:
		v64 = riskie_mem_fetch(ht, addr, 16);
		break;
	case RISCV_RV32I_INSTRUCTION_LWU:
		v64 = riskie_mem_fetch(ht, addr, 32);
		break;
	case RISCV_RV64I_INSTRUCTION_LD:
		v64 = riskie_mem_fetch(ht, addr, 64);
		break;
	default:
		riskie_hart_fatal(ht, "illegal load 0x%08x", instr);
	}

	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION) == 0) {
		ht->regs.x[rd] = v64;
		riskie_log(ht, "    -> reg.%u = %" PRIx64 "\n",
		    rd, ht->regs.x[rd]);
	} else {
		riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		hart_trap_machine(ht, 5);
	}
}

/*
 * A store instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
hart_opcode_store(struct hart *ht, u_int32_t instr)
{
	u_int32_t	funct3;
	u_int8_t	rs1, rs2;
	u_int64_t	off, addr;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;

	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);
	off = riskie_instr_imm_s(ht, instr);

	addr = ht->regs.x[rs1] + (int64_t)off;

	riskie_log(ht, "STORE, funct3=0x%02x, rs1=%u, rs2=%u, "
	    "addr=0x%" PRIx64 "\n", funct3, rs1, rs2, addr);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_SB:
		riskie_mem_store(ht, addr, ht->regs.x[rs2], 8);
		break;
	case RISCV_RV32I_INSTRUCTION_SH:
		riskie_mem_store(ht, addr, ht->regs.x[rs2], 16);
		break;
	case RISCV_RV32I_INSTRUCTION_SW:
		riskie_mem_store(ht, addr, ht->regs.x[rs2], 32);
		break;
	case RISCV_RV64I_INSTRUCTION_SD:
		riskie_mem_store(ht, addr, ht->regs.x[rs2], 64);
		break;
	default:
		riskie_hart_fatal(ht, "illegal store 0x%08x", instr);
	}

	/* XXX trigger some sort of exception. */
	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION)) {
		riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		hart_trap_machine(ht, 5);
	}
}

/*
 * a SYSTEM opcode was found, we look further what it was and perform
 * the correct thing to do.
 *
 * This is everything from writing/reading CSRs, to trap related things
 * such as ecall/mret/sret.
 */
static void
hart_opcode_system(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;
	u_int16_t	csr;
	u_int64_t	rs1, rs2;
	u_int32_t	funct3, funct7;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);
	csr = riskie_instr_csr(ht, instr);

	riskie_log(ht, "SYSTEM, funct3=0x%02x, funct7=0x%02x rd=%u, "
	    "rs1=%" PRIu64 ", rs2=%" PRIu64 " csr=0x%02x\n",
	    funct3, funct7, rd, rs1, rs2, csr);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRC:
		rs1 = ht->regs.x[rs1];
		if (hart_csr_access(ht, csr, rs1, RISKIE_MEM_LOAD) == -1)
			return;
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		rs1 = rs1 & 0xf;
		if (hart_csr_access(ht, csr, rs1, RISKIE_MEM_LOAD) == -1)
			return;

		if (funct3 == RISCV_RV32I_INSTRUCTION_CSRRWI || rs1 != 0) {
			if (hart_csr_access(ht,
			    csr, rs1, RISKIE_MEM_STORE) == -1)
				return;
		}
		break;
	}

	switch (funct3) {
	case RISCV_PRIV_FUNCTION_TRAP:
		switch (rs2) {
		case RISCV_PRIV_FUNCTION_TRAP_RETURN:
			switch (funct7) {
			case RISCV_PRIV_INSTRUCTION_SRET:
				break;
			case RISCV_PRIV_INSTRUCTION_MRET:
				hart_opcode_mret(ht, instr);
				break;
			default:
				riskie_hart_fatal(ht,
				    "illegal trap instruction 0x%08x", instr);
			}
			break;
		case RISCV_PRIV_FUNCTION_INTERRUPT_MGMT:
			switch (funct7) {
			case RISCV_PRIV_INSTRUCTION_WFI:
				riskie_bit_set(&ht->flags,
				    RISKIE_HART_FLAG_WFI);
				break;
			default:
				riskie_hart_fatal(ht,
				    "illegal interrupt mgmt 0x%08x", instr);
			}
			break;
		case RISCV_PRIV_INSTRUCTION_ECALL:
			hart_environment_call(ht);
			break;
		case RISCV_PRIV_INSTRUCTION_EBREAK:
			riskie_hart_dump(ht);
			break;
		default:
			riskie_hart_fatal(ht,
			    "illegal trap instruction 0x%08x", instr);
		}
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
		/*
		 * This counts as atomic unless we start doing
		 * multiprocess approaches for the future harts.
		 */
		if (hart_csr_access(ht, csr, rs1, RISKIE_MEM_STORE) == -1)
			break;
		if (rd != 0)
			ht->regs.x[rd] = ht->csr[csr];
		ht->csr[csr] = rs1;
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
		ht->regs.x[rd] = ht->csr[csr];
		if (rs1 != 0)
			ht->csr[csr] |= rs1;
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRC:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		ht->regs.x[rd] = ht->csr[csr];
		if (rs1 != 0)
			ht->csr[csr] &= ~rs1;
		break;
	default:
		riskie_hart_fatal(ht, "illegal system 0x%08x", instr);
	}
}

/*
 * Control transfer instructions, conditional branches.
 */
static void
hart_opcode_b_type(struct hart *ht, u_int32_t instr)
{
	u_int64_t	imm;
	int		branch;
	u_int32_t	funct3;
	u_int8_t	rs1, rs2;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;

	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);
	imm = riskie_instr_imm_b(ht, instr);

	riskie_log(ht, "B-TYPE, funct3=0x%02x, rs1=%u, rs2=%u, "
	    "imm=0x%" PRIx64 "\n", funct3, rs1, rs2, imm);

	branch = 0;

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_BEQ:
		branch = ht->regs.x[rs1] == ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BNE:
		branch = ht->regs.x[rs1] != ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BLT:
		branch = (int64_t)ht->regs.x[rs1] < (int64_t)ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BGE:
		branch = (int64_t)ht->regs.x[rs1] >= (int64_t)ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BLTU:
		branch = ht->regs.x[rs1] < ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BGEU:
		branch = ht->regs.x[rs1] >= ht->regs.x[rs2];
		break;
	default:
		riskie_hart_fatal(ht, "illegal b-type 0x%08x", instr);
	}

	if (branch)
		ht->regs.pc = (ht->regs.pc - sizeof(instr)) + (int64_t)imm;
}

/*
 * The register to immediate instructions as part of the
 * "Integer Computational Instructions" instruction set.
 *
 * This function handles decoding of instructions that are part of RV32I.
 *
 * Note that while these are part of the RV32I instruction set, they
 * operate on XLEN bits, and thus 64-bit.
 */
static void
hart_opcode_i_type_32(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd, rs1;
	u_int64_t	imm, sbit;
	u_int32_t	funct3, funct7, shamt;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;

	/* funct7 starts at bit 26 when under rv64. */
	funct7 = (instr >> 26) & 0x1f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);

	/*
	 * The imm and shamt parts overlap, but certain instructions
	 * use imm, others shamt. Never combined.
	 */
	imm = riskie_instr_imm_i(ht, instr);
	shamt = riskie_instr_shamt(ht, instr);

	riskie_log(ht, "I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, "
	    "rd=%u, rs1=%u, imm=%" PRId64 ", shamt=0x%08x\n",
	    funct3, funct7, rd, rs1, (int64_t)imm, shamt);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_ADDI:
		ht->regs.x[rd] = ht->regs.x[rs1] + (int64_t)imm;
		break;
	case RISCV_RV32I_INSTRUCTION_XORI:
		ht->regs.x[rd] = ht->regs.x[rs1] ^ imm;
		break;
	case RISCV_RV32I_INSTRUCTION_ANDI:
		ht->regs.x[rd] = ht->regs.x[rs1] & imm;
		break;
	case RISCV_RV32I_INSTRUCTION_ORI:
		ht->regs.x[rd] = ht->regs.x[rs1] | imm;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTI:
		if ((int64_t)ht->regs.x[rs1] < (int64_t)imm)
			ht->regs.x[rd] = 1;
		else
			ht->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTIU:
		if (ht->regs.x[rs1] < imm)
			ht->regs.x[rd] = 1;
		else
			ht->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLLI:
		ht->regs.x[rd] = ht->regs.x[rs1] << shamt;
		break;
	case RISCV_RV32I_FUNCTION_SRI:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_SRLI:
			ht->regs.x[rd] = ht->regs.x[rs1] >> shamt;
			break;
		case RISCV_RV32I_INSTRUCTION_SRAI:
			sbit = ht->regs.x[rs1] >> 63;
			ht->regs.x[rd] = ht->regs.x[rs1] >> shamt;
			ht->regs.x[rd] |= sbit << 63;
			break;
		default:
			riskie_hart_fatal(ht, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_hart_fatal(ht, "illegal i-type 0x%08x", instr);
	}

	riskie_log(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * The register to immediate instructions as part of the
 * "Integer Computational Instructions" instruction set.
 *
 * This function handles decoding of instructions that are part of RV64I.
 *
 * Note that while these are part of the RV64I instruction set, these
 * instructions implement the *.W variants and thus operate on 32-bit.
 */
static void
hart_opcode_i_type_64(struct hart *ht, u_int32_t instr)
{
	u_int64_t	imm;
	u_int8_t	rd, rs1;
	u_int32_t	funct3, funct7, shamt, v32, sbit;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	imm = riskie_instr_imm_i(ht, instr);
	shamt = riskie_instr_shamt(ht, instr);

	riskie_log(ht, "I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, imm=%" PRId64 "\n", funct3, funct7, rd, rs1, (int64_t)imm);

	switch (funct3) {
	case RISCV_RV64I_INSTRUCTION_ADDIW:
		v32 = (u_int32_t)ht->regs.x[rs1] + (int32_t)imm;
		ht->regs.x[rd] = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV64I_INSTRUCTION_SLLIW:
		ht->regs.x[rd] = (u_int32_t)ht->regs.x[rs1] << shamt;
		break;
	case RISCV_RV64I_FUNCTION_SRIW:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_SRLIW:
			v32 = ht->regs.x[rs1];
			ht->regs.x[rd] = v32 >> imm;
			break;
		case RISCV_RV64I_INSTRUCTION_SRAIW:
			v32 = ht->regs.x[rs1];
			sbit = v32 >> 31;
			ht->regs.x[rd] = v32 >> imm;
			ht->regs.x[rd] |= sbit << 31;
			break;
		default:
			riskie_hart_fatal(ht, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_hart_fatal(ht, "illegal i-type 0x%08x", instr);
	}

	riskie_log(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * The register to register instructions as part of the
 * "Integer Computational Instructions" and "Standard Extension for integer
 * multiplication and division" instruction sets.
 *
 * Note that while these are part of the RV32I/RV32M instruction set,
 * they operate on XLEN bits, and thus 64-bit.
 */
static void
hart_opcode_r_type_32(struct hart *ht, u_int32_t instr)
{
	u_int64_t	sbit;
	u_int8_t	rd, rs1, rs2;
	u_int32_t	funct3, funct7;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);

	riskie_log(ht, "I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_OR:
		if (funct7 == RISCV_RV32M_INSTRUCTION_REM) {
			ht->regs.x[rd] = (int64_t)ht->regs.x[rs1] %
			    (int64_t)ht->regs.x[rs2];
		} else {
			ht->regs.x[rd] = ht->regs.x[rs1] | ht->regs.x[rs2];
		}
		break;
	case RISCV_RV32I_INSTRUCTION_XOR:
		if (funct7 == RISCV_RV32M_INSTRUCTION_DIV) {
			ht->regs.x[rd] = (int64_t)ht->regs.x[rs1] /
			    (int64_t)ht->regs.x[rs2];
		} else {
			ht->regs.x[rd] = ht->regs.x[rs1] ^ ht->regs.x[rs2];
		}
		break;
	case RISCV_RV32I_INSTRUCTION_AND:
		if (funct7 == RISCV_RV32M_INSTRUCTION_REMU) {
			ht->regs.x[rd] = ht->regs.x[rs1] % ht->regs.x[rs2];
		} else {
			ht->regs.x[rd] = ht->regs.x[rs1] & ht->regs.x[rs2];
		}
		break;
	case RISCV_RV32I_INSTRUCTION_SLL:
		ht->regs.x[rd] = ht->regs.x[rs1] << (ht->regs.x[rs2] & 0x3f);
		break;
	case RISCV_RV32I_INSTRUCTION_SLT:
		if ((int64_t)ht->regs.x[rs1] < (int64_t)ht->regs.x[rs2])
			ht->regs.x[rd] = 1;
		else
			ht->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTU:
		if (ht->regs.x[rs1] < ht->regs.x[rs2])
			ht->regs.x[rd] = 1;
		else
			ht->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_FUNCTION_ADD_SUB:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_ADD:
			ht->regs.x[rd] = ht->regs.x[rs1] + ht->regs.x[rs2];
			break;
		case RISCV_RV32I_INSTRUCTION_SUB:
			ht->regs.x[rd] = ht->regs.x[rs1] - ht->regs.x[rs2];
			break;
		case RISCV_RV32M_INSTRUCTION_MUL:
			ht->regs.x[rd] = ht->regs.x[rs1] * ht->regs.x[rs2];
			break;
		default:
			riskie_hart_fatal(ht, "illegal addsub 0x%08x", instr);
		}
		break;
	case RISCV_RV32I_FUNCTION_SR:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_SRL:
			ht->regs.x[rd] = ht->regs.x[rs1] >>
			    (ht->regs.x[rs2] & 0x3f);
			break;
		case RISCV_RV32I_INSTRUCTION_SRA:
			sbit = ht->regs.x[rs1] >> 63;
			ht->regs.x[rd] = ht->regs.x[rs1] >>
			    (ht->regs.x[rs2] & 0x3f);
			ht->regs.x[rd] |= sbit << 63;
			break;
		case RISCV_RV32M_INSTRUCTION_DIVU:
			ht->regs.x[rd] = ht->regs.x[rs1] / ht->regs.x[rs2];
			break;
		default:
			riskie_hart_fatal(ht, "illegal sr 0x%08x", instr);
		}
		break;
	default:
		riskie_hart_fatal(ht, "illegal r-type 0x%08x", instr);
	}

	riskie_log(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * The register to register instructions as part of the
 * "Integer Computational Instructions" and "Standard extension for integer
 * multiplication and division" instruction sets.
 *
 * This function handles decoding of instructions that are part of RV64I/RV64M.
 *
 * Note that while these are part of the RV64I/RV64M instruction set, these
 * instructions implement the *.W variants and thus operate on 32-bit.
 */
static void
hart_opcode_r_type_64(struct hart *ht, u_int32_t instr)
{
	u_int64_t	sbit;
	u_int8_t	rd, rs1, rs2;
	u_int32_t	funct3, funct7, v32;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);

	riskie_log(ht, "I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV64I_INSTRUCTION_SLLW:
		ht->regs.x[rd] = (u_int32_t)(ht->regs.x[rs1] <<
		    (ht->regs.x[rs2] & 0x1f));
		break;
	case RISCV_RV64I_FUNCTION_ADD_SUB:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_ADDW:
			v32 = ht->regs.x[rs1] + ht->regs.x[rs2];
			ht->regs.x[rd] = riskie_sign_extend(v32, 31);
			break;
		case RISCV_RV64I_INSTRUCTION_SUBW:
			ht->regs.x[rd] = (int32_t)ht->regs.x[rs1] -
			    (int32_t)ht->regs.x[rs2];
			break;
		case RISCV_RV64M_INSTRUCTION_MULW:
			v32 = (int32_t)ht->regs.x[rs1] *
			    (int32_t)ht->regs.x[rs2];
			ht->regs.x[rd] = riskie_sign_extend(v32, 31);
			break;
		default:
			riskie_hart_fatal(ht, "illegal addsub 0x%08x", instr);
		}
		break;
	case RISCV_RV64M_INSTRUCTION_DIVW:
		v32 = (int32_t)ht->regs.x[rs1] / (int32_t)ht->regs.x[rs2];
		ht->regs.x[rd] = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV64M_INSTRUCTION_REMW:
		v32 = (int32_t)ht->regs.x[rs1] % (int32_t)ht->regs.x[rs2];
		ht->regs.x[rd] = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV64M_INSTRUCTION_REMUW:
		ht->regs.x[rd] = (u_int32_t)ht->regs.x[rs1] %
		    (u_int32_t)ht->regs.x[rs2];
		break;
	case RISCV_RV64I_FUNCTION_SRW:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_SRLW:
			v32 = ht->regs.x[rs1];
			ht->regs.x[rd] = v32 >> (ht->regs.x[rs2] & 0x1f);
			break;
		case RISCV_RV64I_INSTRUCTION_SRAW:
			v32 = ht->regs.x[rs1];
			sbit = v32 >> 31;
			ht->regs.x[rd] = v32 >> (ht->regs.x[rs2] & 0x1f);
			ht->regs.x[rd] |= sbit << 31;
			break;
		case RISCV_RV64M_INSTRUCTION_DIVUW:
			ht->regs.x[rd] = (u_int32_t)ht->regs.x[rs1] /
			    (u_int32_t)ht->regs.x[rs2];
			break;
		default:
			riskie_hart_fatal(ht, "illegal srw 0x%08x", instr);
		}
		break;
	default:
		riskie_hart_fatal(ht, "illegal r-type 0x%08x", instr);
	}

	riskie_log(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * An atomic opcode was found, decode it and perform the correct operation.
 * In funct3 we find if we're operating on a 32-bit word, or 64-bit double.
 * We emulate RV64 so the 32-bit words are sign-extended into our 64-bit
 * registers after we're done operating on them.
 *
 * The acquire / release semantics are ignored for now.
 */
static void
hart_opcode_atomic(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rs1, rs2, rd;
	u_int32_t	funct3, funct7;
	u_int64_t	v64, tmp, addr, rs2val;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 27) & 0x1f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	rs2 = riskie_instr_rs2(ht, instr);

	switch (funct3) {
	case RISCV_RV32A_FUNCTION_ATOMIC:
	case RISCV_RV64A_FUNCTION_ATOMIC:
		break;
	default:
		riskie_hart_fatal(ht, "unknown atomic 0x%08x", instr);
	}

	addr = ht->regs.x[rs1];
	rs2val = ht->regs.x[rs2];

	riskie_log(ht, "ATOMIC, funct3=0x%02x, funct7=0x%02x, rs1=%u, "
	    "rs2=%u, rd=%u, addr=0x%" PRIx64 "\n",
	    funct3, funct7, rs1, rs2, rd, addr);

	v64 = riskie_mem_fetch64(ht, ht->regs.x[rs1]);
	if (funct3 == RISCV_RV32A_FUNCTION_ATOMIC)
		v64 = riskie_sign_extend(v64 & 0xffffffff, 31);

	ht->regs.x[rd] = v64;

	/*
	 * LR.W/D handled outside of the switch due to the fact it won't
	 * actually end up doing a store.
	 */
	if (funct7 == RISCV_EXT_ATOMIC_INSTRUCTION_LR) {
		ht->lr.valid = 1;
		ht->lr.addr = addr;
		ht->lr.value = v64;
		return;
	}

	switch (funct7) {
	case RISCV_EXT_ATOMIC_INSTRUCTION_OR:
		v64 = v64 | rs2val;
		break;
	case RISCV_EXT_ATOMIC_INSTRUCTION_ADD:
		v64 = v64 + rs2val;
		break;
	case RISCV_EXT_ATOMIC_INSTRUCTION_XOR:
		v64 = v64 ^ rs2val;
		break;
	case RISCV_EXT_ATOMIC_INSTRUCTION_AND:
		v64 = v64 & rs2val;
		break;
	case RISCV_EXT_ATOMIC_INSTRUCTION_SWAP:
		tmp = rs2val;
		ht->regs.x[rs2] = v64;
		v64 = tmp;
		break;
	case RISCV_EXT_ATOMIC_INSTRUCTION_SC:
		if (ht->lr.valid == 0 ||
		    ht->lr.addr != addr || ht->lr.value != v64) {
			ht->regs.x[rd] = 1;
		} else {
			v64 = rs2val;
			addr = ht->lr.addr;
			ht->regs.x[rd] = 0;
		}

		ht->lr.addr = 0;
		ht->lr.value = 0;
		ht->lr.valid = 0;

		if (ht->regs.x[rd] == 1)
			return;
		break;
	default:
		riskie_hart_fatal(ht, "illegal atomic 0x%08x", instr);
	}

	if (funct3 == RISCV_RV32A_FUNCTION_ATOMIC)
		v64 = riskie_sign_extend(v64 & 0xffffffff, 31);

	riskie_mem_store64(ht, addr, v64);
}

/*
 * The MRET instruction, returns from an M-mode trap back to where
 * we came from, restoring privilege level etc.
 *
 * Privilege level = MPP
 * MIE = MPIE
 * MPIE = 0
 * PC = MEPC
 */
static void
hart_opcode_mret(struct hart *ht, u_int32_t instr)
{
	u_int8_t	mpp;

	PRECOND(ht != NULL);

	riskie_log(ht, "MRET, mode=%u, mepc=0x%" PRIx64 "\n", ht->mode,
	    ht->csr[RISCV_CSR_MRW_MEPC]);

	mpp = riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS], 12) << 1 |
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS], 11);

	switch (mpp) {
	case RISKIE_HART_USER_MODE:
	case RISKIE_HART_MACHINE_MODE:
	case RISKIE_HART_SUPERVISOR_MODE:
		ht->mode = mpp;
		break;
	default:
		riskie_hart_fatal(ht, "invalid mode %u", mpp);
	}

	if (mpp != RISKIE_HART_MACHINE_MODE)
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 17);
	else
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], 17);

	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 11);
	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 12);

	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_STATUS_BIT_MPIE)) {
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_STATUS_BIT_MIE);
	} else {
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_STATUS_BIT_MIE);
	}

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], RISCV_STATUS_BIT_MPIE);

	ht->csr[RISCV_CSR_MRW_MCAUSE] = 0;
	ht->regs.pc = ht->csr[RISCV_CSR_MRW_MEPC];
}

/*
 * The AUIPC instruction:
 *	Add upper immediate to PC. Add 12 low order zero bits to the
 *	20-bit immediate, sign-extend it to 64-bits and add it to pc
 *	and stores the result in rd.
 */
static void
hart_opcode_auipc(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	imm;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	imm = riskie_instr_imm_u(ht, instr);

	riskie_log(ht,
	    "AUIPC, rd=%u, value=%" PRIx64 "\n", rd, ht->regs.x[rd]);

	ht->regs.x[rd] = (ht->regs.pc - sizeof(instr)) + (int64_t)imm;
}

/*
 * The LUI instruction:
 *	Load upper immediate. Add 12 low order zero bits to the
 *	20-bit immediate, sign-extend it to 64-bits and write the
 *	result to rd.
 */
static void
hart_opcode_lui(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	riskie_log(ht, "LUI, rd=%u, value=%" PRIx64 "\n", rd, ht->regs.x[rd]);

	ht->regs.x[rd] = riskie_sign_extend(instr & 0xfffff000, 31);
}

/*
 * The JAL instruction:
 *	The jump and link (JAL) instruction uses the J-type format,
 *	where the J-immediate encodes a signed offset in multiples of 2 bytes.
 *
 *	The offset is sign-extended and added to the pc to form the jump target
 *	address. Jumps can therefore target a ±1 MiB range. JAL stores the
 *	address of the instruction following the jump (pc+4) into register rd. 
 */
static void
hart_opcode_jal(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	off;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	off = riskie_instr_imm_j(ht, instr);

	riskie_log(ht, "JAL, rd=%u, off=%" PRId64 "\n", rd, (int64_t)off);

	ht->regs.x[rd] = ht->regs.pc;
	ht->regs.pc = (ht->regs.pc - sizeof(instr)) + (int64_t)off;
}

/*
 * The JALR instruction:
 *	The indirect jump instruction JALR (jump and link register) uses the
 *	I-type encoding. The target address is obtained by adding the 12-bit
 *	signed I-immediate to the register rs1, then setting the
 *	least-signiﬁcant bit of the result to zero.
 */
static void
hart_opcode_jalr(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rs1, rd;
	u_int64_t	off, base;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	off = riskie_instr_imm_i(ht, instr);

	riskie_log(ht,
	    "JALR, rd=%u, rs1=%u, off=%" PRIx64 "\n", rd, rs1, off);

	base = ht->regs.x[rs1];
	ht->regs.x[rd] = ht->regs.pc;
	ht->regs.pc = (base + off) & ~0x1;
}

/*
 * Check if we support the given CSR, returning -1 if we do not. Otherwise 0.
 */
static int
hart_csr_known(u_int16_t csr)
{
	switch (csr) {
	case RISCV_CSR_MRW_MIE:
	case RISCV_CSR_MRW_MIP:
	case RISCV_CSR_MRW_MISA:
	case RISCV_CSR_MRW_MEPC:
	case RISCV_CSR_MRW_MTVAL:
	case RISCV_CSR_MRW_MTVEC:
	case RISCV_CSR_MRW_MCAUSE:
	case RISCV_CSR_MRW_MSTATUS:
	case RISCV_CSR_MRW_MEDELEG:
	case RISCV_CSR_MRW_MIDELEG:
	case RISCV_CSR_MRW_MSCRATCH:
	case RISCV_CSR_MRW_MCOUNTEREN:
	case RISCV_CSR_MRW_MCOUNTINHIBIT:
		break;
	case RISCV_CSR_MRO_HART_ID:
	case RISCV_CSR_MRO_VENDOR_ID:
	case RISCV_CSR_MRO_ARCHITECTURE_ID:
	case RISCV_CSR_MRO_IMPLEMENTATION_ID:
		break;
	case RISCV_CSR_SRW_SIE:
	case RISCV_CSR_SRW_SIP:
	case RISCV_CSR_SRW_SATP:
	case RISCV_CSR_SRW_SEPC:
	case RISCV_CSR_SRW_STVAL:
	case RISCV_CSR_SRW_STVEC:
	case RISCV_CSR_SRW_SSTATUS:
	case RISCV_CSR_SRW_SSCRATCH:
	case RISCV_CSR_SRW_SCOUNTEREN:
		break;
	case RISCV_CSR_URO_TIME:
	case RISCV_CSR_URO_CYCLE:
		break;
	default:
		return (-1);
	}

	return (0);
}
