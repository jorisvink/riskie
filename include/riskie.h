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

#ifndef __H_RISKIE_H
#define __H_RISKIE_H

#include <sys/queue.h>

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* Maximum number of harts we support running. */
#define RISKIE_HART_MAX			1

/* The x0 - x31 registers. */
#define RISCV_REGISTER_COUNT		32

/* Maximum number of CSRs. */
#define RISCV_CSR_COUNT			4096

/* Some trap information. */
#define RISCV_TRAP_INTERRUPT_MAX	16
#define RISCV_TRAP_MAX			64

/* Traps we use. */
#define RISCV_TRAP_LOAD_ADDR_MISALIGNED	4

/*
 * RISC-V Control and Status Registers.
 */
#define RISCV_CSR_MRO_VENDOR_ID		0xf11
#define RISCV_CSR_MRO_ARCHITECTURE_ID	0xf12
#define RISCV_CSR_MRO_IMPLEMENTATION_ID	0xf13
#define RISCV_CSR_MRO_HART_ID		0xf14

/* Supervisor CSRs. */
#define RISCV_CSR_SRW_SSTATUS		0x100
#define RISCV_CSR_SRW_SIE		0x104
#define RISCV_CSR_SRW_SCOUNTEREN	0x106
#define RISCV_CSR_SRW_STVEC		0x105
#define RISCV_CSR_SRW_SSCRATCH		0x140
#define RISCV_CSR_SRW_SEPC		0x141
#define RISCV_CSR_SRW_SCAUSE		0x142
#define RISCV_CSR_SRW_STVAL		0x143
#define RISCV_CSR_SRW_SIP		0x144
#define RISCV_CSR_SRW_SATP		0x180

/* The machine status. */
#define RISCV_CSR_MRW_MSTATUS		0x300

/* The supported instructions csr. */
#define RISCV_CSR_MRW_MISA		0x301

/* Machine mode CSRs. */
#define RISCV_CSR_MRW_MEDELEG		0x302
#define RISCV_CSR_MRW_MIDELEG		0x303
#define RISCV_CSR_MRW_MIE		0x304
#define RISCV_CSR_MRW_MTVEC		0x305
#define RISCV_CSR_MRW_MCOUNTEREN	0x306
#define RISCV_CSR_MRW_MCOUNTINHIBIT	0x320
#define RISCV_CSR_MRW_MSCRATCH		0x340
#define RISCV_CSR_MRW_MEPC		0x341
#define RISCV_CSR_MRW_MCAUSE		0x342
#define RISCV_CSR_MRW_MTVAL		0x343
#define RISCV_CSR_MRW_MIP		0x344

/* Counter and Timer CSRs. */
#define RISCV_CSR_URO_CYCLE		0xc00
#define RISCV_CSR_URO_TIME		0xc01

/*
 * The [s,m]status register bits that are important to us right now.
 */
#define RISCV_STATUS_BIT_SIE		1
#define RISCV_STATUS_BIT_MIE		3
#define RISCV_STATUS_BIT_SPIE		5
#define RISCV_STATUS_BIT_MPIE		7
#define RISCV_STATUS_BIT_SPP		8
#define RISCV_STATUS_BIT_MPP_0		11
#define RISCV_STATUS_BIT_MPP_1		12

/* The bits that S-mode cannot write in the status register. */
#define RISCV_STATUS_SSTATUS_RO		0x7ffffffcfff2189e

/*
 * Interrupt bits for both M and S mode.
 */
#define RISCV_IRQ_BIT_MSI		3
#define RISCV_IRQ_BIT_MTI		7
#define RISCV_IRQ_BIT_MEI		11

#define RISCV_IRQ_BIT_SSI		1
#define RISCV_IRQ_BIT_STI		5
#define RISCV_IRQ_BIT_SEI		9

/* The bits that S-mode cannot write in sie, sip. */
#define RISCV_SIE_SIP_RO_BITS		0xfddc

/*
 * The RV32I instruction set.
 */

/* Load instructions. */
#define RISCV_RV32I_OPCODE_LOAD			0x03
#define RISCV_RV32I_INSTRUCTION_LB		0x00
#define RISCV_RV32I_INSTRUCTION_LH		0x01
#define RISCV_RV32I_INSTRUCTION_LW		0x02
#define RISCV_RV32I_INSTRUCTION_LBU		0x04
#define RISCV_RV32I_INSTRUCTION_LHU		0x05
#define RISCV_RV32I_INSTRUCTION_LWU		0x06

/* Store instructions. */
#define RISCV_RV32I_OPCODE_STORE		0x23
#define RISCV_RV32I_INSTRUCTION_SB		0x00
#define RISCV_RV32I_INSTRUCTION_SH		0x01
#define RISCV_RV32I_INSTRUCTION_SW		0x02

/* Integer Computational Instructions (Register - Immediate). */
#define RISCV_RV32I_OPCODE_I_TYPE		0x13
#define RISCV_RV32I_INSTRUCTION_ADDI		0x00
#define RISCV_RV32I_INSTRUCTION_SLLI		0x01
#define RISCV_RV32I_INSTRUCTION_SLTI		0x02
#define RISCV_RV32I_INSTRUCTION_SLTIU		0x03
#define RISCV_RV32I_INSTRUCTION_XORI		0x04
#define RISCV_RV32I_INSTRUCTION_ORI		0x06
#define RISCV_RV32I_INSTRUCTION_ANDI		0x07

#define RISCV_RV32I_FUNCTION_SRI		0x05
#define RISCV_RV32I_INSTRUCTION_SRLI		0x00
#define RISCV_RV32I_INSTRUCTION_SRAI		0x10

/* Integer Computational Instructions (Register - Register). */
#define RISCV_RV32I_OPCODE_R_TYPE		0x33
#define RISCV_RV32I_INSTRUCTION_SLL		0x01
#define RISCV_RV32I_INSTRUCTION_SLT		0x02
#define RISCV_RV32I_INSTRUCTION_SLTU		0x03
#define RISCV_RV32I_INSTRUCTION_XOR		0x04
#define RISCV_RV32I_INSTRUCTION_OR		0x06
#define RISCV_RV32I_INSTRUCTION_AND		0x07

#define RISCV_RV32I_FUNCTION_ADD_SUB		0x00
#define RISCV_RV32I_INSTRUCTION_ADD		0x00
#define RISCV_RV32I_INSTRUCTION_SUB		0x20

#define RISCV_RV32I_FUNCTION_SR			0x05
#define RISCV_RV32I_INSTRUCTION_SRL		0x00
#define RISCV_RV32I_INSTRUCTION_SRA		0x20

/* Control transfer instruction, branches (B-TYPE). */
#define RISCV_RV32I_OPCODE_B_TYPE		0x63
#define RISCV_RV32I_INSTRUCTION_BEQ		0x00
#define RISCV_RV32I_INSTRUCTION_BNE		0x01
#define RISCV_RV32I_INSTRUCTION_BLT		0x04
#define RISCV_RV32I_INSTRUCTION_BGE		0x05
#define RISCV_RV32I_INSTRUCTION_BLTU		0x06
#define RISCV_RV32I_INSTRUCTION_BGEU		0x07

/* System instructions. */
#define RISCV_RV32I_OPCODE_SYSTEM		0x73
#define RISCV_RV32I_INSTRUCTION_CSRRW		0x01
#define RISCV_RV32I_INSTRUCTION_CSRRS		0x02
#define RISCV_RV32I_INSTRUCTION_CSRRC		0x03
#define RISCV_RV32I_INSTRUCTION_CSRRWI		0x05
#define RISCV_RV32I_INSTRUCTION_CSRRSI		0x06
#define RISCV_RV32I_INSTRUCTION_CSRRCI		0x07

/* Other instructions. */
#define RISCV_RV32I_INSTRUCTION_AUIPC		0x17
#define RISCV_RV32I_INSTRUCTION_LUI		0x37
#define RISCV_RV32I_INSTRUCTION_JAL		0x6f
#define RISCV_RV32I_INSTRUCTION_JALR		0x67
#define RISCV_RV32I_INSTRUCTION_FENCE		0x0f

/*
 * Privileged instructions.
 */
#define RISCV_PRIV_FUNCTION_TRAP		0x00
#define RISCV_PRIV_INSTRUCTION_ECALL		0x00
#define RISCV_PRIV_INSTRUCTION_EBREAK		0x01

#define RISCV_PRIV_FUNCTION_TRAP_RETURN		0x02
#define RISCV_PRIV_INSTRUCTION_SRET		0x08
#define RISCV_PRIV_INSTRUCTION_MRET		0x18

#define RISCV_PRIV_FUNCTION_INTERRUPT_MGMT	0x05
#define RISCV_PRIV_INSTRUCTION_WFI		0x08

/*
 * The RV64I instruction set.
 */

/* Load instructions. */
#define RISCV_RV64I_INSTRUCTION_LD		0x03

/* Store instructions. */
#define RISCV_RV64I_INSTRUCTION_SD		0x03

/* Integer Computational Instructions (Register - Immediate). */
#define RISCV_RV64I_OPCODE_I_TYPE		0x1b
#define RISCV_RV64I_INSTRUCTION_ADDIW		0x00
#define RISCV_RV64I_INSTRUCTION_SLLIW		0x01

#define RISCV_RV64I_FUNCTION_SRIW		0x05
#define RISCV_RV64I_INSTRUCTION_SRLIW		0x00
#define RISCV_RV64I_INSTRUCTION_SRAIW		0x20

/* Integer Computational Instructions (Register - Register). */
#define RISCV_RV64I_OPCODE_R_TYPE		0x3b
#define RISCV_RV64I_INSTRUCTION_SLLW		0x01

#define RISCV_RV64I_FUNCTION_SRW		0x05
#define RISCV_RV64I_INSTRUCTION_SRLW		0x00
#define RISCV_RV64I_INSTRUCTION_SRAW		0x20

#define RISCV_RV64I_FUNCTION_ADD_SUB		0x00
#define RISCV_RV64I_INSTRUCTION_ADDW		0x00
#define RISCV_RV64I_INSTRUCTION_SUBW		0x20

/*
 * "M" instructions, standard extension for multiplication and division.
 * Some of these encode funct3, others encode funct7.
 */
#define RISCV_RV32M_INSTRUCTION_MUL		0x01
#define RISCV_RV32M_INSTRUCTION_DIV		0x01
#define RISCV_RV32M_INSTRUCTION_DIVU		0x01
#define RISCV_RV32M_INSTRUCTION_REM		0x01
#define RISCV_RV32M_INSTRUCTION_REMU		0x01

#define RISCV_RV64M_INSTRUCTION_MULW		0x01
#define RISCV_RV64M_INSTRUCTION_DIVW		0x04
#define RISCV_RV64M_INSTRUCTION_DIVUW		0x01
#define RISCV_RV64M_INSTRUCTION_REMW		0x06
#define RISCV_RV64M_INSTRUCTION_REMUW		0x07

/*
 * "A" instructions, standard extension for atomic instructions.
 * XXX - Riskie does not support AMOMIN[U].W/D or AMOMAX[U].W/D.
 */
#define RISCV_EXT_OPCODE_ATOMIC			0x2f
#define RISCV_EXT_ATOMIC_INSTRUCTION_ADD	0x00
#define RISCV_EXT_ATOMIC_INSTRUCTION_SWAP	0x01
#define RISCV_EXT_ATOMIC_INSTRUCTION_LR		0x02
#define RISCV_EXT_ATOMIC_INSTRUCTION_SC		0x03
#define RISCV_EXT_ATOMIC_INSTRUCTION_XOR	0x04
#define RISCV_EXT_ATOMIC_INSTRUCTION_OR		0x08
#define RISCV_EXT_ATOMIC_INSTRUCTION_AND	0x0c

#define RISCV_RV32A_FUNCTION_ATOMIC		0x02
#define RISCV_RV64A_FUNCTION_ATOMIC		0x03

/* The supported privilege modes. */
#define RISKIE_HART_MACHINE_MODE		3
#define RISKIE_HART_SUPERVISOR_MODE		1
#define RISKIE_HART_USER_MODE			0

/*
 * Memory mapped registers and their addresses.
 */
#define RISKIE_MEM_REG_MTIME		0xf0001000
#define RISKIE_MEM_REG_MTIMECMP		0xf0002000

/*
 * Memory operations.
 */
#define RISKIE_MEM_STORE		1
#define RISKIE_MEM_LOAD			2

/* The default base address where RAM is located and code is executed from. */
#define RISKIE_DEFAULT_MEM_BASE_ADDR	0x80000000

/* The default size of our main memory (128MB). */
#define RISKIE_DEFAULT_MEM_SIZE		(1 << 27)

/*
 * Internal flags bits.
 */
#define RISKIE_HART_FLAG_MTIMECMP	0
#define RISKIE_HART_FLAG_MEM_VIOLATION	1
#define RISKIE_HART_IRQ_TRIGGERED	2

/*
 * A RISC-V hart.
 */
struct hart {
	/* Note: memory LOADS are always 64-bit.  */
	u_int8_t		*mem;

	/* The current privilege mode. */
	u_int8_t		mode;

	/* Internal hart state flags. */
	u_int64_t		flags;

	/* Common registers. */
	struct {
		u_int64_t	pc;
		u_int64_t	ie;
		u_int64_t	ip;
		u_int64_t	status;
		u_int64_t	x[RISCV_REGISTER_COUNT];
	} regs;

	/* Memory mapped registers. */
	struct {
		u_int64_t	mtime;
		u_int64_t	mtimecmp;
	} mregs;

	/* Last Load-Reserved address and value. */
	struct {
		u_int8_t	valid;
		u_int64_t	addr;
		u_int64_t	value;
	} lr;

	/* Space for control and status registers. */
	u_int64_t		csr[RISCV_CSR_COUNT];
};

/*
 * An I/O request to a peripheral.
 */
struct peripheral_io_req {
	/* The peripheral that is called. */
	struct peripheral	*perp;

	/* The hart that caused the I/O request. */
	struct hart		*ht;

	/* Are we doing a LOAD or STORE? */
	int			ls;

	/* The address where the I/O requests occurred. */
	u_int64_t		addr;

	/* The amount of bytes requested. */
	size_t			len;
};

/*
 * A peripheral that is accessible via a certain memory space.
 * All memory accesses to this address range are redirected to the peripheral.
 */
struct peripheral {
	/* The memory allocation. */
	struct {
		u_int64_t	base;
		size_t		size;
		u_int8_t	*ptr;
	} mem;

	/* Called when memory access occurs. */
	u_int8_t	*(*io)(struct peripheral_io_req *);

	/* Called for each "tick" on the soc. */
	void		(*tick)(struct peripheral *);

	LIST_ENTRY(peripheral)	list;
};

/* The functions peripheral modules must export. */
void		peripheral_init(struct peripheral *);
u_int8_t	*peripheral_io(struct peripheral_io_req *);

/*
 * The "SoC" riskie mimics. Available as a global symbol to everyone.
 */
struct soc {
	/* Are we running under debug? */
	int			debug;

	/* Our main memory. */
	struct {
		u_int64_t	base;
		size_t		size;
		u_int8_t	*ptr;
	} mem;

	/* The harts. */
	struct hart		ht;

	/* The connected peripherals. */
	LIST_HEAD(, peripheral)	peripherals;
};

/* src/riskie.c */
int		riskie_last_signal(void);
int		riskie_input_pending(u_int8_t *);
void		fatal(const char *, ...) __attribute__((noreturn));

extern struct soc	*soc;

/* src/hart.c */
void		riskie_hart_dump(struct hart *);
void		riskie_hart_tick(struct hart *);
void		riskie_hart_trap(struct hart *);
void		riskie_hart_cleanup(struct hart *);
void		riskie_hart_init(struct hart *, u_int64_t, u_int16_t);
void		riskie_hart_fatal(struct hart *, const char *, ...)
		    __attribute__((format (printf, 2, 3)))
		    __attribute__((noreturn));

/* src/config.c */
void		riskie_config_load(const char *);

/* src/mem.c */
void		riskie_mem_dump(void);
void		riskie_mem_init(const char *);

u_int8_t	riskie_mem_fetch8(struct hart *, u_int64_t);
u_int16_t	riskie_mem_fetch16(struct hart *, u_int64_t);
u_int32_t	riskie_mem_fetch32(struct hart *, u_int64_t);
u_int64_t	riskie_mem_fetch64(struct hart *, u_int64_t);
u_int64_t	riskie_mem_fetch(struct hart *, u_int64_t, u_int16_t);

void		riskie_mem_store8(struct hart *, u_int64_t, u_int64_t);
void		riskie_mem_store16(struct hart *, u_int64_t, u_int64_t);
void		riskie_mem_store32(struct hart *, u_int64_t, u_int64_t);
void		riskie_mem_store64(struct hart *, u_int64_t, u_int64_t);
void		riskie_mem_store(struct hart *, u_int64_t, u_int64_t, size_t);

u_int8_t	*riskie_mem_validate_access(struct hart *, u_int64_t,
		    size_t, int);

/* src/instr.c */
u_int8_t	riskie_instr_rd(struct hart *, u_int32_t);
u_int8_t	riskie_instr_rs1(struct hart *, u_int32_t);
u_int8_t	riskie_instr_rs2(struct hart *, u_int32_t);
u_int16_t	riskie_instr_csr(struct hart *, u_int32_t);
u_int8_t	riskie_instr_shamt(struct hart *, u_int32_t);
u_int64_t	riskie_instr_imm_b(struct hart *, u_int32_t);
u_int64_t	riskie_instr_imm_i(struct hart *, u_int32_t);
u_int64_t	riskie_instr_imm_j(struct hart *, u_int32_t);
u_int64_t	riskie_instr_imm_s(struct hart *, u_int32_t);
u_int64_t	riskie_instr_imm_u(struct hart *, u_int32_t);

/* src/peripheral.c */
void		riskie_peripheral_tick(void);
void		riskie_peripheral_init(void);
void		riskie_peripheral_load(const char *, u_int64_t, size_t);

struct peripheral	*riskie_peripheral_add(u_int64_t, size_t,
			    u_int8_t *(*cb)(struct peripheral_io_req *));

struct peripheral	*riskie_peripheral_from_addr(u_int64_t);

/* src/utils.c */
u_int8_t	riskie_bit_get(u_int64_t, u_int8_t);
void		riskie_bit_set(u_int64_t *, u_int8_t);
void		riskie_bit_clear(u_int64_t *, u_int8_t);
u_int64_t	riskie_sign_extend(u_int32_t, u_int8_t);
void		riskie_bit_clone(u_int64_t *, u_int8_t, u_int8_t);
void		riskie_log(struct hart *, const char *, ...)
		    __attribute__((format (printf, 2, 3)));

/* src/term.c */
void		riskie_term_setup(void);
void		riskie_term_restore(void);

#endif
