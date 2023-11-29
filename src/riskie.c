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
#include <sys/queue.h>
#include <sys/signal.h>

#include <err.h>
#include <endian.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			errx(1, "precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* The x0 - x31 registers. */
#define RISCV_REGISTER_COUNT		32

/* Maximum number of CSRs. */
#define RISCV_CSR_COUNT			4096

/* The size of our memory (2MB). */
#define VM_MEM_SIZE			(1 << 21)

/*
 * RISC-V Control and Status Registers.
 */
#define RISCV_CSR_MRO_VENDOR_ID		0xf11
#define RISCV_CSR_MRO_ARCHITECTURE_ID	0xf12
#define RISCV_CSR_MRO_IMPLEMENTATION_ID	0xf13
#define RISCV_CSR_MRO_HART_ID		0xf14

/* The machine status. */
#define RISCV_CSR_MRW_MSTATUS		0x300

/* Vector base address and traps. */
#define RISCV_CSR_MRW_MIE		0x304
#define RISCV_CSR_MRW_MTVEC		0x305
#define RISCV_CSR_MRW_MEPC		0x341
#define RISCV_CSR_MRW_MCAUSE		0x342
#define RISCV_CSR_MRW_MIP		0x344

/*
 * The mstatus register bits that are important to us right now.
 */
#define RISCV_MSTATUS_BIT_SIE		1
#define RISCV_MSTATUS_BIT_MIE		3
#define RISCV_MSTATUS_BIT_MPIE		7

/*
 * mpi and mie bits that are important to us.
 */
#define RISCV_TRAP_BIT_MSI		3
#define RISCV_TRAP_BIT_MTI		7
#define RISCV_TRAP_BIT_MEI		11

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
#define RISCV_RV32I_INSTRUCTION_SRAI		0x20

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

/* The supported privilege modes. */
#define RISKIE_HART_MACHINE_MODE		3
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

/*
 * Internal flags bits.
 */
#define RISKIE_HART_FLAG_MTIMECMP	0
#define RISKIE_HART_FLAG_WFI		1
#define RISKIE_HART_FLAG_MEM_VIOLATION	2

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
		u_int64_t	x[RISCV_REGISTER_COUNT];
	} regs;

	/* Memory mapped registers. */
	struct {
		u_int64_t	mtime;
		u_int64_t	mtimecmp;
	} mregs;

	/* Space for control and status registers. */
	u_int64_t		csr[RISCV_CSR_COUNT];
};

static void	riskie_sig_handler(int);
static void	riskie_trap_signal(int);
static void	riskie_debug(struct hart *, const char *, ...);

static void	riskie_ht_run(struct hart *);
static void	riskie_ht_dump(struct hart *);
static void	riskie_ht_cleanup(struct hart *);
static void	riskie_ht_init(struct hart *, const char *, u_int16_t);
static void	riskie_ht_exception(struct hart *, const char *, ...)
		    __attribute__((noreturn));

static void		riskie_validate_pc(struct hart *);
static u_int16_t	riskie_validate_csr(struct hart *, u_int16_t);
static u_int8_t		riskie_validate_register(struct hart *, u_int8_t);
static u_int8_t		*riskie_validate_mem_access(struct hart *,
			    u_int64_t, size_t, int);

static u_int8_t		riskie_bit_get(u_int64_t, u_int8_t);
static void		riskie_bit_set(u_int64_t *, u_int8_t);
static void		riskie_bit_clear(u_int64_t *, u_int8_t);

static void		riskie_timer_next(struct hart *);
static void		riskie_environment_call(struct hart *);
static void		riskie_trap_machine(struct hart *, u_int8_t);

static void		riskie_interrupt_execute(struct hart *);
static void		riskie_interrupt_set_pending(struct hart *, u_int8_t);
static void		riskie_interrupt_clear_pending(struct hart *, u_int8_t);

static void		riskie_next_instruction(struct hart *);
static u_int64_t	riskie_sign_extend(u_int32_t, u_int8_t);
static int		riskie_csr_access(struct hart *, u_int16_t,
			    u_int64_t, int);

static u_int8_t		riskie_mem_fetch8(struct hart *, u_int64_t);
static u_int16_t	riskie_mem_fetch16(struct hart *, u_int64_t);
static u_int32_t	riskie_mem_fetch32(struct hart *, u_int64_t);
static u_int64_t	riskie_mem_fetch64(struct hart *, u_int64_t);
static u_int64_t	riskie_mem_fetch(struct hart *, u_int64_t, u_int16_t);

static void	riskie_mem_store8(struct hart *, u_int64_t, u_int64_t);
static void	riskie_mem_store16(struct hart *, u_int64_t, u_int64_t);
static void	riskie_mem_store32(struct hart *, u_int64_t, u_int64_t);
static void	riskie_mem_store64(struct hart *, u_int64_t, u_int64_t);
static void	riskie_mem_store(struct hart *, u_int64_t, u_int64_t, size_t);

static u_int8_t		riskie_instr_rd(struct hart *, u_int32_t);
static u_int8_t		riskie_instr_rs1(struct hart *, u_int32_t);
static u_int8_t		riskie_instr_rs2(struct hart *, u_int32_t);
static u_int8_t		riskie_instr_shamt(struct hart *, u_int32_t);
static u_int64_t	riskie_instr_imm_i(struct hart *, u_int32_t);
static u_int64_t	riskie_instr_imm_j(struct hart *, u_int32_t);
static u_int64_t	riskie_instr_imm_s(struct hart *, u_int32_t);
static u_int64_t	riskie_instr_imm_u(struct hart *, u_int32_t);

static void	riskie_opcode_lui(struct hart *, u_int32_t);
static void	riskie_opcode_jal(struct hart *, u_int32_t);
static void	riskie_opcode_jalr(struct hart *, u_int32_t);
static void	riskie_opcode_load(struct hart *, u_int32_t);
static void	riskie_opcode_mret(struct hart *, u_int32_t);
static void	riskie_opcode_store(struct hart *, u_int32_t);
static void	riskie_opcode_auipc(struct hart *, u_int32_t);
static void	riskie_opcode_system(struct hart *, u_int32_t);
static void	riskie_opcode_b_type(struct hart *, u_int32_t);
static void	riskie_opcode_r_type_32(struct hart *, u_int32_t);
static void	riskie_opcode_r_type_64(struct hart *, u_int32_t);
static void	riskie_opcode_i_type_32(struct hart *, u_int32_t);
static void	riskie_opcode_i_type_64(struct hart *, u_int32_t);

/* Last received signal. */
static volatile sig_atomic_t	sig_recv = -1;

/* Are we running with debug mode or not. */
static int			debug = 0;

static void
usage(void)
{
	fprintf(stderr, "Usage: riskie [-d] [binary]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		ch;
	struct hart	ht;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	riskie_trap_signal(SIGINT);

	riskie_ht_init(&ht, argv[0], 0);
	riskie_ht_run(&ht);
	riskie_ht_cleanup(&ht);

	return (0);
}

/*
 * Our signal handler.
 */
static void
riskie_sig_handler(int sig)
{
	sig_recv = sig;
}

/*
 * Catch the given signal by letting it call our signal handler.
 */
static void
riskie_trap_signal(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = riskie_sig_handler;

	if (sigfillset(&sa.sa_mask) == -1)
		err(1, "sigfillset");

	if (sigaction(sig, &sa, NULL) == -1)
		err(1, "sigaction");
}

/*
 * Output debug info on stdout if debug flag was given.
 */
static void
riskie_debug(struct hart *ht, const char *fmt, ...)
{
	va_list		args;

	PRECOND(ht != NULL);
	PRECOND(fmt != NULL);

	if (debug == 0)
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

/*
 * Set the given bit in the given 64-bit bitmap.
 */
static void
riskie_bit_set(u_int64_t *bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	*bitmap |= ((u_int64_t)1 << bit);
}

/*
 * Clear the given bit in the given 64-bit bitmap.
 */
static void
riskie_bit_clear(u_int64_t *bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	*bitmap &= ~((u_int64_t)1 << bit);
}

/*
 * Get the given bit from the given 64-bit bitmap.
 */
static u_int8_t
riskie_bit_get(u_int64_t bitmap, u_int8_t bit)
{
	PRECOND(bit <= 63);

	return ((bitmap >> bit) & 0x01);
}

/*
 * Fetch 8 bits from the given address in our memory and return it.
 */
static u_int8_t
riskie_mem_fetch8(struct hart *ht, u_int64_t addr)
{
	return ((u_int8_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 16 bits from the given address in our memory and return it.
 */
static u_int16_t
riskie_mem_fetch16(struct hart *ht, u_int64_t addr)
{
	return ((u_int16_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 32 bits from the given address in our memory and return it.
 */
static u_int32_t
riskie_mem_fetch32(struct hart *ht, u_int64_t addr)
{
	return ((u_int32_t)riskie_mem_fetch64(ht, addr));
}

/*
 * Fetch 64 bits from address in our memory and return it.
 */
static u_int64_t
riskie_mem_fetch64(struct hart *ht, u_int64_t addr)
{
	u_int64_t	v;
	u_int8_t	*ptr;

	PRECOND(ht != NULL);

	ptr = riskie_validate_mem_access(ht, addr, 8, RISKIE_MEM_LOAD);
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
static u_int64_t
riskie_mem_fetch(struct hart *ht, u_int64_t addr, u_int16_t bits)
{
	u_int64_t	v;

	PRECOND(ht != NULL);

	riskie_debug(ht,
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
		riskie_ht_exception(ht, "%s: unknown bits %u", __func__, bits);
	}

	return (v);
}

/*
 * Store 8 bits at the given address.
 */
static void
riskie_mem_store8(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_validate_mem_access(ht, addr, 1, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
}

/*
 * Store 16 bits at the given address.
 */
static void
riskie_mem_store16(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_validate_mem_access(ht, addr, 2, RISKIE_MEM_STORE);
	if (ptr == NULL)
		return;

	ptr[0] = (u_int8_t)(value & 0xff);
	ptr[1] = (u_int8_t)((value >> 8) & 0xff);
}

/*
 * Store 32 bits at the given address.
 */
static void
riskie_mem_store32(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_validate_mem_access(ht, addr, 4, RISKIE_MEM_STORE);
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
static void
riskie_mem_store64(struct hart *ht, u_int64_t addr, u_int64_t value)
{
	u_int8_t	*ptr;

	ptr = riskie_validate_mem_access(ht, addr, 8, RISKIE_MEM_STORE);
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
static void
riskie_mem_store(struct hart *ht, u_int64_t addr, u_int64_t value, size_t bits)
{
	PRECOND(ht != NULL);

	riskie_debug(ht,
	    "MEM-STORE: addr=0x%" PRIx64 ", value=0x%" PRIx64 ", bits=%zu\n",
	    addr, value, bits);

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
		riskie_ht_exception(ht, "%s: unknown bits %u", __func__, bits);
	}
}

/*
 * Prepare the VM by loading in the image specified in the given path.
 * The image is always loaded at 0x0.
 */
static void
riskie_ht_init(struct hart *ht, const char *path, u_int16_t hid)
{
	int			fd;
	struct stat		st;
	ssize_t			ret;

	PRECOND(ht != NULL);
	PRECOND(path != NULL);

	memset(ht, 0, sizeof(*ht));

	if ((ht->mem = calloc(1, VM_MEM_SIZE)) == NULL)
		err(1, "calloc");

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "open: %s", path);

	if (fstat(fd, &st) == -1)
		err(1, "fstat: %s", path);

	if (st.st_size > VM_MEM_SIZE)
		errx(1, "image doesn't fit in memory");

	if ((ret = read(fd, ht->mem, st.st_size)) == -1)
		err(1, "read");

	close(fd);

	if (ret != st.st_size)
		errx(1, "failed to read, only got %zd/%zd", ret, st.st_size);

	ht->regs.x[2] = VM_MEM_SIZE;
	ht->mode = RISKIE_HART_MACHINE_MODE;

	ht->csr[RISCV_CSR_MRO_HART_ID] = hid;
	ht->csr[RISCV_CSR_MRO_VENDOR_ID] = 0x20231021;

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], RISCV_MSTATUS_BIT_MPIE);

	riskie_debug(ht, "loaded %zd byte image at 0x00000000\n", ret);
}

/*
 * Cleanup the VM data and all its resources.
 */
static void
riskie_ht_cleanup(struct hart *ht)
{
	PRECOND(ht != NULL);

	free(ht->mem);
}

/*
 * An exception occurred, we log it, dump all registers and exit.
 */
static void
riskie_ht_exception(struct hart *ht, const char *fmt, ...)
{
	va_list		args;

	PRECOND(ht != NULL);

	fprintf(stderr, "ht exception: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	riskie_ht_dump(ht);
	riskie_ht_cleanup(ht);

	exit(1);
}

/*
 * Dump the given hart its registers.
 */
static void
riskie_ht_dump(struct hart *ht)
{
	int		idx;

	PRECOND(ht != NULL);

	fprintf(stderr, "\n");

	fprintf(stderr, "pc=0x%" PRIx64 "\n", ht->regs.pc - sizeof(u_int32_t));
	for (idx = 0; idx < RISCV_REGISTER_COUNT; idx++)
		fprintf(stderr, "x%d=0x%" PRIx64 "\n", idx, ht->regs.x[idx]);
}

/*
 * Run the VM by executing instructions.
 */
static void
riskie_ht_run(struct hart *ht)
{
	int		running;

	PRECOND(ht != NULL);

	running = 1;

	while (running) {
		if (sig_recv != -1) {
			switch (sig_recv) {
			case SIGINT:
				running = 0;
				continue;
			}
			sig_recv = -1;
		}

		riskie_timer_next(ht);
		riskie_interrupt_execute(ht);

		if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_WFI) == 0)
			riskie_next_instruction(ht);
	}

	riskie_ht_exception(ht, "interrupted by user");
}

/*
 * Validate the current value in the PC register, make sure it can
 * be executed in the correct privilege mode.
 */
static void
riskie_validate_pc(struct hart *ht)
{
	PRECOND(ht != NULL);

	if ((ht->regs.pc % 4) != 0)
		riskie_ht_exception(ht, "unaligned instruction access");

	if (ht->regs.pc + sizeof(u_int32_t) < ht->regs.pc)
		riskie_ht_exception(ht, "pc wrap around");

	if (ht->regs.pc + sizeof(u_int32_t) > VM_MEM_SIZE)
		riskie_ht_exception(ht, "pc out of bounds");

	/* XXX - todo, check R and X bit. */
	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		break;
	}
}

/*
 * Validate the given CSR to be a valid one.
 */
static u_int16_t
riskie_validate_csr(struct hart *ht, u_int16_t csr)
{
	if (csr >= RISCV_CSR_COUNT)
		riskie_ht_exception(ht, "csr out of bounds (%u)", csr);

	return (csr);
}

/*
 * Validate the given register to be a valid one.
 */
static u_int8_t
riskie_validate_register(struct hart *ht, u_int8_t reg)
{
	PRECOND(ht != NULL);

	if (reg >= RISCV_REGISTER_COUNT)
		riskie_ht_exception(ht, "reg out of bounds (%u)", reg);

	return (reg);
}

/*
 * Check if we can access memory at addr for the given amount of bytes.
 * XXX - The privilege accesses should be checked here later.
 *
 * This will return a pointer to where the data can be written, which
 * is essentially &ht->mem[addr] unless addr was a memory mapped register,
 * in which case a pointer to the correct mreg is returned.
 */
static u_int8_t *
riskie_validate_mem_access(struct hart *ht, u_int64_t addr, size_t len, int ls)
{
	u_int8_t	*ptr;

	PRECOND(ht != NULL);
	PRECOND(ls == RISKIE_MEM_STORE || ls == RISKIE_MEM_LOAD);

	ptr = NULL;

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

	if (addr >= VM_MEM_SIZE) {
		riskie_ht_exception(ht,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}

	if (addr + len < addr)
		riskie_ht_exception(ht, "memory access overflow");

	if (addr + len > VM_MEM_SIZE) {
		riskie_ht_exception(ht,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}

	ptr = &ht->mem[addr];

	return (ptr);
}

/*
 * Sign extend the 32-bit value to a 64-bit value.
 */
static u_int64_t
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
 * Extracts the "shamt" part of the given I-TYPE instruction.
 * For RV64I implementations these are bits 25..20.
 */
static u_int8_t
riskie_instr_shamt(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return ((instr >> 20) & 0x3f);
}

/*
 * Extract the "csr" part of the given instruction. (bits 31 .. 20)
 */
static u_int16_t
riskie_instr_csr(struct hart *ht, u_int32_t instr)
{
	u_int16_t	csr;

	PRECOND(ht != NULL);

	csr = (instr >> 20) & 0xfff;

	return (riskie_validate_csr(ht, csr));
}

/*
 * Extract the "rd" part of the given instruction (bits 11 .. 7).
 * Present in R, I, S, U and J instructions.
 */
static u_int8_t
riskie_instr_rd(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_validate_register(ht, (instr >> 7) & 0x1f));
}

/*
 * Extract the "rs1" part of the given instruction (bits 19 .. 15).
 * Present in R, I, S and B instructions.
 */
static u_int8_t
riskie_instr_rs1(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_validate_register(ht, (instr >> 15) & 0x1f));
}

/*
 * Extract the "rs2" part of the given instruction (bits 24 .. 20).
 * Present in R, S and B instructions.
 */
static u_int8_t
riskie_instr_rs2(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_validate_register(ht, (instr >> 20) & 0x1f));
}

/*
 * Extract the immediate value from a B-type instruction.
 * imm[12|10:5|4:1|11] = inst[31|30:25|11:8|7]
 */
static u_int64_t
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
static u_int64_t
riskie_instr_imm_u(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_sign_extend(instr & 0xfffff000, 31));
}

/*
 * Extract the immediate value from a I-type instruction.
 * imm[11:0] = inst[31:20]
 */
static u_int64_t
riskie_instr_imm_i(struct hart *ht, u_int32_t instr)
{
	PRECOND(ht != NULL);

	return (riskie_sign_extend(instr >> 20, 11));
}

/*
 * Extract the immediate value from a J-type instruction.
 * imm[20|10:1|11|19:12] = inst[31|30:21|20|19:12]
 */
static u_int64_t
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
static u_int64_t
riskie_instr_imm_s(struct hart *ht, u_int32_t instr)
{
	u_int32_t		imm;

	PRECOND(ht != NULL);

	imm = ((instr & 0xfe000000) >> 20) | ((instr >> 7) & 0x1f);

	return (riskie_sign_extend(imm, 11));
}

/*
 * Check permissions for the given CSR against our current privilege
 * mode and wether or not we are trying to read / write.
 *
 * XXX - if it fails we do a hard fail right now.
 */
static int
riskie_csr_access(struct hart *ht, u_int16_t csr, u_int64_t bits, int ls)
{
	int		fail;
	u_int8_t	perm, privilege;

	PRECOND(ht != NULL);

	perm = (csr >> 10) & 0x03;
	privilege = (csr >> 8) & 0x03;

	if (ht->mode != privilege)
		riskie_ht_exception(ht, "unprivileged access to 0x%04x", csr);

	switch (ls) {
	case RISKIE_MEM_STORE:
		if (perm != 0 && perm != 2)
			riskie_ht_exception(ht, "write to ro csr 0x%04x", csr);
		break;
	case RISKIE_MEM_LOAD:
		if (perm == 2)
			riskie_ht_exception(ht, "read from wr csr 0x%04x", csr);
		break;
	default:
		riskie_ht_exception(ht, "unknown ls %d", ls);
	}

	if (bits == 0)
		return (1);

	fail = 0;

	/*
	 * Different CSRs have protected bits that cannot be set
	 * by software.
	 */
	switch (csr) {
	case RISCV_CSR_MRW_MIP:
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MEI))
			fail++;
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MTI))
			fail++;
		if (riskie_bit_get(bits, RISCV_TRAP_BIT_MSI))
			fail++;
		break;
	}

	if (fail)
		riskie_ht_exception(ht, "write to ro-bit csr 0x%04x", csr);

	return (0);
}

/*
 * Execute an environment call into M-mode, this happens immediately.
 */
static void
riskie_environment_call(struct hart *ht)
{
	u_int8_t	exception;

	PRECOND(ht != NULL);

	/* Global M-mode interrupts enabled. */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_MSTATUS_BIT_MIE) == 0)
		return;

	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		exception = 11;
		break;
	default:
		riskie_ht_exception(ht, "invalid mode %u", ht->mode);
	}

	riskie_trap_machine(ht, exception);
}

/*
 * Get current nanoseconds since boot and store it into the mtime memory
 * register. Check mtimecmp and set MTI to pending if mtime >= mtimecmp.
 */
static void
riskie_timer_next(struct hart *ht)
{
	struct timespec		ts;

	PRECOND(ht != NULL);

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	ht->mregs.mtime = ts.tv_nsec + (ts.tv_sec * 1000000000);

	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MTIMECMP)) {
		if (ht->mregs.mtimecmp > ht->mregs.mtime)
			riskie_interrupt_clear_pending(ht, RISCV_TRAP_BIT_MTI);
		else
			riskie_interrupt_set_pending(ht, RISCV_TRAP_BIT_MTI);
	}
}

/*
 * Clear the given interrupt bit from the mpi register.
 */
static void
riskie_interrupt_clear_pending(struct hart *ht, u_int8_t irq)
{
	PRECOND(ht != NULL);
	PRECOND(irq <= 15);

	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MIP], irq);
}

/*
 * Mark the given interrupt bit as pending in the mpi register.
 */
static void
riskie_interrupt_set_pending(struct hart *ht, u_int8_t irq)
{
	PRECOND(ht != NULL);
	PRECOND(irq <= 15);

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MIP], irq);
}

/*
 * Execute pending interrupts in priority order:
 *	-> MEI, MSI, MTI, SEI, SSI, STI.
 */
static void
riskie_interrupt_execute(struct hart *ht)
{
	PRECOND(ht != NULL);

	/* Global M-mode interrupts enabled. */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_MSTATUS_BIT_MIE) == 0)
		return;

	/* MIE */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MEI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MEI))
		riskie_trap_machine(ht, RISCV_TRAP_BIT_MEI);

	/* MSI */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MSI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MSI))
		riskie_trap_machine(ht, RISCV_TRAP_BIT_MSI);

	/* MTI */
	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIE], RISCV_TRAP_BIT_MTI) &&
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MIP], RISCV_TRAP_BIT_MTI))
		riskie_trap_machine(ht, RISCV_TRAP_BIT_MTI);
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
 */
static void
riskie_trap_machine(struct hart *ht, u_int8_t exception)
{
	PRECOND(ht != NULL);
	PRECOND(exception < 64);

	riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_WFI);

	riskie_debug(ht, "MTRAP, mode=%u, exception=%u, mpi=0x%" PRIx64
	    ", mie=0x%" PRIx64 "\n", ht->mode, exception,
	    ht->csr[RISCV_CSR_MRW_MIP], ht->csr[RISCV_CSR_MRW_MIE]);

	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], 11);
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], 12);
		break;
	case RISKIE_HART_USER_MODE:
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 11);
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 12);
		ht->mode = RISKIE_HART_MACHINE_MODE;
		break;
	default:
		riskie_ht_exception(ht, "invalid mode %u", ht->mode);
	}

	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_MSTATUS_BIT_MIE)) {
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_MSTATUS_BIT_MPIE);
	} else {
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_MSTATUS_BIT_MPIE);
	}

	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_MSTATUS_BIT_MIE);

	ht->csr[RISCV_CSR_MRW_MEPC] = ht->regs.pc;
	ht->csr[RISCV_CSR_MRW_MCAUSE] = exception;

	ht->regs.pc = ht->csr[RISCV_CSR_MRW_MTVEC];
}

/*
 * Fetch the next instruction, decode it and execute it.
 */
static void
riskie_next_instruction(struct hart *ht)
{
	u_int32_t	instr;
	u_int8_t	opcode;

	PRECOND(ht != NULL);

	riskie_validate_pc(ht);
	memcpy(&instr, &ht->mem[ht->regs.pc], sizeof(instr));
	ht->regs.pc += sizeof(instr);

	ht->regs.x[0] = 0;
	opcode = instr & 0x7f;

	switch (opcode) {
	case RISCV_RV32I_OPCODE_LOAD:
		riskie_opcode_load(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_STORE:
		riskie_opcode_store(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_SYSTEM:
		riskie_opcode_system(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_B_TYPE:
		riskie_opcode_b_type(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_I_TYPE:
		riskie_opcode_i_type_32(ht, instr);
		break;
	case RISCV_RV64I_OPCODE_I_TYPE:
		riskie_opcode_i_type_64(ht, instr);
		break;
	case RISCV_RV32I_OPCODE_R_TYPE:
		riskie_opcode_r_type_32(ht, instr);
		break;
	case RISCV_RV64I_OPCODE_R_TYPE:
		riskie_opcode_r_type_64(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_AUIPC:
		riskie_opcode_auipc(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_LUI:
		riskie_opcode_lui(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JAL:
		riskie_opcode_jal(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JALR:
		riskie_opcode_jalr(ht, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_FENCE:
		break;
	default:
		riskie_ht_exception(ht, "illegal instruction 0x%08x", instr);
	}
}

/*
 * A load instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
riskie_opcode_load(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "LOAD, funct3=0x%02x, rd=%u, rs1=%u, addr=0x%"
	    PRIx64 "\n", funct3, rd, rs1, addr);

	riskie_debug(ht, "    <- reg.%u = %" PRIx64 "\n", rs1, ht->regs.x[rs1]);

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
		riskie_ht_exception(ht, "illegal load 0x%08x", instr);
	}

	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION) == 0) {
		ht->regs.x[rd] = v64;
		riskie_debug(ht, "    -> reg.%u = %" PRIx64 "\n",
		    rd, ht->regs.x[rd]);
	} else {
		/* XXX trigger some sort of exception. */
		riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		riskie_debug(ht, "    -> memory violation\n");
	}
}

/*
 * A store instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
riskie_opcode_store(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "STORE, funct3=0x%02x, rs1=%u, rs2=%u, "
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
		riskie_ht_exception(ht, "illegal store 0x%08x", instr);
	}

	/* XXX trigger some sort of exception. */
	if (riskie_bit_get(ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION)) {
		riskie_bit_clear(&ht->flags, RISKIE_HART_FLAG_MEM_VIOLATION);
		riskie_debug(ht, "    -> memory violation\n");
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
riskie_opcode_system(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "SYSTEM, funct3=0x%02x, funct7=0x%02x rd=%u, rs1=%u, "
	    "rs2=%u csr=0x%02x\n", funct3, funct7, rd, rs1, rs2, csr);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRC:
		rs1 = ht->regs.x[rs1];
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		rs1 = rs1 & 0xf;
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
				riskie_opcode_mret(ht, instr);
				break;
			default:
				riskie_ht_exception(ht,
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
				riskie_ht_exception(ht,
				    "illegal interrupt mgmt 0x%08x", instr);
			}
			break;
		case RISCV_PRIV_INSTRUCTION_ECALL:
			riskie_environment_call(ht);
			break;
		case RISCV_PRIV_INSTRUCTION_EBREAK:
			riskie_ht_dump(ht);
			break;
		default:
			riskie_ht_exception(ht,
			    "illegal trap instruction 0x%08x", instr);
		}
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
		/*
		 * This counts as atomic unless we start doing
		 * multiprocess approaches for the future harts.
		 */
		riskie_csr_access(ht, csr, rs1, RISKIE_MEM_LOAD);
		riskie_csr_access(ht, csr, rs1, RISKIE_MEM_STORE);
		if (rd != 0)
			ht->regs.x[rd] = ht->csr[csr];
		ht->csr[csr] = rs1;
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
		riskie_csr_access(ht, csr, rs1, RISKIE_MEM_LOAD);
		ht->regs.x[rd] = ht->csr[csr];

		if (rs1 != 0) {
			riskie_csr_access(ht, csr, rs1, RISKIE_MEM_STORE);
			ht->csr[csr] |= rs1;
		}
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRC:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		riskie_csr_access(ht, csr, rs1, RISKIE_MEM_LOAD);
		ht->regs.x[rd] = ht->csr[csr];

		if (rs1 != 0) {
			riskie_csr_access(ht, csr, rs1, RISKIE_MEM_STORE);
			ht->csr[csr] &= ~rs1;
		}
		break;
	default:
		riskie_ht_exception(ht, "illegal system 0x%08x", instr);
	}
}

/*
 * Control transfer instructions, conditional branches.
 */
static void
riskie_opcode_b_type(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "B-TYPE, funct3=0x%02x, rs1=%u, rs2=%u, "
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
		riskie_ht_exception(ht, "illegal b-type 0x%08x", instr);
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
riskie_opcode_i_type_32(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd, rs1;
	u_int64_t	imm, sbit;
	u_int32_t	funct3, funct7, shamt;

	PRECOND(ht != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	imm = riskie_instr_imm_i(ht, instr);
	shamt = riskie_instr_shamt(ht, instr);

	riskie_debug(ht, "I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, "
	    "rd=%u, rs1=%u, imm=%" PRId64 "\n", funct3, funct7, rd,
	    rs1, (int64_t)imm);

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
			ht->regs.x[rd] = ht->regs.x[rs1] >> imm;
			break;
		case RISCV_RV32I_INSTRUCTION_SRAI:
			sbit = ht->regs.x[rs1] >> 63;
			ht->regs.x[rd] = ht->regs.x[rs1] >> imm;
			ht->regs.x[rd] |= sbit << 63;
			break;
		default:
			riskie_ht_exception(ht, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_ht_exception(ht, "illegal i-type 0x%08x", instr);
	}

	riskie_debug(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
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
riskie_opcode_i_type_64(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
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
			riskie_ht_exception(ht, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_ht_exception(ht, "illegal i-type 0x%08x", instr);
	}

	riskie_debug(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * The register to register instructions as part of the
 * "Integer Computational Instructions" instruction set.
 *
 * Note that while these are part of the RV32I instruction set, they
 * operate on XLEN bits, and thus 64-bit.
 */
static void
riskie_opcode_r_type_32(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_OR:
		ht->regs.x[rd] = ht->regs.x[rs1] | ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_XOR:
		ht->regs.x[rd] = ht->regs.x[rs1] ^ ht->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_AND:
		ht->regs.x[rd] = ht->regs.x[rs1] & ht->regs.x[rs2];
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
		default:
			riskie_ht_exception(ht, "illegal addsub 0x%08x", instr);
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
		default:
			riskie_ht_exception(ht, "illegal sr 0x%08x", instr);
		}
		break;
	default:
		riskie_ht_exception(ht, "illegal r-type 0x%08x", instr);
	}

	riskie_debug(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
}

/*
 * The register to register instructions as part of the
 * "Integer Computational Instructions" instruction set.
 *
 * This function handles decoding of instructions that are part of RV64I.
 *
 * Note that while these are part of the RV64I instruction set, these
 * instructions implement the *.W variants and thus operate on 32-bit.
 */
static void
riskie_opcode_r_type_64(struct hart *ht, u_int32_t instr)
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

	riskie_debug(ht, "I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV64I_INSTRUCTION_SLLW:
		ht->regs.x[rd] = (u_int32_t)(ht->regs.x[rs1] <<
		    (ht->regs.x[rs2] & 0xf));
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
		default:
			riskie_ht_exception(ht, "illegal addsub 0x%08x", instr);
		}
		break;
	case RISCV_RV64I_FUNCTION_SRW:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_SRLW:
			v32 = ht->regs.x[rs1];
			ht->regs.x[rd] = v32 >> (ht->regs.x[rs2] & 0xf);
			break;
		case RISCV_RV64I_INSTRUCTION_SRAW:
			v32 = ht->regs.x[rs1];
			sbit = v32 >> 31;
			ht->regs.x[rd] = v32 >> (ht->regs.x[rs2] & 0xf);
			ht->regs.x[rd] |= sbit << 31;
			break;
		default:
			riskie_ht_exception(ht, "illegal sri 0x%08x", instr);
		}
	default:
		riskie_ht_exception(ht, "illegal r-type 0x%08x", instr);
	}

	riskie_debug(ht, "   -> reg.%u = %" PRIx64 "\n", rd, ht->regs.x[rd]);
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
riskie_opcode_mret(struct hart *ht, u_int32_t instr)
{
	u_int8_t	mpp;

	PRECOND(ht != NULL);

	riskie_debug(ht, "MRET, mode=%u, mepc=0x%" PRIx64 "\n", ht->mode,
	    ht->csr[RISCV_CSR_MRW_MEPC]);

	mpp = riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS], 12) << 1 |
	    riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS], 11);

	switch (mpp) {
	case RISKIE_HART_USER_MODE:
	case RISKIE_HART_MACHINE_MODE:
		ht->mode = mpp;
		break;
	default:
		riskie_ht_exception(ht, "invalid mode %u", mpp);
	}

	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 11);
	riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS], 12);

	if (riskie_bit_get(ht->csr[RISCV_CSR_MRW_MSTATUS],
	    RISCV_MSTATUS_BIT_MPIE)) {
		riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_MSTATUS_BIT_MIE);
	} else {
		riskie_bit_clear(&ht->csr[RISCV_CSR_MRW_MSTATUS],
		    RISCV_MSTATUS_BIT_MIE);
	}

	riskie_bit_set(&ht->csr[RISCV_CSR_MRW_MSTATUS], RISCV_MSTATUS_BIT_MPIE);

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
riskie_opcode_auipc(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	imm;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	imm = riskie_instr_imm_u(ht, instr);

	riskie_debug(ht,
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
riskie_opcode_lui(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	riskie_debug(ht, "LUI, rd=%u, value=%" PRIx64 "\n", rd, ht->regs.x[rd]);

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
riskie_opcode_jal(struct hart *ht, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	off;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	off = riskie_instr_imm_j(ht, instr);

	riskie_debug(ht, "JAL, rd=%u, off=%" PRId64 "\n", rd, (int64_t)off);

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
riskie_opcode_jalr(struct hart *ht, u_int32_t instr)
{
	u_int64_t	off;
	u_int8_t	rs1, rd;

	PRECOND(ht != NULL);

	rd = riskie_instr_rd(ht, instr);
	rs1 = riskie_instr_rs1(ht, instr);
	off = riskie_instr_imm_i(ht, instr);

	riskie_debug(ht,
	    "JALR, rd=%u, rs1=%u, off=%" PRIx64 "\n", rd, rs1, off);

	ht->regs.x[rd] = ht->regs.pc;
	ht->regs.pc = (rs1 + off) & ~0x1;
}
