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
 * Some RISC-V defined CSRs we prepopulate.
 */
#define RISCV_CSR_RO_VENDOR_ID		0xf11
#define RISCV_CSR_RO_ARCHITECTURE_ID	0xf12
#define RISCV_CSR_RO_IMPLEMENTATION_ID	0xf13
#define RISCV_CSR_RO_HART_ID		0xf14

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
#define RISCV_RV32I_INSTRUCTION_ECALL		0x00
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
 * The RISC-V vm.
 */
struct vm {
	/* Note: memory LOADS are always 64-bit.  */
	u_int8_t		*mem;

	struct {
		u_int64_t	pc;
		u_int64_t	x[RISCV_REGISTER_COUNT];
	} regs;

	u_int64_t		csr[RISCV_CSR_COUNT];
};

static void	riskie_sig_handler(int);
static void	riskie_trap_signal(int);
static void	riskie_debug(const char *, ...);

static void	riskie_vm_run(struct vm *);
static void	riskie_vm_cleanup(struct vm *);
static void	riskie_vm_init(struct vm *, const char *);
static void	riskie_vm_exception(struct vm *, const char *, ...)
		    __attribute__((noreturn));

static void		riskie_validate_pc(struct vm *);
static u_int16_t	riskie_validate_csr(struct vm *, u_int16_t);
static u_int8_t		riskie_validate_register(struct vm *, u_int8_t);
static void		riskie_validate_mem_access(struct vm *,
			    u_int64_t, size_t);

static void		riskie_next_instruction(struct vm *);
static u_int64_t	riskie_sign_extend(u_int32_t, u_int8_t);
static void		riskie_csr_writable(struct vm *, u_int16_t);

static u_int8_t		riskie_mem_fetch8(struct vm *, u_int64_t);
static u_int16_t	riskie_mem_fetch16(struct vm *, u_int64_t);
static u_int32_t	riskie_mem_fetch32(struct vm *, u_int64_t);
static u_int64_t	riskie_mem_fetch64(struct vm *, u_int64_t);
static u_int64_t	riskie_mem_fetch(struct vm *, u_int64_t, u_int16_t);

static void	riskie_mem_store8(struct vm *, u_int64_t, u_int64_t);
static void	riskie_mem_store16(struct vm *, u_int64_t, u_int64_t);
static void	riskie_mem_store32(struct vm *, u_int64_t, u_int64_t);
static void	riskie_mem_store64(struct vm *, u_int64_t, u_int64_t);
static void	riskie_mem_store(struct vm *, u_int64_t, u_int64_t, size_t);

static u_int8_t		riskie_instr_rd(struct vm *, u_int32_t);
static u_int8_t		riskie_instr_rs1(struct vm *, u_int32_t);
static u_int8_t		riskie_instr_rs2(struct vm *, u_int32_t);
static u_int8_t		riskie_instr_shamt(struct vm *, u_int32_t);
static u_int64_t	riskie_instr_imm_i(struct vm *, u_int32_t);
static u_int64_t	riskie_instr_imm_j(struct vm *, u_int32_t);
static u_int64_t	riskie_instr_imm_s(struct vm *, u_int32_t);
static u_int64_t	riskie_instr_imm_u(struct vm *, u_int32_t);

static void	riskie_opcode_lui(struct vm *, u_int32_t);
static void	riskie_opcode_jal(struct vm *, u_int32_t);
static void	riskie_opcode_jalr(struct vm *, u_int32_t);
static void	riskie_opcode_load(struct vm *, u_int32_t);
static void	riskie_opcode_store(struct vm *, u_int32_t);
static void	riskie_opcode_auipc(struct vm *, u_int32_t);
static void	riskie_opcode_system(struct vm *, u_int32_t);
static void	riskie_opcode_b_type(struct vm *, u_int32_t);
static void	riskie_opcode_r_type_32(struct vm *, u_int32_t);
static void	riskie_opcode_r_type_64(struct vm *, u_int32_t);
static void	riskie_opcode_i_type_32(struct vm *, u_int32_t);
static void	riskie_opcode_i_type_64(struct vm *, u_int32_t);

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
	struct vm	vm;

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

	riskie_vm_init(&vm, argv[0]);
	riskie_vm_run(&vm);
	riskie_vm_cleanup(&vm);

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
riskie_debug(const char *fmt, ...)
{
	va_list		args;

	PRECOND(fmt != NULL);

	if (debug == 0)
		return;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/*
 * Fetch 8 bits from the given address in our memory and return it.
 */
static u_int8_t
riskie_mem_fetch8(struct vm *vm, u_int64_t addr)
{
	return ((u_int8_t)riskie_mem_fetch64(vm, addr));
}

/*
 * Fetch 16 bits from the given address in our memory and return it.
 */
static u_int16_t
riskie_mem_fetch16(struct vm *vm, u_int64_t addr)
{
	return ((u_int16_t)riskie_mem_fetch64(vm, addr));
}

/*
 * Fetch 32 bits from the given address in our memory and return it.
 */
static u_int32_t
riskie_mem_fetch32(struct vm *vm, u_int64_t addr)
{
	return ((u_int32_t)riskie_mem_fetch64(vm, addr));
}

/*
 * Fetch 64 bits from address in our memory and return it.
 */
static u_int64_t
riskie_mem_fetch64(struct vm *vm, u_int64_t addr)
{
	u_int64_t	v;

	PRECOND(vm != NULL);

	riskie_validate_mem_access(vm, addr, 8);

	v = (u_int64_t)vm->mem[addr] |
	    (u_int64_t)vm->mem[addr + 1] << 8 |
	    (u_int64_t)vm->mem[addr + 2] << 16 |
	    (u_int64_t)vm->mem[addr + 3] << 24 |
	    (u_int64_t)vm->mem[addr + 4] << 32 |
	    (u_int64_t)vm->mem[addr + 5] << 40 |
	    (u_int64_t)vm->mem[addr + 6] << 48 |
	    (u_int64_t)vm->mem[addr + 7] << 56;

	return (v);
}

/*
 * Fetch given amount of bits from our memory and return it.
 *
 * The memory access check is done by riskie_mem_fetch64() which is
 * called for each type.
 */
static u_int64_t
riskie_mem_fetch(struct vm *vm, u_int64_t addr, u_int16_t bits)
{
	u_int64_t	v;

	PRECOND(vm != NULL);

	switch (bits) {
	case 8:
		v = riskie_mem_fetch8(vm, addr);
		break;
	case 16:
		v = riskie_mem_fetch16(vm, addr);
		break;
	case 32:
		v = riskie_mem_fetch32(vm, addr);
		break;
	case 64:
		v = riskie_mem_fetch64(vm, addr);
		break;
	default:
		riskie_vm_exception(vm, "%s: unknown bits %u", __func__, bits);
	}

	return (v);
}

/*
 * Store 8 bits at the given address.
 */
static void
riskie_mem_store8(struct vm *vm, u_int64_t addr, u_int64_t value)
{
	riskie_validate_mem_access(vm, addr, 1);

	vm->mem[addr] = (u_int8_t)(value & 0xff);
}

/*
 * Store 16 bits at the given address.
 */
static void
riskie_mem_store16(struct vm *vm, u_int64_t addr, u_int64_t value)
{
	riskie_validate_mem_access(vm, addr, 2);

	vm->mem[addr] = (u_int8_t)(value & 0xff);
	vm->mem[addr + 1] = (u_int8_t)((value >> 8) & 0xff);
}

/*
 * Store 32 bits at the given address.
 */
static void
riskie_mem_store32(struct vm *vm, u_int64_t addr, u_int64_t value)
{
	riskie_validate_mem_access(vm, addr, 4);

	vm->mem[addr] = (u_int8_t)(value & 0xff);
	vm->mem[addr + 1] = (u_int8_t)((value >> 8) & 0xff);
	vm->mem[addr + 2] = (u_int8_t)((value >> 16) & 0xff);
	vm->mem[addr + 3] = (u_int8_t)((value >> 24) & 0xff);
}

/*
 * Store 64 bits at the given address.
 */
static void
riskie_mem_store64(struct vm *vm, u_int64_t addr, u_int64_t value)
{
	riskie_validate_mem_access(vm, addr, 8);

	vm->mem[addr] = (u_int8_t)(value & 0xff);
	vm->mem[addr + 1] = (u_int8_t)((value >> 8) & 0xff);
	vm->mem[addr + 2] = (u_int8_t)((value >> 16) & 0xff);
	vm->mem[addr + 3] = (u_int8_t)((value >> 24) & 0xff);
	vm->mem[addr + 4] = (u_int8_t)((value >> 32) & 0xff);
	vm->mem[addr + 5] = (u_int8_t)((value >> 40) & 0xff);
	vm->mem[addr + 6] = (u_int8_t)((value >> 48) & 0xff);
	vm->mem[addr + 7] = (u_int8_t)((value >> 56) & 0xff);
}

/*
 * Store the given amount of bits into memory.
 */
static void
riskie_mem_store(struct vm *vm, u_int64_t addr, u_int64_t value, size_t bits)
{
	PRECOND(vm != NULL);

	switch (bits) {
	case 8:
		riskie_mem_store8(vm, addr, value);
		break;
	case 16:
		riskie_mem_store16(vm, addr, value);
		break;
	case 32:
		riskie_mem_store32(vm, addr, value);
		break;
	case 64:
		riskie_mem_store64(vm, addr, value);
		break;
	default:
		riskie_vm_exception(vm, "%s: unknown bits %u", __func__, bits);
	}
}

/*
 * Prepare the VM by loading in the image specified in the given path.
 * The image is always loaded at 0x0.
 */
static void
riskie_vm_init(struct vm *vm, const char *path)
{
	int			fd;
	struct stat		st;
	ssize_t			ret;

	PRECOND(vm != NULL);
	PRECOND(path != NULL);

	memset(vm, 0, sizeof(*vm));

	if ((vm->mem = calloc(1, VM_MEM_SIZE)) == NULL)
		err(1, "calloc");

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "open: %s", path);

	if (fstat(fd, &st) == -1)
		err(1, "fstat: %s", path);

	if (st.st_size > VM_MEM_SIZE)
		errx(1, "image doesn't fit in memory");

	if ((ret = read(fd, vm->mem, st.st_size)) == -1)
		err(1, "read");

	if (ret != st.st_size)
		errx(1, "failed to read, only got %zd/%zd", ret, st.st_size);

	vm->regs.x[2] = VM_MEM_SIZE;
	vm->csr[RISCV_CSR_RO_VENDOR_ID] = 0x20231021;

	close(fd);

	riskie_debug("loaded %zd byte image at 0x00000000\n", ret);
}

/*
 * Cleanup the VM data and all its resources.
 */
static void
riskie_vm_cleanup(struct vm *vm)
{
	PRECOND(vm != NULL);

	free(vm->mem);
}

/*
 * An exception occurred, we log it, dump all registers and exit.
 */
static void
riskie_vm_exception(struct vm *vm, const char *fmt, ...)
{
	int		idx;
	va_list		args;

	PRECOND(vm != NULL);

	fprintf(stderr, "vm exception: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	fprintf(stderr, "pc=0x%" PRIx64 "\n", vm->regs.pc - sizeof(u_int32_t));
	for (idx = 0; idx < RISCV_REGISTER_COUNT; idx++)
		fprintf(stderr, "x%d=0x%" PRIx64 "\n", idx, vm->regs.x[idx]);

	riskie_vm_cleanup(vm);

	exit(1);
}

/*
 * Run the VM by executing instructions.
 */
static void
riskie_vm_run(struct vm *vm)
{
	int		running;

	PRECOND(vm != NULL);

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

		riskie_next_instruction(vm);
	}

	riskie_vm_exception(vm, "interrupted by user");
}

/*
 * Validate the current value in the PC register.
 */
static void
riskie_validate_pc(struct vm *vm)
{
	PRECOND(vm != NULL);

	if ((vm->regs.pc % 4) != 0)
		riskie_vm_exception(vm, "unaligned instruction access");

	if (vm->regs.pc + sizeof(u_int32_t) < vm->regs.pc)
		riskie_vm_exception(vm, "pc wrap around");

	if (vm->regs.pc + sizeof(u_int32_t) > VM_MEM_SIZE)
		riskie_vm_exception(vm, "pc out of bounds");
}

/*
 * Validate the given CSR to be a valid one.
 */
static u_int16_t
riskie_validate_csr(struct vm *vm, u_int16_t csr)
{
	if (csr >= RISCV_CSR_COUNT)
		riskie_vm_exception(vm, "csr out of bounds (%u)", csr);

	return (csr);
}

/*
 * Validate the given register to be a valid one.
 */
static u_int8_t
riskie_validate_register(struct vm *vm, u_int8_t reg)
{
	PRECOND(vm != NULL);

	if (reg >= RISCV_REGISTER_COUNT)
		riskie_vm_exception(vm, "reg out of bounds (%u)", reg);

	return (reg);
}

/*
 * Check if we can access memory at addr for the given amount of bytes.
 */
static void
riskie_validate_mem_access(struct vm *vm, u_int64_t addr, size_t bytes)
{
	PRECOND(vm != NULL);

	if (addr >= VM_MEM_SIZE) {
		riskie_vm_exception(vm,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}

	if (addr + bytes < addr)
		riskie_vm_exception(vm, "memory access overflow");

	if (addr + bytes > VM_MEM_SIZE) {
		riskie_vm_exception(vm,
		    "memory access at 0x%" PRIx64 " out of bounds", addr);
	}
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
riskie_instr_shamt(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return ((instr >> 20) & 0x3f);
}

/*
 * Extract the "csr" part of the given instruction. (bits 31 .. 20)
 */
static u_int16_t
riskie_instr_csr(struct vm *vm, u_int32_t instr)
{
	u_int16_t	csr;

	PRECOND(vm != NULL);

	csr = (instr >> 20) & 0xfff;

	return (riskie_validate_csr(vm, csr));
}

/*
 * Extract the "rd" part of the given instruction (bits 11 .. 7).
 * Present in R, I, S, U and J instructions.
 */
static u_int8_t
riskie_instr_rd(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return (riskie_validate_register(vm, (instr >> 7) & 0x1f));
}

/*
 * Extract the "rs1" part of the given instruction (bits 19 .. 15).
 * Present in R, I, S and B instructions.
 */
static u_int8_t
riskie_instr_rs1(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return (riskie_validate_register(vm, (instr >> 15) & 0x1f));
}

/*
 * Extract the "rs2" part of the given instruction (bits 24 .. 20).
 * Present in R, S and B instructions.
 */
static u_int8_t
riskie_instr_rs2(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return (riskie_validate_register(vm, (instr >> 20) & 0x1f));
}

/*
 * Extract the immediate value from a B-type instruction.
 * imm[12|10:5|4:1|11] = inst[31|30:25|11:8|7]
 */
static u_int64_t
riskie_instr_imm_b(struct vm *vm, u_int32_t instr)
{
	u_int32_t		imm;

	PRECOND(vm != NULL);

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
riskie_instr_imm_u(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return (riskie_sign_extend(instr & 0xfffff000, 31));
}

/*
 * Extract the immediate value from a I-type instruction.
 * imm[11:0] = inst[31:20]
 */
static u_int64_t
riskie_instr_imm_i(struct vm *vm, u_int32_t instr)
{
	PRECOND(vm != NULL);

	return (riskie_sign_extend(instr >> 20, 11));
}

/*
 * Extract the immediate value from a J-type instruction.
 * imm[20|10:1|11|19:12] = inst[31|30:21|20|19:12]
 */
static u_int64_t
riskie_instr_imm_j(struct vm *vm, u_int32_t instr)
{
	size_t			idx;
	u_int32_t		imm;

	PRECOND(vm != NULL);

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
riskie_instr_imm_s(struct vm *vm, u_int32_t instr)
{
	u_int32_t		imm;

	PRECOND(vm != NULL);

	imm = ((instr & 0xfe000000) >> 20) | ((instr >> 7) & 0x1f);

	return (riskie_sign_extend(imm, 11));
}

/*
 * Causes an exception if the given CSR is not writable.
 */
static void
riskie_csr_writable(struct vm *vm, u_int16_t csr)
{
	PRECOND(vm != NULL);

	if (csr >= RISCV_CSR_RO_VENDOR_ID && csr <= RISCV_CSR_RO_HART_ID)
		riskie_vm_exception(vm, "attempted write to csr %u", csr);
}

/*
 * Fetch the next instruction, decode it and execute it.
 */
static void
riskie_next_instruction(struct vm *vm)
{
	u_int32_t	instr;
	u_int8_t	opcode;

	PRECOND(vm != NULL);

	riskie_validate_pc(vm);
	memcpy(&instr, &vm->mem[vm->regs.pc], sizeof(instr));
	vm->regs.pc += sizeof(instr);

	vm->regs.x[0] = 0;
	opcode = instr & 0x7f;

	switch (opcode) {
	case RISCV_RV32I_OPCODE_LOAD:
		riskie_opcode_load(vm, instr);
		break;
	case RISCV_RV32I_OPCODE_STORE:
		riskie_opcode_store(vm, instr);
		break;
	case RISCV_RV32I_OPCODE_SYSTEM:
		riskie_opcode_system(vm, instr);
		break;
	case RISCV_RV32I_OPCODE_B_TYPE:
		riskie_opcode_b_type(vm, instr);
		break;
	case RISCV_RV32I_OPCODE_I_TYPE:
		riskie_opcode_i_type_32(vm, instr);
		break;
	case RISCV_RV64I_OPCODE_I_TYPE:
		riskie_opcode_i_type_64(vm, instr);
		break;
	case RISCV_RV32I_OPCODE_R_TYPE:
		riskie_opcode_r_type_32(vm, instr);
		break;
	case RISCV_RV64I_OPCODE_R_TYPE:
		riskie_opcode_r_type_64(vm, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_AUIPC:
		riskie_opcode_auipc(vm, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_LUI:
		riskie_opcode_lui(vm, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JAL:
		riskie_opcode_jal(vm, instr);
		break;
	case RISCV_RV32I_INSTRUCTION_JALR:
		riskie_opcode_jalr(vm, instr);
		break;
	default:
		riskie_vm_exception(vm, "illegal instruction 0x%08x", instr);
	}
}

/*
 * A load instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
riskie_opcode_load(struct vm *vm, u_int32_t instr)
{
	u_int8_t	rd, rs1;
	u_int64_t	off, addr;
	u_int32_t	funct3, v32;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	off = riskie_instr_imm_i(vm, instr);

	addr = vm->regs.x[rs1] + (int64_t)off;

	riskie_debug("LOAD, funct3=0x%02x, rd=%u, rs1=%u, addr=0x%" PRIx64 "\n",
	    funct3, rd, rs1, addr);

	riskie_debug("    <- reg.%u = %" PRIx64 "\n", rs1, vm->regs.x[rs1]);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_LB:
		v32 = riskie_mem_fetch(vm, addr, 8);
		vm->regs.x[rd] = riskie_sign_extend(v32, 7);
		break;
	case RISCV_RV32I_INSTRUCTION_LH:
		v32 = riskie_mem_fetch(vm, addr, 16);
		vm->regs.x[rd] = riskie_sign_extend(v32, 15);
		break;
	case RISCV_RV32I_INSTRUCTION_LW:
		v32 = riskie_mem_fetch(vm, addr, 32);
		vm->regs.x[rd] = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV32I_INSTRUCTION_LBU:
		vm->regs.x[rd] = riskie_mem_fetch(vm, addr, 8);
		break;
	case RISCV_RV32I_INSTRUCTION_LHU:
		vm->regs.x[rd] = riskie_mem_fetch(vm, addr, 16);
		break;
	case RISCV_RV32I_INSTRUCTION_LWU:
		vm->regs.x[rd] = riskie_mem_fetch(vm, addr, 32);
		break;
	case RISCV_RV64I_INSTRUCTION_LD:
		vm->regs.x[rd] = riskie_mem_fetch(vm, addr, 64);
		break;
	default:
		riskie_vm_exception(vm, "illegal load 0x%08x", instr);
	}

	riskie_debug("    -> reg.%u = %" PRIx64 "\n", rd, vm->regs.x[rd]);
}

/*
 * A store instruction was found, check funct3 to figure out which
 * one and execute it.
 */
static void
riskie_opcode_store(struct vm *vm, u_int32_t instr)
{
	u_int32_t	funct3;
	u_int8_t	rs1, rs2;
	u_int64_t	off, addr;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;

	rs1 = riskie_instr_rs1(vm, instr);
	rs2 = riskie_instr_rs2(vm, instr);
	off = riskie_instr_imm_s(vm, instr);

	addr = vm->regs.x[rs1] + (int64_t)off;

	riskie_debug("STORE, funct3=0x%02x, rs1=%u, rs2=%u, "
	    "addr=0x%" PRIx64 "\n", funct3, rs1, rs2, addr);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_SB:
		riskie_mem_store(vm, addr, vm->regs.x[rs2], 8);
		break;
	case RISCV_RV32I_INSTRUCTION_SH:
		riskie_mem_store(vm, addr, vm->regs.x[rs2], 16);
		break;
	case RISCV_RV32I_INSTRUCTION_SW:
		riskie_mem_store(vm, addr, vm->regs.x[rs2], 32);
		break;
	case RISCV_RV64I_INSTRUCTION_SD:
		riskie_mem_store(vm, addr, vm->regs.x[rs2], 64);
		break;
	default:
		riskie_vm_exception(vm, "illegal store 0x%08x", instr);
	}
}

/*
 * A system instruction was found, check funct3 and execute the
 * correct one.
 */
static void
riskie_opcode_system(struct vm *vm, u_int32_t instr)
{
	u_int16_t	csr;
	u_int32_t	funct3;
	u_int8_t	rd, rs1;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	csr = riskie_instr_csr(vm, instr);

	riskie_debug("SYSTEM, funct3=0x%02x, rd=%u, rs1=%u, csr=0x%02x",
	    funct3, rd, rs1, csr);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRC:
		rs1 = vm->regs.x[rs1];
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		rs1 = rs1 & 0xf;
		break;
	}

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_ECALL:
		/* big bunch of nothing. */
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRW:
	case RISCV_RV32I_INSTRUCTION_CSRRWI:
		/*
		 * This counts as atomic unless we start doing
		 * multiprocess approaches for the future harts.
		 */
		riskie_csr_writable(vm, csr);
		if (rd != 0)
			vm->regs.x[rd] = vm->csr[csr];
		vm->csr[csr] = rs1;
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRS:
	case RISCV_RV32I_INSTRUCTION_CSRRSI:
		vm->regs.x[rd] = vm->csr[csr];
		if (rs1 != 0) {
			riskie_csr_writable(vm, csr);
			vm->csr[csr] |= rs1;
		}
		break;
	case RISCV_RV32I_INSTRUCTION_CSRRC:
	case RISCV_RV32I_INSTRUCTION_CSRRCI:
		vm->regs.x[rd] = vm->csr[csr];
		if (rs1 != 0) {
			riskie_csr_writable(vm, csr);
			vm->csr[csr] &= ~rs1;
		}
		break;
	default:
		riskie_vm_exception(vm, "illegal system 0x%08x", instr);
	}
}

/*
 * Control transfer instructions, conditional branches.
 */
static void
riskie_opcode_b_type(struct vm *vm, u_int32_t instr)
{
	u_int64_t	imm;
	int		branch;
	u_int32_t	funct3;
	u_int8_t	rs1, rs2;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;

	rs1 = riskie_instr_rs1(vm, instr);
	rs2 = riskie_instr_rs2(vm, instr);
	imm = riskie_instr_imm_b(vm, instr);

	riskie_debug("B-TYPE, funct3=0x%02x, rs1=%u, rs2=%u, "
	    "imm=0x%" PRIx64 "\n", funct3, rs1, rs2, imm);

	branch = 0;

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_BEQ:
		branch = vm->regs.x[rs1] == vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BNE:
		branch = vm->regs.x[rs1] != vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BLT:
		branch = (int64_t)vm->regs.x[rs1] < (int64_t)vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BGE:
		branch = (int64_t)vm->regs.x[rs1] >= (int64_t)vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BLTU:
		branch = vm->regs.x[rs1] < vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_BGEU:
		branch = vm->regs.x[rs1] >= vm->regs.x[rs2];
		break;
	default:
		riskie_vm_exception(vm, "illegal b-type 0x%08x", instr);
	}

	if (branch) {
		vm->regs.pc = (vm->regs.pc - sizeof(instr)) + (int64_t)imm;
		riskie_validate_pc(vm);
		riskie_debug("branched to 0x%" PRIx64 "\n", vm->regs.pc);
	}
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
riskie_opcode_i_type_32(struct vm *vm, u_int32_t instr)
{
	u_int8_t	rd, rs1;
	u_int64_t	imm, sbit;
	u_int32_t	funct3, funct7, shamt;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	imm = riskie_instr_imm_i(vm, instr);
	shamt = riskie_instr_shamt(vm, instr);

	riskie_debug("I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, "
	    "rd=%u, rs1=%u, imm=%" PRId64 "\n", funct3, funct7, rd,
	    rs1, (int64_t)imm);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_ADDI:
		vm->regs.x[rd] = vm->regs.x[rs1] + (int64_t)imm;
		break;
	case RISCV_RV32I_INSTRUCTION_XORI:
		vm->regs.x[rd] = vm->regs.x[rs1] ^ imm;
		break;
	case RISCV_RV32I_INSTRUCTION_ANDI:
		vm->regs.x[rd] = vm->regs.x[rs1] & imm;
		break;
	case RISCV_RV32I_INSTRUCTION_ORI:
		vm->regs.x[rd] = vm->regs.x[rs1] | imm;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTI:
		if ((int64_t)vm->regs.x[rs1] < (int64_t)imm)
			vm->regs.x[rd] = 1;
		else
			vm->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTIU:
		if (vm->regs.x[rs1] < imm)
			vm->regs.x[rd] = 1;
		else
			vm->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLLI:
		vm->regs.x[rd] = vm->regs.x[rs1] << shamt;
		break;
	case RISCV_RV32I_FUNCTION_SRI:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_SRLI:
			vm->regs.x[rd] = vm->regs.x[rs1] >> imm;
			break;
		case RISCV_RV32I_INSTRUCTION_SRAI:
			sbit = vm->regs.x[rs1] >> 63;
			vm->regs.x[rd] = vm->regs.x[rs1] >> imm;
			vm->regs.x[rd] |= sbit << 63;
			break;
		default:
			riskie_vm_exception(vm, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_vm_exception(vm, "illegal i-type 0x%08x", instr);
	}

	riskie_debug("   -> reg.%u = %" PRIx64 "\n", rd, vm->regs.x[rd]);
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
riskie_opcode_i_type_64(struct vm *vm, u_int32_t instr)
{
	u_int64_t	imm;
	u_int8_t	rd, rs1;
	u_int32_t	funct3, funct7, shamt, v32, sbit;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	imm = riskie_instr_imm_i(vm, instr);
	shamt = riskie_instr_shamt(vm, instr);

	riskie_debug("I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, imm=%" PRId64 "\n", funct3, funct7, rd, rs1, (int64_t)imm);

	switch (funct3) {
	case RISCV_RV64I_INSTRUCTION_ADDIW:
		v32 = (u_int32_t)vm->regs.x[rs1] + (int32_t)imm;
		vm->regs.x[rd] = riskie_sign_extend(v32, 31);
		break;
	case RISCV_RV64I_INSTRUCTION_SLLIW:
		vm->regs.x[rd] = (u_int32_t)vm->regs.x[rs1] << shamt;
		break;
	case RISCV_RV64I_FUNCTION_SRIW:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_SRLIW:
			v32 = vm->regs.x[rs1];
			vm->regs.x[rd] = v32 >> imm;
			break;
		case RISCV_RV64I_INSTRUCTION_SRAIW:
			v32 = vm->regs.x[rs1];
			sbit = v32 >> 31;
			vm->regs.x[rd] = v32 >> imm;
			vm->regs.x[rd] |= sbit << 31;
			break;
		default:
			riskie_vm_exception(vm, "illegal sri 0x%08x", instr);
		}
		break;
	default:
		riskie_vm_exception(vm, "illegal i-type 0x%08x", instr);
	}

	riskie_debug("   -> reg.%u = %" PRIx64 "\n", rd, vm->regs.x[rd]);
}

/*
 * The register to register instructions as part of the
 * "Integer Computational Instructions" instruction set.
 *
 * Note that while these are part of the RV32I instruction set, they
 * operate on XLEN bits, and thus 64-bit.
 */
static void
riskie_opcode_r_type_32(struct vm *vm, u_int32_t instr)
{
	u_int64_t	sbit;
	u_int8_t	rd, rs1, rs2;
	u_int32_t	funct3, funct7;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	rs2 = riskie_instr_rs2(vm, instr);

	riskie_debug("I-TYPE-RV32I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV32I_INSTRUCTION_OR:
		vm->regs.x[rd] = vm->regs.x[rs1] | vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_XOR:
		vm->regs.x[rd] = vm->regs.x[rs1] ^ vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_AND:
		vm->regs.x[rd] = vm->regs.x[rs1] & vm->regs.x[rs2];
		break;
	case RISCV_RV32I_INSTRUCTION_SLL:
		vm->regs.x[rd] = vm->regs.x[rs1] << (vm->regs.x[rs2] & 0x3f);
		break;
	case RISCV_RV32I_INSTRUCTION_SLT:
		if ((int64_t)vm->regs.x[rs1] < (int64_t)vm->regs.x[rs2])
			vm->regs.x[rd] = 1;
		else
			vm->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_INSTRUCTION_SLTU:
		if (vm->regs.x[rs1] < vm->regs.x[rs2])
			vm->regs.x[rd] = 1;
		else
			vm->regs.x[rd] = 0;
		break;
	case RISCV_RV32I_FUNCTION_ADD_SUB:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_ADD:
			vm->regs.x[rd] = vm->regs.x[rs1] + vm->regs.x[rs2];
			break;
		case RISCV_RV32I_INSTRUCTION_SUB:
			vm->regs.x[rd] = vm->regs.x[rs1] - vm->regs.x[rs2];
			break;
		default:
			riskie_vm_exception(vm, "illegal addsub 0x%08x", instr);
		}
		break;
	case RISCV_RV32I_FUNCTION_SR:
		switch (funct7) {
		case RISCV_RV32I_INSTRUCTION_SRL:
			vm->regs.x[rd] = vm->regs.x[rs1] >>
			    (vm->regs.x[rs2] & 0x3f);
			break;
		case RISCV_RV32I_INSTRUCTION_SRA:
			sbit = vm->regs.x[rs1] >> 63;
			vm->regs.x[rd] = vm->regs.x[rs1] >>
			    (vm->regs.x[rs2] & 0x3f);
			vm->regs.x[rd] |= sbit << 63;
			break;
		default:
			riskie_vm_exception(vm, "illegal sr 0x%08x", instr);
		}
		break;
	default:
		riskie_vm_exception(vm, "illegal r-type 0x%08x", instr);
	}

	riskie_debug("   -> reg.%u = %" PRIx64 "\n", rd, vm->regs.x[rd]);
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
riskie_opcode_r_type_64(struct vm *vm, u_int32_t instr)
{
	u_int64_t	sbit;
	u_int8_t	rd, rs1, rs2;
	u_int32_t	funct3, funct7, v32;

	PRECOND(vm != NULL);

	funct3 = (instr >> 12) & 0x7;
	funct7 = (instr >> 25) & 0x7f;

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	rs2 = riskie_instr_rs2(vm, instr);

	riskie_debug("I-TYPE-RV64I, funct3=0x%02x, funct7=0x%02x, rd=%u, "
	    "rs1=%u, rs2=%u\n", funct3, funct7, rd, rs1, rs2);

	switch (funct3) {
	case RISCV_RV64I_INSTRUCTION_SLLW:
		vm->regs.x[rd] = (u_int32_t)(vm->regs.x[rs1] <<
		    (vm->regs.x[rs2] & 0xf));
		break;
	case RISCV_RV64I_FUNCTION_ADD_SUB:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_ADDW:
			v32 = vm->regs.x[rs1] + vm->regs.x[rs2];
			vm->regs.x[rd] = riskie_sign_extend(v32, 31);
			break;
		case RISCV_RV64I_INSTRUCTION_SUBW:
			vm->regs.x[rd] = (int32_t)vm->regs.x[rs1] -
			    (int32_t)vm->regs.x[rs2];
			break;
		default:
			riskie_vm_exception(vm, "illegal addsub 0x%08x", instr);
		}
		break;
	case RISCV_RV64I_FUNCTION_SRW:
		switch (funct7) {
		case RISCV_RV64I_INSTRUCTION_SRLW:
			v32 = vm->regs.x[rs1];
			vm->regs.x[rd] = v32 >> (vm->regs.x[rs2] & 0xf);
			break;
		case RISCV_RV64I_INSTRUCTION_SRAW:
			v32 = vm->regs.x[rs1];
			sbit = v32 >> 31;
			vm->regs.x[rd] = v32 >> (vm->regs.x[rs2] & 0xf);
			vm->regs.x[rd] |= sbit << 31;
			break;
		default:
			riskie_vm_exception(vm, "illegal sri 0x%08x", instr);
		}
	default:
		riskie_vm_exception(vm, "illegal r-type 0x%08x", instr);
	}

	riskie_debug("   -> reg.%u = %" PRIx64 "\n", rd, vm->regs.x[rd]);
}

/*
 * The AUIPC instruction:
 *	Add upper immediate to PC. Add 12 low order zero bits to the
 *	20-bit immediate, sign-extend it to 64-bits and add it to pc
 *	and stores the result in rd.
 */
static void
riskie_opcode_auipc(struct vm *vm, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	imm;

	PRECOND(vm != NULL);

	rd = riskie_instr_rd(vm, instr);
	imm = riskie_instr_imm_u(vm, instr);

	vm->regs.x[rd] = (vm->regs.pc - sizeof(instr)) + (int64_t)imm;

	riskie_debug("AUIPC, rd=%u, value=%" PRIx64 "\n", rd, vm->regs.x[rd]);
}

/*
 * The LUI instruction:
 *	Load upper immediate. Add 12 low order zero bits to the
 *	20-bit immediate, sign-extend it to 64-bits and write the
 *	result to rd.
 */
static void
riskie_opcode_lui(struct vm *vm, u_int32_t instr)
{
	u_int8_t	rd;

	PRECOND(vm != NULL);

	rd = riskie_instr_rd(vm, instr);
	riskie_debug("LUI, rd=%u, value=%" PRIx64 "\n", rd, vm->regs.x[rd]);

	vm->regs.x[rd] = riskie_sign_extend(instr & 0xfffff000, 31);
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
riskie_opcode_jal(struct vm *vm, u_int32_t instr)
{
	u_int8_t	rd;
	u_int64_t	off;

	PRECOND(vm != NULL);

	rd = riskie_instr_rd(vm, instr);
	off = riskie_instr_imm_j(vm, instr);

	riskie_debug("JAL, rd=%u, off=%" PRId64 "\n", rd, (int64_t)off);

	vm->regs.x[rd] = vm->regs.pc;
	vm->regs.pc = (vm->regs.pc - sizeof(instr)) + (int64_t)off;

	riskie_validate_pc(vm);
}

/*
 * The JALR instruction:
 *	The indirect jump instruction JALR (jump and link register) uses the
 *	I-type encoding. The target address is obtained by adding the 12-bit
 *	signed I-immediate to the register rs1, then setting the
 *	least-signiﬁcant bit of the result to zero.
 */
static void
riskie_opcode_jalr(struct vm *vm, u_int32_t instr)
{
	u_int64_t	off;
	u_int8_t	rs1, rd;

	PRECOND(vm != NULL);

	rd = riskie_instr_rd(vm, instr);
	rs1 = riskie_instr_rs1(vm, instr);
	off = riskie_instr_imm_i(vm, instr);

	riskie_debug("JALR, rd=%u, rs1=%u, off=%" PRIx64 "\n", rd, rs1, off);

	vm->regs.x[rd] = vm->regs.pc;
	vm->regs.pc = (rs1 + off) & ~0x1;

	riskie_validate_pc(vm);
}
