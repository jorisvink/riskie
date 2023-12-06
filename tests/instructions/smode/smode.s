#
# Setup a timer interrupt that ticks every 1 second and is
# delegated to S-mode.
#

.equ MTIME,	0xf0001000
.equ MTIMECMP,	0xf0002000

.globl test_entry
.globl umode_entry

.type test_entry, @function
.type trap_entry, @function
.type umode_entry, @function

test_entry:
	# our M-mode trap handler
	la t0, trap
	csrw mtvec, t0

	# our S-mode trap handler
	la t0, smode_trap
	csrw stvec, t0

	# enable MTI
	li t0, 0x80
	csrw mie, t0

	# delegate MTI to S-mode
	li t0, 0x80
	csrs mideleg, t0

	# read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	# set mepc to smode_entry
	la t0, smode_entry
	csrw mepc, t0

	# enable interrupts
	li t0, 8
	csrs mstatus, t0

	# set MPP to S-mode
	li t0, 0x800
	csrs mstatus, t0

	# Move to s-mode
	mret

# This is the M-mode trap.
trap:
	# read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	# jump over instruction that caused the trap
	csrr a4, mepc
	addi a4, a4, 4
	csrw mepc, a4

	mret

# This is the S-mode trap.
smode_trap:
	# do a trap into m-mode
	ecall
	sret

smode_entry:
	j smode_entry
