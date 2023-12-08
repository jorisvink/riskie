#
# Setup a machine timer interrupt that ticks every 1 second and is
# delegated to supervisor mode.
#
# We keep the main loop in user mode.
#

.equ MTIME,	0xf0001000
.equ MTIMECMP,	0xf0002000
.equ SERIAL,	0x90000000
.equ COUNT,	0x800f0000

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
	la t0, strap
	csrw stvec, t0

	# delegate STI to S-mode
	li t0, 0x20
	csrs mideleg, t0

	# enable MTI and STI
	li t0, 0xa0
	csrw mie, t0

	# read mtime into t0, add 0.1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 100000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	# set mepc to umode
	la t0, umode
	csrw mepc, t0

	# enable M-mode interrupts
	li t0, 0x08
	csrs mstatus, t0

	# enable S-mode interrupts
	li t0, 0x02
	csrs mstatus, t0

	# Move to umode
	mret

# This is the M-mode trap.
trap:
	li t0, 5
	csrr t1, mcause
	beq t0, t1, memory_bad

	# read mtime into t0, add 0.1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 100000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	# increment COUNT, if COUNT reaches 1, raise STI and reset COUNT
	li t0, COUNT
	ld t1, 0(t0)
	addi t1, t1, 1
	sd t1, 0(t0)

	li t0, 10
	bne t1, t0, trap_do_mret

	li t0, COUNT
	li t1, 0
	sd t1, 0(t0)

	# raise STI
	li t0, 0x20
	csrs mip, t0

trap_do_mret:
	mret

# This is the S-mode trap.
strap:
	li x0, 0xcafebabe

	# clear STI
	li t0, 0x20
	csrc sip, t0

	li x0, 0xbadc0ffee
	sret

umode:
	j umode

memory_bad:
	csrw mie, 0
	j memory_bad
