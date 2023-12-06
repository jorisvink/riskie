#
# Timer test
#

.equ MTIME,	0xf0001000
.equ MTIMECMP,	0xf0002000

.equ COUNT, 0x80002000

.globl test_entry
.type test_entry, @function

test_entry:
	# Setup where our trap function is.
	la t0, trap
	csrw mtvec, t0

	# Enable interrupts globally.
	li t0, 0x8
	csrw mstatus, t0

	# Enable MTI (timer interrupts)
	li t0, 0x80
	csrw mie, t0

	# Read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)
loop:
	wfi

	li t0, COUNT
	ld t1, 0(t0)

	li t0, 4
	beq t0, t1, generate_env_call
	j loop

generate_env_call:
	ecall
	j loop

.globl trap
.type trap, @function

trap:
	csrr t0, mcause

	li t1, 7
	beq t0, t1, timer_trap

	li t1, 11
	beq t0, t1, environment_call

timer_trap:
	# Read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	li t0, COUNT
	ld t1, 0(t0)

	add t1, t1, 1
	sd t1, 0(t0)

	j trap_return

environment_call:
	ebreak
	mret

trap_return:
	mret
