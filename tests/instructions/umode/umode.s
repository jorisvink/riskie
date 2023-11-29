#
# Test heading into U-mode.
#

.equ MTIME,	0xf0001000
.equ MTIMECMP,	0xf0002000

.globl test_entry
.globl umode_entry

.type test_entry, @function
.type trap_entry, @function
.type umode_entry, @function

test_entry:
	# our trap handler
	la t0, trap_entry
	csrw mtvec, t0

	# enable MTI
	li t0, 0x80
	csrw mie, t0

	# read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	# set mepc to umode_entry
	la t0, umode_entry
	csrw mepc, t0

	# enable interrupts
	li t0, 8
	csrs mstatus, t0

	# Move to user-mode
	mret

trap_entry:
	# read mtime into t0, add 1 second and set timecmp
	li t0, MTIME
	ld t1, 0(t0)

	li t2, 1000000000
	add t1, t1, t2
	li t0, MTIMECMP
	sd t1, 0(t0)

	mret

umode_entry:
	wfi
	j umode_entry
