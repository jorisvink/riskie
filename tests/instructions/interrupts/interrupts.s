#
# Interrupt tests
#

.globl test_entry
.type test_entry, @function

test_entry:
	la t0, trap
	csrw mtvec, t0

	li t0, 8
	csrw mstatus, t0

	li t0, 8
	csrw mie, t0

	ecall
	j end

.globl trap
.type trap, @function

trap:
	li t0, 0
loop:
	addw t0,t0,1
	mret

end:
