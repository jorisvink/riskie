#
# M tests.
#

.globl test_entry
.type test_entry, @function

test_entry:
	li t0, 8
	li t1, 2
	mulw t3, t0, t1

	li t1, -1
	mulw t4, t3, t1

	li t1, -2
	divw t5, t4, t1
