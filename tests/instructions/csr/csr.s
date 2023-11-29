#
# Test CSR instructions.
#

.globl test_entry
.type test_entry, @function

test_entry:
	csrr a0, mvendorid

	li t0, 0xdeadbeef
	csrw mtvec, t0

	csrr a1, mtvec

	li t0, 0x800
	csrw mip, t0
