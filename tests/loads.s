#
# Test several LOAD instructions.
#

.globl test_entry
.type test_entry, @function

test_entry:
	# return address (x1)
	li ra, 0xdeadbeef

	# stack pointer (x2)
	li sp, 0xbadf00d

	# global pointer (x3)
	li gp, 0xcafebabe

	# thread pointer (x4)
	li tp, 18446744073709551615

	# temporary registers (x5 - x7)
	li t0, 18446744073709551614
	li t1, 4294967295
	li t2, 65535

	# callee saved registers (x8 - x9)
	li s0, 0xa0
	li s1, 0xa1

	# argument registers (x10 - x17)
	li a0, 0xff
	li a1, 1
	li a2, 2
	li a3, 3
	li a4, 4
	li a5, 5
	li a6, 6
	li a7, 7

	# Test all load instructions individually.
	lb a0,0x0(zero)
	lh a0,0x0(zero)
	lw a0,0x0(zero)
	ld a0,0x0(zero)

	lbu a0,0x0(zero)
	lhu a0,0x0(zero)
	lwu a0,0x0(zero)

	li a1, 10
	slti a0, a1, 11
