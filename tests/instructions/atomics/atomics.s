#
# Tests lr/sc mostly.
#

.globl test_entry
.type test_entry, @function

.equ MARK, 0x800e0000

test_entry:
	li a0, MARK
	li a1, 0
	li a2, 0xcafebabe

	lr.d t0, (a0)
	bne t0, a1, fail

#	li a3, -1
#	sb a3, 0x0(a0)

	sc.w t0, a2, (a0)
	beq t0, a1, done

fail:
	li t0, 0xbadc0de
	j nope

done:
	li t0, 0xf00df00d

nope:
