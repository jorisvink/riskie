#
# Test CSR instructions.
#

.globl test_entry
.type test_entry, @function

test_entry:
	csrr a0, mvendorid
