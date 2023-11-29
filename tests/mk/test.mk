#
# Gets pulled in to generate the make target for the given test.
#

AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
OBJCOPY=riscv64-unknown-elf-objcopy

$(OBJDIR)/$(test-name).bin: $(test-source) $(TEST_ROOT)/misc/link.ld
	$(AS) -march=rv64i -c $(test-source) -o $(OBJDIR)/$(test-source).o
	$(LD) $(OBJDIR)/$(test-source).o -T $(TEST_ROOT)/misc/link.ld \
	    -o $(OBJDIR)/$(test-name).elf
	$(OBJCOPY) -O binary $(OBJDIR)/$(test-name).elf \
	    $(OBJDIR)/$(test-name).bin
