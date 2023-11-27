# riskie tests Makefile

OBJDIR?=obj

AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
OBJCOPY=riscv64-unknown-elf-objcopy

TESTS=		$(OBJDIR)/loads.bin

all: $(OBJDIR) $(TESTS)

$(OBJDIR)/loads.bin: $(OBJDIR) loads.s link.ld
	$(AS) -march=rv64i -c loads.s -o $(OBJDIR)/loads.o
	$(LD) $(OBJDIR)/loads.o -T link.ld -o $(OBJDIR)/loads.elf
	$(OBJCOPY) -O binary $(OBJDIR)/loads.elf $(OBJDIR)/loads.bin

$(OBJDIR):
	@mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR)
