# riskie tests Makefile

OBJDIR?=obj

AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
OBJCOPY=riscv64-unknown-elf-objcopy

TESTS=		$(OBJDIR)/loads.bin $(OBJDIR)/csr.bin

all: $(OBJDIR) $(TESTS)

$(OBJDIR)/loads.bin: $(OBJDIR) loads.s link.ld
	$(AS) -march=rv64i -c loads.s -o $(OBJDIR)/loads.o
	$(LD) $(OBJDIR)/loads.o -T link.ld -o $(OBJDIR)/loads.elf
	$(OBJCOPY) -O binary $(OBJDIR)/loads.elf $(OBJDIR)/loads.bin

$(OBJDIR)/csr.bin: $(OBJDIR) csr.s link.ld
	$(AS) -march=rv64i -c csr.s -o $(OBJDIR)/csr.o
	$(LD) $(OBJDIR)/csr.o -T link.ld -o $(OBJDIR)/csr.elf
	$(OBJCOPY) -O binary $(OBJDIR)/csr.elf $(OBJDIR)/csr.bin

$(OBJDIR):
	@mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR)
