# riskie testbed Makefile

OBJDIR?=obj

KERNEL=kernel.elf

AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
CC=riscv64-unknown-elf-gcc
OBJCOPY=riscv64-unknown-elf-objcopy

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+=-Wtype-limits -fno-common -g -ffreestanding -nostdlib
CFLAGS+=-march=rv64i -mabi=lp64

C_SRC=		src/riscv.c
ASM_SRC=

C_OBJS=		$(C_SRC:src/%.c=$(OBJDIR)/%.o)
ASM_OBJS=	$(ASM_SRC:src/%.s=$(OBJDIR)/%.o)
OBJS=		$(C_OBJS) $(ASM_OBJS)

all: $(KERNEL)

debug: $(KERNEL)
	$(GDB) $(KERNEL)

$(KERNEL): $(OBJDIR) $(OBJS) src/link.ld
	$(LD) $(OBJS) -T src/link.ld -o $(KERNEL)
	$(OBJCOPY) -O binary $(KERNEL) kernel.bin

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: src/%.s
	$(AS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(KERNEL) kernel.bin
