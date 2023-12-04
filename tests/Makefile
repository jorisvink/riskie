# riskie tests Makefile

TEST_ROOT=$(shell pwd)
OBJDIR?=$(TEST_ROOT)/obj

export TEST_ROOT
export OBJDIR

AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
OBJCOPY=riscv64-unknown-elf-objcopy

TESTS=	instructions/atomics \
	instructions/csr \
	instructions/loads \
	instructions/interrupts \
	instructions/timer \
	instructions/umode

all: $(OBJDIR)
	@for test in $(TESTS); do			\
		$(MAKE) -C $$test;			\
	done

$(OBJDIR):
	@mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR)
