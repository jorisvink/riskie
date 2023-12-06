# riskie Makefile

CC?=cc
OBJDIR?=obj
BIN=riskie

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-g

SRC=	src/riskie.c \
	src/config.c \
	src/mem.c \
	src/hart.c \
	src/instr.c \
	src/peripheral.c \
	src/utils.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-DPLATFORM_DARWIN
else ifeq ("$(OSNAME)", "openbsd")
	CFLAGS+=-DPLATFORM_OPENBSD
endif

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

all: $(BIN)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)
	$(MAKE) -C tests clean

.PHONY: all clean force
