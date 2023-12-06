# peripherals Makefile

CC?=cc
OBJDIR?=obj

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/riskie/peripherals

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -I../include
CFLAGS+=-g

PERIPHERALS=	$(OBJDIR)/uart8250.so

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

all: $(PERIPHERALS)

$(PERIPHERALS): $(OBJDIR)

install: $(PERIPHERALS)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/uart8250.so: uart8250.c
	$(CC) $(CFLAGS) -shared $< -o $@

clean:
	rm -rf $(OBJDIR) $(PERIPHERALS)

.PHONY: all clean force
