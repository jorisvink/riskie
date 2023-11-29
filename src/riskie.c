/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/signal.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static void	riskie_trap_signal(int);
static void	riskie_sig_handler(int);

/* Last received signal. */
static volatile sig_atomic_t	sig_recv = -1;

/* Are we running with debug mode or not. */
int		riskie_debug = 0;

static void
usage(void)
{
	fprintf(stderr, "Usage: riskie [-d] [binary]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		ch;
	struct hart	ht;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			riskie_debug = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	riskie_trap_signal(SIGINT);

	riskie_hart_init(&ht, argv[0], 0);
	riskie_hart_run(&ht);
	riskie_hart_cleanup(&ht);

	return (0);
}

/*
 * Returns the last received signal and sets sig_recv back to -1.
 */
int
riskie_last_signal(void)
{
	int		sig;

	sig = sig_recv;
	sig_recv = -1;

	return (sig);
}

/*
 * Sign extend the 32-bit value to a 64-bit value.
 */
u_int64_t
riskie_sign_extend(u_int32_t value, u_int8_t bit)
{
	u_int32_t	idx;
	u_int64_t	extended;

	PRECOND(bit <= 32);

	if (value & ((u_int32_t)1 << bit)) {
		extended = value;
		for (idx = bit + 1; idx <= 63; idx++)
			extended |= ((u_int64_t)1 << idx);
		return (extended);
	}

	return ((u_int64_t)value);
}

/*
 * Output debug info on stdout if the debug flag was given.
 */
void
riskie_log(struct hart *ht, const char *fmt, ...)
{
	va_list		args;

	PRECOND(ht != NULL);
	PRECOND(fmt != NULL);

	if (riskie_debug == 0)
		return;

	printf("[%02d] ", (u_int8_t)ht->csr[RISCV_CSR_MRO_HART_ID]);

	switch (ht->mode) {
	case RISKIE_HART_MACHINE_MODE:
		printf("[M] ");
		break;
	case RISKIE_HART_USER_MODE:
		printf("[U] ");
		break;
	default:
		printf("[?] ");
		break;
	}

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/*
 * Sad juju happened and riskie must die.
 */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	fprintf(stderr, "fatal: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
	exit(1);
}

/*
 * Our signal handler.
 */
static void
riskie_sig_handler(int sig)
{
	sig_recv = sig;
}

/*
 * Catch the given signal by letting it call our signal handler.
 */
static void
riskie_trap_signal(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = riskie_sig_handler;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset");

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction");
}
