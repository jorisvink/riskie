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
#include <sys/poll.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static void	riskie_trap_signal(int);
static void	riskie_sig_handler(int);

/* The global context. */
struct soc	*soc = NULL;

/* Last received signal. */
static volatile sig_atomic_t	sig_recv = -1;

/* The last input from stdin. */
static int			last_input = -1;

static void
usage(void)
{
	fprintf(stderr, "Usage: riskie [-c config] [-d] [binary]\n");
	exit(1);
}

/*
 * Riskie business.
 */
int
main(int argc, char *argv[])
{
	struct pollfd		pfd;
	ssize_t			ret;
	u_int8_t		input;
	const char		*config;
	int			ch, running, sig;

	config = NULL;

	/* XXX - place in shm later when doing multiple hart procs. */
	if ((soc = calloc(1, sizeof(*soc))) == NULL)
		fatal("calloc: failed");

	soc->mem.size = RISKIE_DEFAULT_MEM_SIZE;
	soc->mem.base = RISKIE_DEFAULT_MEM_BASE_ADDR;

	while ((ch = getopt(argc, argv, "c:d")) != -1) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'd':
			soc->debug = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	riskie_peripheral_init();

	if (config != NULL)
		riskie_config_load(config);

	riskie_mem_init(argv[0]);
	riskie_hart_init(&soc->ht, soc->mem.base, 0);

	running = 1;
	pfd.events = POLLIN;
	pfd.fd = STDIN_FILENO;

	riskie_term_setup();
	riskie_trap_signal(SIGINT);

	while (running) {
		if ((sig = riskie_last_signal()) != -1) {
			switch (sig) {
			case SIGINT:
				running = 0;
				continue;
			}
		}

		riskie_hart_tick(&soc->ht);
		riskie_peripheral_tick();

		if (poll(&pfd, 1, 0) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", strerror(errno));
		}

		if (pfd.revents & POLLIN) {
			ret = read(STDIN_FILENO, &input, sizeof(input));
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				fatal("read: %s", strerror(errno));
			}

			if (ret == 0)
				fatal("eof on stdin");

			last_input = input;
		}
	}

	riskie_term_restore();
	riskie_hart_cleanup(&soc->ht);

	if (soc->debug) {
		riskie_mem_dump();
		riskie_hart_dump(&soc->ht);
	}

	free(soc->mem.ptr);

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
 * Returns the last input byte, if there is one.
 */
int
riskie_input_pending(u_int8_t *byte)
{
	PRECOND(byte != NULL);

	if (last_input == -1)
		return (-1);

	*byte = (u_int8_t)last_input;
	last_input = -1;

	return (0);
}

/*
 * Sad juju happened and riskie must die.
 */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	riskie_term_restore();

	fprintf(stderr, "fatal: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	if (soc->debug)
		riskie_mem_dump();

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
