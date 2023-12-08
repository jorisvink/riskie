/*
 * Copyright (c) 2020-2023 Joris Vink <joris@sanctorum.se>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "riskie.h"

/* Current and previous terminal settings. */
static struct termios	cur;
static struct termios	old;

/* If we should even attempt to restore the terminal settings. */
static int 		can_restore = 0;

/*
 * Setup the terminal so that local echo is turned off, etc.
 */
void
riskie_term_setup(void)
{
	memset(&old, 0, sizeof(old));
	memset(&cur, 0, sizeof(cur));

	if (tcgetattr(STDIN_FILENO, &old) == -1)
		fatal("%s: tcgetattr: %s", __func__, strerror(errno));

	cur = old;

	cur.c_cc[VMIN] = 1;
	cur.c_cc[VTIME] = 0;
	cur.c_lflag &= ~(ICANON | ECHO | ECHOE);

	if (tcsetattr(STDIN_FILENO, TCSANOW, &cur) == -1)
		fatal("%s: tcsetattr: %s", __func__, strerror(errno));

	can_restore = 1;
}

/*
 * Restore terminal to its former glory.
 */
void
riskie_term_restore(void)
{
	if (can_restore == 0)
		return;

	can_restore = 0;
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &old);
}
