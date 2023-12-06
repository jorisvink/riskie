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

#include <ctype.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "riskie.h"

static void	config_parse_memory(char *);
static void	config_parse_peripheral(char *);

static char	*config_read_line(FILE *, char *, size_t);

static const struct {
	const char		*option;
	void			(*cb)(char *);
} keywords[] = {
	{ "memory",		config_parse_memory },
	{ "peripheral",		config_parse_peripheral },
	{ NULL,			NULL },
};

/*
 * Load the configuration present under `file` into the riskie context.
 */
void
riskie_config_load(const char *file)
{
	FILE		*fp;
	int		idx;
	char		buf[BUFSIZ], *option, *value;

	PRECOND(file != NULL);

	if ((fp = fopen(file, "r")) == NULL)
		fatal("failed to open '%s': %s", file, strerror(errno));

	while ((option = config_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(option) == 0)
			continue;

		if ((value = strchr(option, ' ')) == NULL)
			fatal("malformed option '%s'", option);

		*(value)++ = '\0';

		for (idx = 0; keywords[idx].option != NULL; idx++) {
			if (!strcmp(keywords[idx].option, option)) {
				keywords[idx].cb(value);
				break;
			}
		}

		if (keywords[idx].option == NULL)
			fatal("unknown option '%s'", option);
	}

	if (ferror(fp))
		fatal("error reading the configuration file");

	fclose(fp);
}

/*
 * Read a single line from the file, stripping away comments and whitespaces.
 */
static char *
config_read_line(FILE *fp, char *in, size_t len)
{
	char		*p, *t;

	PRECOND(fp != NULL);
	PRECOND(in != NULL);

	if (fgets(in, len, fp) == NULL)
		return (NULL);

	p = in;
	in[strcspn(in, "\n")] = '\0';

	while (isspace(*(unsigned char *)p))
		p++;

	if (p[0] == '#' || p[0] == '\0') {
		p[0] = '\0';
		return (p);
	}

	for (t = p; *t != '\0'; t++) {
		if (*t == '\t')
			*t = ' ';
	}

	return (p);
}

/*
 * Configures the base address for riskie and how much memory is available.
 *
 * Format:
 *	memory <base> <size>
 *		eg: memory 0x80000000 0x8000000
 */
static void
config_parse_memory(char *memory)
{
	u_int64_t	addr, size;

	PRECOND(memory != NULL);

	if (sscanf(memory, "0x%" PRIx64 " 0x%" PRIx64, &addr, &size) != 2)
		fatal("Bad memory config, expected <addr> <size> (0x0)");

	riskie->mem.base = addr;
	riskie->mem.size = size;

	if (riskie->mem.base + riskie->mem.size < riskie->mem.base)
		fatal("memory size is a bit too large");
}

/*
 * Adds a new peripheral that can be addressed via the given address.
 *
 * Format:
 *	peripheral <module> <addr> <size>
 *		eg: peripheral serial.so 0x90000000 0x1000
 */
static void
config_parse_peripheral(char *peripheral)
{
	PRECOND(peripheral != NULL);
}
