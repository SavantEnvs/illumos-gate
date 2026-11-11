/*
 * Fuzz harness for illumos' fault-management diagnosis-code dictionary reader (libfm diagcode.c), which
 * fmd uses to turn a set of fault classes into a short "SUN4U-8000-0Y" style code and back. The input is
 * the text of a ".dict" file: a "FMDICT: name=FZ version=1 maxkey=N" header followed by
 * "<fault class> [<fault class>...]=<number>" lines. The library only opens dictionaries by path, so the
 * input is written to FZ.dict in a private directory made once from $TMPDIR (rewritten for each input).
 * A dictionary that fm_dc_opendict() refuses is rejected (-1); an accepted one has its properties read and
 * every key in it (taken from the dictionary lines themselves) turned into a code and back again.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fm/diagcode.h>

#define	DICTNAME	"FZ"
#define	MAXINPUT	65536
#define	MAXWORDS	64

static char dir[4096];
static char path[4200];
static volatile unsigned long sink;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp = getenv("TMPDIR");

	(void) argc;
	(void) argv;
	if (tmp == NULL || *tmp == '\0')
		tmp = "/tmp";
	(void) snprintf(dir, sizeof (dir), "%s/fuzz_diagcode.XXXXXX", tmp);
	if (mkdtemp(dir) == NULL) {
		perror("mkdtemp");
		abort();
	}
	(void) snprintf(path, sizeof (path), "%s/" DICTNAME ".dict", dir);
	return (0);
}

static int
write_dict(const uint8_t *data, size_t size)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	size_t off = 0;

	if (fd < 0)
		return (-1);
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);

		if (n <= 0) {
			(void) close(fd);
			return (-1);
		}
		off += (size_t)n;
	}
	return (close(fd));
}

static void
roundtrip(fm_dc_handle_t *dhp, char *line, size_t codelen, int maxkey)
{
	const char *key[MAXWORDS + 1];
	char *back[MAXWORDS + 1];
	char code[64];
	int n = 0;
	char *p;
	int i;

	if ((p = strchr(line, '=')) == NULL)
		return;
	*p = '\0';
	for (p = strtok(line, " \t\r\n"); p != NULL && n < MAXWORDS; p = strtok(NULL, " \t\r\n"))
		key[n++] = p;
	key[n] = NULL;
	if (n == 0)
		return;

	(void) memset(code, 0, sizeof (code));
	if (fm_dc_key2code(dhp, key, code, sizeof (code)) == 0) {
		sink += strlen(code);
		if (maxkey > 1 && maxkey <= MAXWORDS + 1) {
			(void) memset(back, 0, sizeof (back));
			if (fm_dc_code2key(dhp, code, back, maxkey) == 0) {
				for (i = 0; i < maxkey && back[i] != NULL; i++) {
					sink += strlen(back[i]);
					free(back[i]);
				}
			} else {
				for (i = 0; i < maxkey && back[i] != NULL; i++)
					free(back[i]);
			}
		}
	}
	/* too-small output buffers take the ENOSPC paths */
	(void) fm_dc_key2code(dhp, key, code, codelen > 3 ? codelen - 3 : 1);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fm_dc_handle_t *dhp;
	char *copy, *line, *save = NULL;
	int maxkey;
	size_t codelen;

	if (size == 0 || size > MAXINPUT)
		return (-1);
	if (write_dict(data, size) != 0)
		return (-1);
	if ((dhp = fm_dc_opendict(FM_DC_VERSION, dir, DICTNAME)) == NULL)
		return (-1);

	codelen = fm_dc_codelen(dhp);
	maxkey = fm_dc_maxkey(dhp);
	sink += codelen + (unsigned)maxkey;
	if (fm_dc_getprop(dhp, "name") != NULL)
		sink++;
	if (fm_dc_getprop(dhp, "version") != NULL)
		sink++;
	if (fm_dc_getprop(dhp, "nonexistent") != NULL)
		sink++;

	if ((copy = malloc(size + 1)) != NULL) {
		(void) memcpy(copy, data, size);
		copy[size] = '\0';
		for (line = strtok_r(copy, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
			if (*line == '#' || strncmp(line, "FMDICT:", 7) == 0)
				continue;
			roundtrip(dhp, line, codelen, maxkey);
		}
		free(copy);
	}

	/* decode strings that were never produced by key2code */
	{
		char *back[MAXWORDS + 1];
		const char *probes[] = {
			DICTNAME "-8000-0Y", DICTNAME "-9YYY-X6", DICTNAME "-0000-00",
			DICTNAME "-AAAA-AAAA-AA", "", "-", DICTNAME,
		};
		size_t k;
		int i;

		for (k = 0; k < sizeof (probes) / sizeof (probes[0]); k++) {
			(void) memset(back, 0, sizeof (back));
			if (maxkey > 1 && maxkey <= MAXWORDS + 1 &&
			    fm_dc_code2key(dhp, probes[k], back, maxkey) == 0)
				for (i = 0; i < maxkey && back[i] != NULL; i++)
					free(back[i]);
		}
	}

	fm_dc_closedict(dhp);
	return (0);
}
