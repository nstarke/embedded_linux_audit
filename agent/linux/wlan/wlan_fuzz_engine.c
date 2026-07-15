// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Fuzz loop, crash oracle, windowed triage with suffix minimization and
 * history-prefix fallback.
 *
 * Crash artifacts are self-contained text files (one case per line, hex
 * payload) replayable with --replay.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_stream_fmt.h"

#define WINDOW_MAX  64
#define HISTORY_MULT 4

void msleep_ms(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

struct stored_case {
	int     msg_idx;
	int     len;
	uint8_t payload[CASE_MAX_BYTES];
	char    note[128];
};

struct fuzz_ctx {
	struct target *t;
	struct fuzz_opts o;	/* copied by value; caller's opts may be on its stack */
	struct stored_case window[WINDOW_MAX];
	int nwindow;
	struct stored_case history[WINDOW_MAX * HISTORY_MULT];
	int nhistory;
	long cases, crashes, recoveries;
};

/* ---- send/replay helpers -------------------------------------------------- */

static int send_stored(struct fuzz_ctx *fc, const struct stored_case *sc)
{
	const struct msg *m = &fc->t->msgs[sc->msg_idx];

	return fc->t->send(fc->t, m, sc->payload, sc->len);
}

/* replay a sequence on a fresh session; 1 = firmware died */
static int replay_seq(struct fuzz_ctx *fc, const struct stored_case *seq,
		      int n)
{
	int i;

	if (!fc->t->recover(fc->t)) {
		fprintf(stderr,
			"[!] device did not come back for replay -- replug and rerun\n");
		exit(1);
	}
	fc->recoveries++;
	for (i = 0; i < n; i++)
		if (send_stored(fc, &seq[i]) < 0)
			return 1;
	msleep_ms(200);
	return !fc->t->probe_alive(fc->t);
}

/* ---- crash persistence ----------------------------------------------------- */

/* Render the crash file (header + one case line each) into `buf`. Returns the
 * length written, or -1 if it would not fit. Reuses the same line format the
 * remote stream uses so the API-saved copy is byte-identical and replayable. */
static int format_crash_file(char *buf, size_t bufsz, const char *target_name,
			     const struct target *t,
			     const struct stored_case *seq, int n)
{
	int off, i;

	off = snprintf(buf, bufsz, "# target=%s cases=%d\n", target_name, n);
	if (off < 0 || (size_t)off >= bufsz)
		return -1;
	for (i = 0; i < n; i++) {
		int m = wlan_fuzz_format_case_line(buf + off, bufsz - (size_t)off,
						   t->msgs[seq[i].msg_idx].name,
						   seq[i].payload, seq[i].len,
						   seq[i].note);
		if (m < 0 || (size_t)(off + m + 1) >= bufsz)
			return -1;
		off += m;
		buf[off++] = '\n';
	}
	buf[off] = '\0';
	return off;
}

static void save_crash(struct fuzz_ctx *fc, const struct stored_case *seq,
		       int n, const char *tag)
{
	/* Header + n lines; a minimized sequence is small, but size for the worst
	 * case (a full unminimized window) so the on-disk and uploaded copies are
	 * always complete. */
	static char buf[64 + WINDOW_MAX * (HISTORY_MULT + 1) *
			(CASE_MAX_BYTES * 2 + 200)];
	char path[512];
	int len, fd;
	ssize_t w;

	fc->crashes++;
	snprintf(path, sizeof(path), "%s/crash_%04ld_%s.txt",
		 fc->o.out_dir, fc->crashes, tag);

	len = format_crash_file(buf, sizeof(buf), fc->t->name, fc->t, seq, n);
	if (len < 0) {
		fprintf(stderr, "[!] crash %s too large to serialize\n", path);
		return;
	}

	/* Create 0600, not fopen()'s world-writable 0666: crash files can hold
	 * captured firmware state and should not be readable/writable by all. */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "[!] cannot write %s: %s\n", path,
			strerror(errno));
		return;
	}
	w = write(fd, buf, (size_t)len);
	close(fd);
	if (w != len) {
		fprintf(stderr, "[!] short write to %s\n", path);
		return;
	}
	printf("[+] crash saved: %s (%d case(s))\n", path, n);

	/* Push the confirmed crash to the agent API immediately (best-effort),
	 * so it is captured even for runs the agent survives. */
	if (fc->o.sink && fc->o.sink->crash)
		fc->o.sink->crash(fc->o.sink->ctx, buf, len);
}

/* ---- triage: confirm, history fallback, suffix binary search --------------- */

static void triage(struct fuzz_ctx *fc)
{
	struct stored_case seq[WINDOW_MAX * (HISTORY_MULT + 1)];
	int n = 0, lo, hi, mid, i;

	printf("[*] triage: replaying window of %d case(s)\n", fc->nwindow);

	memcpy(seq, fc->window, fc->nwindow * sizeof(seq[0]));
	n = fc->nwindow;

	if (!replay_seq(fc, seq, n)) {
		/* killer may need state set up before the window: prepend
		 * bounded history and retry (history fallback) */
		if (fc->nhistory) {
			printf("[*] window alone does not reproduce -- retrying with %d-case history prefix\n",
			       fc->nhistory);
			memmove(seq + fc->nhistory, seq,
				(size_t)n * sizeof(seq[0]));
			memcpy(seq, fc->history,
			       (size_t)fc->nhistory * sizeof(seq[0]));
			n += fc->nhistory;
			if (!replay_seq(fc, seq, n)) {
				printf("[!] does not reproduce even with history -- flaky; saving unminimized\n");
				save_crash(fc, fc->window, fc->nwindow,
					   "flaky");
				return;
			}
		} else {
			printf("[!] window does not reproduce -- flaky; saving unminimized\n");
			save_crash(fc, fc->window, fc->nwindow, "flaky");
			return;
		}
	}

	/* shortest reproducing suffix: seq[lo..n) reproduces */
	lo = 0;
	hi = n - 1;
	while (lo < hi) {
		mid = lo + (hi - lo + 1) / 2;
		if (replay_seq(fc, seq + mid, n - mid))
			lo = mid;
		else
			hi = mid - 1;
	}
	printf("[*] triage: reduced to %d case(s)\n", n - lo);
	for (i = lo; i < n; i++)
		;	/* seq[lo..n) is the minimized sequence */
	save_crash(fc, seq + lo, n - lo, "min");
}

/* ---- main loop --------------------------------------------------------------- */

static void roll_history(struct fuzz_ctx *fc)
{
	int cap = fc->o.probe_every * HISTORY_MULT;
	int excess;

	if (cap > WINDOW_MAX * HISTORY_MULT)
		cap = WINDOW_MAX * HISTORY_MULT;
	excess = fc->nhistory + fc->nwindow - cap;
	if (excess > 0) {
		if (excess > fc->nhistory)
			excess = fc->nhistory;
		memmove(fc->history, fc->history + excess,
			(size_t)(fc->nhistory - excess) * sizeof(fc->history[0]));
		fc->nhistory -= excess;
	}
	if (fc->nwindow > cap)
		fc->nwindow = cap;	/* degenerate probe_every > cap */
	memcpy(fc->history + fc->nhistory, fc->window,
	       (size_t)fc->nwindow * sizeof(fc->history[0]));
	fc->nhistory += fc->nwindow;
	fc->nwindow = 0;
}

static int replay_file(struct fuzz_ctx *fc, const char *path)
{
	struct stored_case seq[WINDOW_MAX * (HISTORY_MULT + 1)];
	char line[4096], name[64], hex[2600], note[256];
	int n = 0, i, j, killed;
	FILE *f = fopen(path, "r");

	if (!f) {
		fprintf(stderr, "[!] cannot open %s\n", path);
		return 1;
	}
	while (fgets(line, sizeof(line), f) && n < (int)(sizeof(seq) / sizeof(seq[0]))) {
		if (line[0] == '#')
			continue;
		note[0] = '\0';
		if (sscanf(line, "%63s %2599s #%255[^\n]", name, hex, note) < 2)
			continue;
		for (i = 0; i < fc->t->nmsgs; i++)
			if (!strcmp(fc->t->msgs[i].name, name))
				break;
		if (i == fc->t->nmsgs) {
			fprintf(stderr, "[!] unknown msg %s\n", name);
			continue;
		}
		seq[n].msg_idx = i;
		seq[n].len = (int)strlen(hex) / 2;
		if (seq[n].len > CASE_MAX_BYTES)
			seq[n].len = CASE_MAX_BYTES;
		for (j = 0; j < seq[n].len; j++) {
			unsigned int b = 0;

			if (sscanf(hex + 2 * j, "%2x", &b) != 1)
				b = 0;
			seq[n].payload[j] = (uint8_t)b;
		}
		snprintf(seq[n].note, sizeof(seq[n].note), "%s", note);
		n++;
	}
	fclose(f);
	printf("[*] replaying %d case(s) from %s\n", n, path);
	killed = replay_seq(fc, seq, n);
	printf("[%c] replay %s\n", killed ? '+' : '!',
	       killed ? "reproduces" : "did not reproduce");
	return !killed;
}

int wlan_fuzz_run(struct target *t, const struct fuzz_opts *o)
{
	struct fuzz_ctx *fc = calloc(1, sizeof(*fc));
	time_t last_report = time(NULL);
	int probe_every = o->probe_every;
	long i;

	if (!fc)
		return 1;
	fc->t = t;
	fc->o = *o;
	if (probe_every > WINDOW_MAX)
		probe_every = WINDOW_MAX;

	mkdir(o->out_dir, 0755);
	rng_seed(o->seed);

	if (t->attach(t) < 0) {
		fprintf(stderr, "[!] attach failed\n");
		free(fc);
		return 1;
	}

	if (o->replay_path) {
		int r = replay_file(fc, o->replay_path);

		free(fc);
		return r;
	}

	if (!t->probe_alive(t)) {
		fprintf(stderr, "[!] firmware not answering before fuzzing started\n");
		free(fc);
		return 1;
	}
	printf("[*] fuzzing %s for %ld cases (probe every %d)\n",
	       t->name, o->iterations, probe_every);

	for (i = 0; i < o->iterations; i++) {
		struct stored_case *sc = &fc->window[fc->nwindow];
		struct fcase c;
		uint8_t buf[CASE_MAX_BYTES];
		int len, dead = 0;

		case_generate(t->msgs, t->nmsgs, &c);
		len = msg_build(&t->msgs[c.msg_idx], &c, t->big_endian, buf,
				sizeof(buf));
		if (len < 0)
			continue;

		sc->msg_idx = c.msg_idx;
		sc->len = len;
		memcpy(sc->payload, buf, (size_t)len);
		snprintf(sc->note, sizeof(sc->note), "%s", c.note);
		fc->nwindow++;
		fc->cases++;

		/* Stream the payload out BEFORE executing it: if this case panics
		 * the host and kills us, the remote sink still holds it for triage. */
		if (fc->o.sink && fc->o.sink->emit)
			fc->o.sink->emit(fc->o.sink->ctx,
					 t->msgs[c.msg_idx].name, buf, len,
					 c.note);

		if (t->send(t, &t->msgs[c.msg_idx], buf, len) < 0)
			dead = 1;

		if (!dead && fc->nwindow >= probe_every) {
			dead = !t->probe_alive(t);
			if (!dead)
				roll_history(fc);
		}

		if (dead) {
			printf("[!] firmware dead after case %ld (%s%s)\n",
			       i, t->msgs[c.msg_idx].name, c.note);
			triage(fc);
			fc->nwindow = 0;
			fc->nhistory = 0;
			if (!t->recover(t)) {
				/* LCOV_EXCL_START -- interactive replug path */
				printf("[!] device gone -- replug it, then press enter\n");
				getchar();
				if (t->attach(t) < 0) {
					fprintf(stderr, "[!] re-attach failed\n");
					break;
				}
				/* LCOV_EXCL_STOP */
			}
		}

		if (time(NULL) - last_report >= 10) {
			printf("[*] %ld cases, %ld crashes, %ld recoveries\n",
			       fc->cases, fc->crashes, fc->recoveries);
			last_report = time(NULL);
		}
	}
	printf("[*] done: %ld cases, %ld crashes\n", fc->cases, fc->crashes);
	free(fc);
	return 0;
}

/* ---- offline triage: decode a crash file without hardware ------------------ */

/* Read the "# target=<name>" header a crash file records, so --replay/--show
 * can pick the grammar without the operator re-specifying --target. */
int wlan_fuzz_peek_target(const char *path, char *out, size_t outsz)
{
	char line[512];
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = strstr(line, "target=");

		if (p) {
			if (sscanf(p + 7, "%31s", out) == 1 && outsz) {
				fclose(f);
				return 0;
			}
		}
	}
	fclose(f);
	return -1;
}

static uint32_t get_int(const uint8_t *p, int w, int be)
{
	uint32_t v = 0;
	int i;

	for (i = 0; i < w; i++)
		v |= (uint32_t)p[i] << (be ? 8 * (w - 1 - i) : 8 * i);
	return v;
}

static const char *klass_label(enum fclass k)
{
	switch (k) {
	case FC_INDEX:  return "  [INDEX]";
	case FC_LENGTH: return "  [LENGTH]";
	case FC_COUNT:  return "  [COUNT]";
	case FC_ARRAY:  return "  [ARRAY]";
	default:        return "";
	}
}

/* Decode one case's payload positionally against the message grammar. Scalar
 * fields (the trust-boundary indices/lengths/counts) decode exactly; a
 * variable-length bytes field consumes its default size, after which trailing
 * bytes are reported raw -- the mutation note carries the authoritative edit. */
static void show_case(const struct msg *m, const uint8_t *pl, int plen,
		      int big_endian)
{
	int off = 0, i, j;

	for (i = 0; i < m->nfields && off < plen; i++) {
		const struct field *f = &m->fields[i];

		if (f->type == FT_BYTES) {
			int w = f->size;

			if (off + w > plen)
				w = plen - off;
			printf("    %-20s = ", f->name);
			for (j = 0; j < w; j++)
				printf("%02x", pl[off + j]);
			printf("%s\n", klass_label(f->klass));
			off += w;
		} else {
			int w = f->type == FT_U8 ? 1 : f->type == FT_U16 ? 2 : 4;
			uint32_t v;

			if (off + w > plen)
				break;
			v = get_int(pl + off, w, big_endian);
			printf("    %-20s = 0x%08x (%u)%s\n", f->name, v, v,
			       klass_label(f->klass));
			off += w;
		}
	}
	if (off < plen)
		printf("    +%d trailing byte(s)\n", plen - off);
}

int wlan_fuzz_show(struct target *t, const char *path)
{
	char line[4096], name[64], hex[2600], note[256];
	FILE *f = fopen(path, "r");
	int caseno = 0, i, j;

	if (!f) {
		fprintf(stderr, "[!] cannot open %s\n", path);
		return 1;
	}
	printf("# crash file %s decoded as target=%s\n", path, t->name);
	while (fgets(line, sizeof(line), f)) {
		const struct msg *m = NULL;
		uint8_t pl[CASE_MAX_BYTES];
		int plen;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		note[0] = '\0';
		if (sscanf(line, "%63s %2599s #%255[^\n]", name, hex, note) < 2)
			continue;
		for (i = 0; i < t->nmsgs; i++)
			if (!strcmp(t->msgs[i].name, name)) {
				m = &t->msgs[i];
				break;
			}
		plen = (int)strlen(hex) / 2;
		if (plen > CASE_MAX_BYTES)
			plen = CASE_MAX_BYTES;
		for (j = 0; j < plen; j++) {
			unsigned int b = 0;

			if (sscanf(hex + 2 * j, "%2x", &b) != 1)
				b = 0;
			pl[j] = (uint8_t)b;
		}
		printf("\ncase %d: %s (%d bytes)\n", ++caseno, name, plen);
		if (note[0])
			printf("    mutations:%s\n", note);
		if (!m) {
			printf("    (message not in target %s grammar)\n", t->name);
			continue;
		}
		show_case(m, pl, plen, t->big_endian);
	}
	fclose(f);
	printf("\n[*] %d case(s). Reproduce on hardware with: --replay %s\n",
	       caseno, path);
	return 0;
}
