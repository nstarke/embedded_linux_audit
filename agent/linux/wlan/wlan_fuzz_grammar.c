// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Grammar rendering + class-directed mutation engine.
 */
#include <stdio.h>
#include <string.h>

#include "wlan_fuzz.h"

/* ---- rng: xorshift64* --------------------------------------------------- */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

void rng_seed(uint64_t s)
{
	rng_state = s ? s : 0x9E3779B97F4A7C15ull;
}

uint64_t rng_next(void)
{
	uint64_t x = rng_state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545F4914F6CDD1Dull;
}

uint32_t rng_below(uint32_t n)
{
	return n ? (uint32_t)(rng_next() % n) : 0;
}

/* ---- render -------------------------------------------------------------- */

static void put_int(uint8_t *p, uint32_t v, int width, int be)
{
	int i;

	for (i = 0; i < width; i++) {
		int shift = be ? 8 * (width - 1 - i) : 8 * i;

		p[i] = (v >> shift) & 0xFF;
	}
}

int msg_build(const struct msg *m, const struct fcase *c, int big_endian,
	      uint8_t *out, int outcap)
{
	int off = 0, i;

	for (i = 0; i < m->nfields; i++) {
		const struct field *f = &m->fields[i];
		int w;

		switch (f->type) {
		case FT_BYTES:
			if (off + c->blen[i] > outcap)
				return -1;
			memcpy(out + off, c->bytes[i], c->blen[i]);
			off += c->blen[i];
			break;
		case FT_U8:  w = 1; goto integer;
		case FT_U16: w = 2; goto integer;
		case FT_U32: w = 4;
integer:
			if (off + w > outcap)
				return -1;
			put_int(out + off, c->ints[i], w, big_endian);
			off += w;
			break;
		}
	}
	return off;
}

/* ---- boundary sets ------------------------------------------------------- */

static uint32_t pick_index_boundary(uint32_t valid_max, int wide)
{
	/* off-by-one first-class: vm, vm+1, vm+2 (the if_owl.c:749 class) */
	static const uint32_t wide_extra[] = {
		0x100, 0xFFFF, 0x10000, 0x00100000,
		0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu,
	};
	uint32_t vm = valid_max ? valid_max : 7;
	uint32_t base[] = { 0, vm, vm + 1, vm + 2, 2 * (vm + 1),
			    0x7F, 0x80, 0xFF };
	uint32_t nb = sizeof(base) / sizeof(base[0]);

	if (wide && rng_below(2))
		return wide_extra[rng_below(sizeof(wide_extra) /
					    sizeof(wide_extra[0]))];
	return base[rng_below(nb)];
}

static uint32_t pick_count_boundary(uint32_t valid_max)
{
	uint32_t vm = valid_max ? valid_max : 30;
	uint32_t set[] = { 0, 1, vm, vm + 1, 2 * vm, 0x7F, 0xFF };

	return set[rng_below(sizeof(set) / sizeof(set[0]))];
}

static uint16_t pick_length_size(uint16_t nominal)
{
	/* pool/stack sizes from the audit: 64/100/112/128/480... */
	static const uint16_t set[] = {
		0, 1, 2, 3, 4, 64, 100, 112, 113, 128, 129,
		256, 400, 480, 496,
	};
	uint16_t v;

	if (rng_below(4) == 0)
		return nominal;
	v = set[rng_below(sizeof(set) / sizeof(set[0]))];
	return v < FIELD_BYTES_MAX ? v : FIELD_BYTES_MAX - 1;
}

static const uint8_t boundary_bytes[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };

static void mutate_array_bytes(uint8_t *buf, uint16_t *len)
{
	uint16_t n = *len, i;

	switch (rng_below(4)) {
	case 0:	/* duplicate-spam one byte (the H6 pattern) */
		if (n)
			memset(buf, buf[rng_below(n)], n);
		break;
	case 1:	/* truncate */
		if (n > 1)
			*len = 1 + rng_below(n - 1);
		break;
	case 2: {	/* repeat/extend up to 4x, capped */
		uint16_t newlen = n * 4 > 480 ? 480 : n * 4;

		for (i = n; i < newlen && n; i++)
			buf[i] = buf[i % n];
		*len = newlen;
		break;
	}
	default:	/* sprinkle boundary bytes */
		if (!n) {
			buf[0] = 0;
			*len = 1;
			n = 1;
		}
		for (i = 0; i < (uint16_t)(n / 8 + 1); i++)
			buf[rng_below(n)] =
				boundary_bytes[rng_below(5)];
	}
}

/* ---- case generation ------------------------------------------------------ */

static void case_defaults(const struct msg *m, struct fcase *c)
{
	int i;

	memset(c->ints, 0, sizeof(c->ints));
	memset(c->blen, 0, sizeof(c->blen));
	for (i = 0; i < m->nfields; i++) {
		const struct field *f = &m->fields[i];

		if (f->type == FT_BYTES) {
			c->blen[i] = f->size;
			memset(c->bytes[i], 0, f->size);
		} else {
			c->ints[i] = f->dflt;
		}
	}
}

static void note_append(struct fcase *c, const char *fmt, const char *name,
			uint32_t v)
{
	size_t used = strlen(c->note);

	if (used < sizeof(c->note) - 32)
		snprintf(c->note + used, sizeof(c->note) - used, fmt,
			 name, v);
}

static void mutate_field(const struct msg *m, struct fcase *c, int fi)
{
	const struct field *f = &m->fields[fi];
	uint16_t sz, i;

	switch (f->klass) {
	case FC_INDEX:
		c->ints[fi] = pick_index_boundary(f->valid_max,
						  f->type != FT_U8);
		note_append(c, " %s=idx:%u", f->name, c->ints[fi]);
		break;
	case FC_COUNT:
		c->ints[fi] = pick_count_boundary(f->valid_max);
		note_append(c, " %s=cnt:%u", f->name, c->ints[fi]);
		break;
	case FC_LENGTH:
		if (f->type == FT_BYTES) {
			sz = pick_length_size(f->size);
			c->blen[fi] = sz;
			for (i = 0; i < sz; i++)	/* traceable pattern */
				c->bytes[fi][i] = 0x41 + (i % 26);
			note_append(c, " %s=len:%u", f->name, sz);
		} else {	/* integer length field: lie about size */
			c->ints[fi] = pick_length_size((uint16_t)f->dflt);
			note_append(c, " %s=len:%u", f->name, c->ints[fi]);
		}
		break;
	case FC_ARRAY:
		if (f->type == FT_BYTES) {
			static const uint8_t rates[] = { 0x0C, 0x80, 0x82, 0x84 };

			memset(c->bytes[fi], rates[rng_below(4)], f->size);
			c->blen[fi] = f->size;
			mutate_array_bytes(c->bytes[fi], &c->blen[fi]);
			note_append(c, " %s=arr:%u", f->name, c->blen[fi]);
		}
		break;
	default:	/* FC_OPAQUE */
		if (f->type == FT_BYTES) {
			for (i = 0; i < c->blen[fi]; i++)
				c->bytes[fi][i] = boundary_bytes[rng_below(5)];
		} else {
			static const uint32_t vals[] = {
				0, 1, 0x7F, 0xFF, 0xFFFF, 0xFFFFFFFFu,
			};
			c->ints[fi] = vals[rng_below(6)];
		}
		note_append(c, " %s=rnd:%u", f->name, 0);
	}
}

void case_generate(const struct msg *msgs, int nmsgs, struct fcase *c)
{
	double total = 0, r;
	const struct msg *m;
	int i, nmut, fi, prev;

	for (i = 0; i < nmsgs; i++)
		total += msgs[i].weight;
	r = (double)(rng_next() >> 11) / (double)(1ull << 53) * total;
	for (i = 0; i < nmsgs - 1; i++) {
		r -= msgs[i].weight;
		if (r <= 0)
			break;
	}
	c->msg_idx = i;
	m = &msgs[i];

	case_defaults(m, c);
	c->note[0] = '\0';

	nmut = (rng_below(10) < 7) ? 1 : 2;
	prev = -1;
	while (nmut--) {
		fi = rng_below(m->nfields);
		if (fi == prev)
			fi = (fi + 1) % m->nfields;
		mutate_field(m, c, fi);
		prev = fi;
	}
}
