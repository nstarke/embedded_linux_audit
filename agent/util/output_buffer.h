// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_OUTPUT_BUFFER_H
#define ELA_OUTPUT_BUFFER_H

#include <csv.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct output_buffer {
	char *data;
	size_t len;
	size_t cap;
};

static inline int output_buffer_append_len(struct output_buffer *buf, const char *text, size_t text_len)
{
	size_t need;
	char *tmp;
	size_t new_cap;

	if (!buf || (!text && text_len != 0))
		return -1;

	need = buf->len + text_len + 1;
	if (need > buf->cap) {
		new_cap = buf->cap ? buf->cap : 1024;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(buf->data, new_cap);
		if (!tmp)
			return -1;
		buf->data = tmp;
		buf->cap = new_cap;
	}

	if (text_len)
		memcpy(buf->data + buf->len, text, text_len);
	buf->len += text_len;
	buf->data[buf->len] = '\0';
	return 0;
}

static inline int output_buffer_append(struct output_buffer *buf, const char *text)
{
	if (!text)
		return -1;
	return output_buffer_append_len(buf, text, strlen(text));
}

static inline int output_buffer_printf(struct output_buffer *out, const char *fmt, ...)
{
	va_list ap;
	va_list copy;
	char stack[1024];
	char *heap;
	int needed;
	int rc;

	va_start(ap, fmt);
	va_copy(copy, ap);
	needed = vsnprintf(stack, sizeof(stack), fmt, ap);
	va_end(ap);
	if (needed < 0) {
		va_end(copy);
		return -1;
	}
	if ((size_t)needed < sizeof(stack)) {
		va_end(copy);
		return output_buffer_append_len(out, stack, (size_t)needed);
	}
	heap = malloc((size_t)needed + 1);
	if (!heap) {
		va_end(copy);
		return -1;
	}
	vsnprintf(heap, (size_t)needed + 1, fmt, copy);
	va_end(copy);
	rc = output_buffer_append_len(out, heap, (size_t)needed);
	free(heap);
	return rc;
}

static inline int csv_write_to_buf(struct output_buffer *buf, const char *text)
{
	const char *in = text ? text : "";
	size_t in_len = strlen(in);
	size_t field_sz = (in_len * 2U) + 3U;
	char *field = malloc(field_sz);
	size_t written;
	int ret;

	if (!field)
		return -1;
	written = csv_write(field, field_sz, in, in_len);
	ret = output_buffer_append_len(buf, field, written);
	free(field);
	return ret;
}

#endif /* ELA_OUTPUT_BUFFER_H */
