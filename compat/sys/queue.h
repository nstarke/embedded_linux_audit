/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal sys/queue.h compatibility header for toolchains lacking it (e.g. musl). */

#ifndef FW_COMPAT_SYS_QUEUE_H
#define FW_COMPAT_SYS_QUEUE_H

#define LIST_HEAD(name, type) \
struct name { \
	struct type *lh_first; /* first element */ \
}

#define LIST_HEAD_INITIALIZER(head) \
	{ NULL }

#define LIST_ENTRY(type) \
struct { \
	struct type *le_next;  /* next element */ \
	struct type **le_prev; /* address of previous next element */ \
}

#define LIST_FIRST(head)		((head)->lh_first)
#define LIST_END(head)			NULL
#define LIST_EMPTY(head)		(LIST_FIRST(head) == LIST_END(head))
#define LIST_NEXT(elm, field)		((elm)->field.le_next)

#define LIST_FOREACH(var, head, field) \
	for ((var) = LIST_FIRST(head); (var) != LIST_END(head); (var) = LIST_NEXT(var, field))

#define LIST_INIT(head) do { \
	LIST_FIRST(head) = LIST_END(head); \
} while (0)

#define LIST_INSERT_HEAD(head, elm, field) do { \
	if (((elm)->field.le_next = (head)->lh_first) != NULL) \
		(head)->lh_first->field.le_prev = &(elm)->field.le_next; \
	(head)->lh_first = (elm); \
	(elm)->field.le_prev = &(head)->lh_first; \
} while (0)

#define LIST_INSERT_BEFORE(listelm, elm, field) do { \
	(elm)->field.le_prev = (listelm)->field.le_prev; \
	(elm)->field.le_next = (listelm); \
	*(listelm)->field.le_prev = (elm); \
	(listelm)->field.le_prev = &(elm)->field.le_next; \
} while (0)

#define LIST_INSERT_AFTER(listelm, elm, field) do { \
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL) \
		(listelm)->field.le_next->field.le_prev = &(elm)->field.le_next; \
	(listelm)->field.le_next = (elm); \
	(elm)->field.le_prev = &(listelm)->field.le_next; \
} while (0)

#define LIST_REMOVE(elm, field) do { \
	if ((elm)->field.le_next != NULL) \
		(elm)->field.le_next->field.le_prev = (elm)->field.le_prev; \
	*(elm)->field.le_prev = (elm)->field.le_next; \
} while (0)

#endif /* FW_COMPAT_SYS_QUEUE_H */
