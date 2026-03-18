// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_LIST_FILES_FILTER_UTIL_H
#define UTIL_LIST_FILES_FILTER_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

enum permission_filter_kind {
	PERMISSION_FILTER_NONE = 0,
	PERMISSION_FILTER_EXACT,
	PERMISSION_FILTER_SYMBOLIC,
};

struct symbolic_permission_clause {
	mode_t affected_mask;
	mode_t value_mask;
	char op;
};

struct permissions_filter {
	enum permission_filter_kind kind;
	mode_t exact_mode;
	struct symbolic_permission_clause clauses[16];
	size_t clause_count;
};

struct list_files_filters {
	bool suid_only;
	bool user_set;
	uid_t uid;
	bool group_set;
	gid_t gid;
	struct permissions_filter permissions;
};

bool ela_is_octal_string(const char *s);
int ela_parse_symbolic_permissions(const char *spec, struct permissions_filter *filter);
int ela_parse_permissions_filter(const char *spec, struct permissions_filter *filter);
bool ela_permissions_match(const struct permissions_filter *filter, mode_t mode);
bool ela_list_files_entry_matches_filters(const struct stat *st, const struct list_files_filters *filters);

#endif
