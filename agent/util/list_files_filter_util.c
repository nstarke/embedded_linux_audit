// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "list_files_filter_util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static mode_t who_bits_to_mask(unsigned int who_mask)
{
	mode_t mask = 0;

	if (who_mask & 0x1)
		mask |= S_IRUSR | S_IWUSR | S_IXUSR | S_ISUID;
	if (who_mask & 0x2)
		mask |= S_IRGRP | S_IWGRP | S_IXGRP | S_ISGID;
	if (who_mask & 0x4)
		mask |= S_IROTH | S_IWOTH | S_IXOTH | S_ISVTX;

	return mask;
}

bool ela_is_octal_string(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s)
		return false;

	while (*p) {
		if (*p < '0' || *p > '7')
			return false;
		p++;
	}

	return true;
}

int ela_parse_symbolic_permissions(const char *spec, struct permissions_filter *filter)
{
	const char *p = spec;

	if (!spec || !*spec || !filter)
		return -1;

	filter->kind = PERMISSION_FILTER_SYMBOLIC;
	filter->clause_count = 0;

	while (*p) {
		unsigned int who_mask = 0;
		mode_t value_mask = 0;
		mode_t affected_mask;
		char op;
		bool saw_who = false;
		bool saw_perm = false;

		while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
			saw_who = true;
			if (*p == 'u')
				who_mask |= 0x1;
			else if (*p == 'g')
				who_mask |= 0x2;
			else if (*p == 'o')
				who_mask |= 0x4;
			else
				who_mask |= 0x1 | 0x2 | 0x4;
			p++;
		}

		if (!saw_who)
			who_mask = 0x1 | 0x2 | 0x4;

		op = *p;
		if (op != '+' && op != '-' && op != '=')
			return -1;
		p++;

		affected_mask = who_bits_to_mask(who_mask);
		while (*p && *p != ',') {
			saw_perm = true;
			switch (*p) {
			case 'r':
				if (who_mask & 0x1)
					value_mask |= S_IRUSR;
				if (who_mask & 0x2)
					value_mask |= S_IRGRP;
				if (who_mask & 0x4)
					value_mask |= S_IROTH;
				break;
			case 'w':
				if (who_mask & 0x1)
					value_mask |= S_IWUSR;
				if (who_mask & 0x2)
					value_mask |= S_IWGRP;
				if (who_mask & 0x4)
					value_mask |= S_IWOTH;
				break;
			case 'x':
				if (who_mask & 0x1)
					value_mask |= S_IXUSR;
				if (who_mask & 0x2)
					value_mask |= S_IXGRP;
				if (who_mask & 0x4)
					value_mask |= S_IXOTH;
				break;
			case 's':
				if (who_mask & 0x1)
					value_mask |= S_ISUID;
				if (who_mask & 0x2)
					value_mask |= S_ISGID;
				break;
			case 't':
				if (who_mask & 0x4)
					value_mask |= S_ISVTX;
				break;
			default:
				return -1;
			}
			p++;
		}

		if (!saw_perm || filter->clause_count >= (sizeof(filter->clauses) / sizeof(filter->clauses[0])))
			return -1;

		filter->clauses[filter->clause_count].affected_mask = affected_mask;
		filter->clauses[filter->clause_count].value_mask = value_mask;
		filter->clauses[filter->clause_count].op = op;
		filter->clause_count++;

		if (*p == ',')
			p++;
	}

	return 0;
}

int ela_parse_permissions_filter(const char *spec, struct permissions_filter *filter)
{
	char *end = NULL;
	unsigned long value;

	if (!spec || !*spec || !filter)
		return -1;

	memset(filter, 0, sizeof(*filter));
	if (ela_is_octal_string(spec)) {
		errno = 0;
		value = strtoul(spec, &end, 8);
		if (errno != 0 || !end || *end != '\0' || value > 07777UL)
			return -1;
		filter->kind = PERMISSION_FILTER_EXACT;
		filter->exact_mode = (mode_t)value;
		return 0;
	}

	return ela_parse_symbolic_permissions(spec, filter);
}

bool ela_permissions_match(const struct permissions_filter *filter, mode_t mode)
{
	size_t i;
	mode_t perm_mode = mode & 07777;

	if (!filter || filter->kind == PERMISSION_FILTER_NONE)
		return true;

	if (filter->kind == PERMISSION_FILTER_EXACT)
		return perm_mode == filter->exact_mode;

	for (i = 0; i < filter->clause_count; i++) {
		const struct symbolic_permission_clause *clause = &filter->clauses[i];

		switch (clause->op) {
		case '+':
			if ((perm_mode & clause->value_mask) != clause->value_mask)
				return false;
			break;
		case '-':
			if (perm_mode & clause->value_mask)
				return false;
			break;
		case '=':
			if ((perm_mode & clause->affected_mask) != clause->value_mask)
				return false;
			break;
		default:
			return false;
		}
	}

	return true;
}

bool ela_list_files_entry_matches_filters(const struct stat *st, const struct list_files_filters *filters)
{
	if (!st || !filters)
		return false;

	if (filters->suid_only && !(st->st_mode & S_ISUID))
		return false;
	if (filters->user_set && st->st_uid != filters->uid)
		return false;
	if (filters->group_set && st->st_gid != filters->gid)
		return false;
	if (!ela_permissions_match(&filters->permissions, st->st_mode))
		return false;

	return true;
}
