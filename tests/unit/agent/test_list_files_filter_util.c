// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/list_files_filter_util.h"

#include <string.h>
#include <sys/stat.h>

static void test_parse_permissions_filter_accepts_exact_octal(void)
{
	struct permissions_filter filter;

	ELA_ASSERT_INT_EQ(0, ela_parse_permissions_filter("4755", &filter));
	ELA_ASSERT_INT_EQ(PERMISSION_FILTER_EXACT, filter.kind);
	ELA_ASSERT_TRUE(ela_permissions_match(&filter, 04755));
	ELA_ASSERT_FALSE(ela_permissions_match(&filter, 0755));
}

static void test_parse_permissions_filter_accepts_symbolic_clauses(void)
{
	struct permissions_filter filter;

	ELA_ASSERT_INT_EQ(0, ela_parse_permissions_filter("u+sx,g-w,o=r", &filter));
	ELA_ASSERT_INT_EQ(PERMISSION_FILTER_SYMBOLIC, filter.kind);
	ELA_ASSERT_TRUE(ela_permissions_match(&filter, S_ISUID | S_IXUSR | S_IRUSR | S_IROTH));
	ELA_ASSERT_FALSE(ela_permissions_match(&filter, S_IWGRP | S_IRUSR));
}

static void test_parse_permissions_filter_rejects_invalid_specs(void)
{
	struct permissions_filter filter;

	ELA_ASSERT_INT_EQ(-1, ela_parse_permissions_filter("8888", &filter));
	ELA_ASSERT_INT_EQ(-1, ela_parse_permissions_filter("u+", &filter));
	ELA_ASSERT_INT_EQ(-1, ela_parse_permissions_filter("u?x", &filter));
}

static void test_entry_matches_filters_combines_all_criteria(void)
{
	struct list_files_filters filters;
	struct stat st;

	memset(&filters, 0, sizeof(filters));
	memset(&st, 0, sizeof(st));
	filters.suid_only = true;
	filters.user_set = true;
	filters.uid = 1000;
	filters.group_set = true;
	filters.gid = 100;
	ELA_ASSERT_INT_EQ(0, ela_parse_permissions_filter("4755", &filters.permissions));

	st.st_mode = 04755;
	st.st_uid = 1000;
	st.st_gid = 100;
	ELA_ASSERT_TRUE(ela_list_files_entry_matches_filters(&st, &filters));

	st.st_gid = 200;
	ELA_ASSERT_FALSE(ela_list_files_entry_matches_filters(&st, &filters));
}

int run_list_files_filter_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_permissions_filter_accepts_exact_octal", test_parse_permissions_filter_accepts_exact_octal },
		{ "parse_permissions_filter_accepts_symbolic_clauses", test_parse_permissions_filter_accepts_symbolic_clauses },
		{ "parse_permissions_filter_rejects_invalid_specs", test_parse_permissions_filter_rejects_invalid_specs },
		{ "entry_matches_filters_combines_all_criteria", test_entry_matches_filters_combines_all_criteria },
	};

	return ela_run_test_suite("list_files_filter_util", cases, sizeof(cases) / sizeof(cases[0]));
}
