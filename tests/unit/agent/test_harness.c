// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"

int ela_test_failures = 0;

int ela_run_test_suite(const char *suite_name,
		       const struct ela_test_case *cases,
		       size_t case_count)
{
	size_t i;
	int suite_failures = 0;

	printf("[suite] %s\n", suite_name);
	for (i = 0; i < case_count; i++) {
		int before = ela_test_failures;

		printf("  [test] %s\n", cases[i].name);
		cases[i].fn();
		if (ela_test_failures != before)
			suite_failures++;
	}

	printf("[suite] %s complete: %zu case(s), %d failure(s)\n",
	       suite_name, case_count, suite_failures);
	return suite_failures == 0 ? 0 : 1;
}
