// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef TESTS_UNIT_AGENT_TEST_HARNESS_H
#define TESTS_UNIT_AGENT_TEST_HARNESS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ela_test_case {
	const char *name;
	void (*fn)(void);
};

extern int ela_test_failures;

#define ELA_ASSERT_TRUE(expr) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, "assertion failed: %s (%s:%d)\n", #expr, __FILE__, __LINE__); \
			ela_test_failures++; \
			return; \
		} \
	} while (0)

#define ELA_ASSERT_FALSE(expr) ELA_ASSERT_TRUE(!(expr))

#define ELA_ASSERT_INT_EQ(expected, actual) \
	do { \
		long long _expected = (long long)(expected); \
		long long _actual = (long long)(actual); \
		if (_expected != _actual) { \
			fprintf(stderr, \
				"assertion failed: expected %lld, got %lld (%s:%d)\n", \
				_expected, _actual, __FILE__, __LINE__); \
			ela_test_failures++; \
			return; \
		} \
	} while (0)

#define ELA_ASSERT_STR_EQ(expected, actual) \
	do { \
		const char *_expected = (expected); \
		const char *_actual = (actual); \
		if (((_expected) == NULL) != ((_actual) == NULL) || \
		    (_expected && _actual && strcmp(_expected, _actual) != 0)) { \
			fprintf(stderr, \
				"assertion failed: expected \"%s\", got \"%s\" (%s:%d)\n", \
				_expected ? _expected : "(null)", \
				_actual ? _actual : "(null)", \
				__FILE__, __LINE__); \
			ela_test_failures++; \
			return; \
		} \
	} while (0)

int ela_run_test_suite(const char *suite_name,
		       const struct ela_test_case *cases,
		       size_t case_count);

#endif
