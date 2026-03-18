// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

int run_str_util_tests(void);
int run_isa_util_tests(void);
int run_crc32_util_tests(void);
int run_http_uri_util_tests(void);
int run_command_parse_util_tests(void);
int run_record_formatter_tests(void);
int run_list_files_filter_util_tests(void);
int run_lifecycle_formatter_tests(void);
int run_ela_conf_util_tests(void);
int run_interactive_parse_util_tests(void);

int main(void)
{
	int rc = 0;

	rc |= run_str_util_tests();
	rc |= run_isa_util_tests();
	rc |= run_crc32_util_tests();
	rc |= run_http_uri_util_tests();
	rc |= run_command_parse_util_tests();
	rc |= run_record_formatter_tests();
	rc |= run_list_files_filter_util_tests();
	rc |= run_lifecycle_formatter_tests();
	rc |= run_ela_conf_util_tests();
	rc |= run_interactive_parse_util_tests();

	return rc;
}
