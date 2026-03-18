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
int run_file_scan_formatter_tests(void);
int run_tpm2_pcr_parse_util_tests(void);
int run_ws_url_util_tests(void);
int run_remote_copy_util_tests(void);
int run_orom_util_tests(void);
int run_http_protocol_util_tests(void);
int run_tcp_parse_util_tests(void);
int run_api_key_util_tests(void);
int run_command_io_util_tests(void);
int run_ws_frame_util_tests(void);
int run_ssh_parse_util_tests(void);
int run_tpm2_output_format_util_tests(void);
int run_tpm2_command_util_tests(void);
int run_transfer_parse_util_tests(void);
int run_ws_session_util_tests(void);
int run_uboot_command_extract_util_tests(void);
int run_uboot_env_util_tests(void);
int run_uboot_audit_util_tests(void);
int run_linux_dmesg_util_tests(void);
int run_http_ws_policy_util_tests(void);

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
	rc |= run_file_scan_formatter_tests();
	rc |= run_tpm2_pcr_parse_util_tests();
	rc |= run_ws_url_util_tests();
	rc |= run_remote_copy_util_tests();
	rc |= run_orom_util_tests();
	rc |= run_http_protocol_util_tests();
	rc |= run_tcp_parse_util_tests();
	rc |= run_api_key_util_tests();
	rc |= run_command_io_util_tests();
	rc |= run_ws_frame_util_tests();
	rc |= run_ssh_parse_util_tests();
	rc |= run_tpm2_output_format_util_tests();
	rc |= run_tpm2_command_util_tests();
	rc |= run_transfer_parse_util_tests();
	rc |= run_ws_session_util_tests();
	rc |= run_uboot_command_extract_util_tests();
	rc |= run_uboot_env_util_tests();
	rc |= run_uboot_audit_util_tests();
	rc |= run_linux_dmesg_util_tests();
	rc |= run_http_ws_policy_util_tests();

	return rc;
}
