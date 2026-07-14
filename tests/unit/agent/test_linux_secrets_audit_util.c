// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_secrets_audit_util.h"
#include "test_harness.h"

#include <string.h>

static void test_candidate_matches_config_names(void)
{
	ELA_ASSERT_TRUE(ela_secrets_candidate("app.conf"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("settings.ini"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("deploy.yaml"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("localization.xml"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("server.key"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("tls.pem"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("sshd.service"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("passwd"));
	ELA_ASSERT_TRUE(ela_secrets_candidate("shadow"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("vmlinuz"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("libpasswd.so"));
}

static void test_candidate_rejects_compressed_names(void)
{
	ELA_ASSERT_FALSE(ela_secrets_candidate("de_DE-b07bcb0a389562b3142ba934105e10e6.xml.gz"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("app.conf.gz"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("bundle.json.xz"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("settings.ini.bz2"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("backup.yaml.zst"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("certs.pem.zip"));
	ELA_ASSERT_FALSE(ela_secrets_candidate("archive.xml.7z"));
}

static void test_compressed_name_suffix_only(void)
{
	ELA_ASSERT_TRUE(ela_secrets_compressed_name("a.gz"));
	ELA_ASSERT_TRUE(ela_secrets_compressed_name("a.tgz"));
	ELA_ASSERT_TRUE(ela_secrets_compressed_name("a.lzma"));
	ELA_ASSERT_TRUE(ela_secrets_compressed_name("a.lz4"));
	ELA_ASSERT_FALSE(ela_secrets_compressed_name("gz"));
	ELA_ASSERT_FALSE(ela_secrets_compressed_name("a.gz.conf"));
	ELA_ASSERT_FALSE(ela_secrets_compressed_name("gzip.conf"));
}

static void test_compressed_magic_signatures(void)
{
	static const unsigned char gzip[] = { 0x1f, 0x8b, 0x08, 0x00 };
	static const unsigned char bzip2[] = { 'B', 'Z', 'h', '9' };
	static const unsigned char xz[] = { 0xfd, '7', 'z', 'X' };
	static const unsigned char zstd[] = { 0x28, 0xb5, 0x2f, 0xfd };
	static const unsigned char lz4[] = { 0x04, 0x22, 0x4d, 0x18 };
	static const unsigned char zip[] = { 'P', 'K', 0x03, 0x04 };
	static const unsigned char text[] = { 'p', 'a', 's', 's' };

	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(gzip, sizeof(gzip)));
	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(bzip2, sizeof(bzip2)));
	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(xz, sizeof(xz)));
	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(zstd, sizeof(zstd)));
	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(lz4, sizeof(lz4)));
	ELA_ASSERT_TRUE(ela_secrets_compressed_magic(zip, sizeof(zip)));
	ELA_ASSERT_FALSE(ela_secrets_compressed_magic(text, sizeof(text)));
	ELA_ASSERT_FALSE(ela_secrets_compressed_magic(gzip, 1));
	ELA_ASSERT_FALSE(ela_secrets_compressed_magic(gzip, 0));
}

static void test_classify_private_key_and_tokens(void)
{
	const char *rule = NULL, *title = NULL;

	ELA_ASSERT_TRUE(ela_secrets_classify_line("-----BEGIN RSA PRIVATE KEY-----", &rule, &title));
	ELA_ASSERT_STR_EQ("ELA-SEC-002", rule);
	ELA_ASSERT_TRUE(ela_secrets_classify_line("api_key = abc", &rule, &title));
	ELA_ASSERT_STR_EQ("ELA-SEC-001", rule);
	ELA_ASSERT_TRUE(ela_secrets_classify_line("Authorization: Bearer xyz", &rule, &title));
	ELA_ASSERT_STR_EQ("ELA-SEC-001", rule);
}

static void test_classify_credentials(void)
{
	const char *rule = NULL, *title = NULL;

	ELA_ASSERT_TRUE(ela_secrets_classify_line("password=hunter2", &rule, &title));
	ELA_ASSERT_STR_EQ("ELA-SEC-003", rule);
	ELA_ASSERT_FALSE(ela_secrets_classify_line("password=${SECRET_FROM_ENV}", &rule, &title));
}

static void test_classify_high_entropy(void)
{
	const char *rule = NULL, *title = NULL;

	ELA_ASSERT_TRUE(ela_secrets_classify_line("dGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE9PT0x", &rule, &title));
	ELA_ASSERT_STR_EQ("ELA-SEC-004", rule);
	ELA_ASSERT_FALSE(ela_secrets_classify_line("Short1", &rule, &title));
	ELA_ASSERT_FALSE(
		ela_secrets_classify_line("a long lowercase line without digits that keeps going on", &rule, &title));
}

int run_linux_secrets_audit_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "candidate_matches_config_names", test_candidate_matches_config_names },
		{ "candidate_rejects_compressed_names", test_candidate_rejects_compressed_names },
		{ "compressed_name_suffix_only", test_compressed_name_suffix_only },
		{ "compressed_magic_signatures", test_compressed_magic_signatures },
		{ "classify_private_key_and_tokens", test_classify_private_key_and_tokens },
		{ "classify_credentials", test_classify_credentials },
		{ "classify_high_entropy", test_classify_high_entropy },
	};

	return ela_run_test_suite("linux_secrets_audit_util", cases, sizeof(cases) / sizeof(cases[0]));
}
