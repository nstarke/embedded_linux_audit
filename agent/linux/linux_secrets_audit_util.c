// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
#include "linux_secrets_audit_util.h"
#include <string.h>
static bool has_suffix(const char *name, const char *suffix)
{
	size_t n = strlen(name), m = strlen(suffix);
	return n >= m && !strcmp(name + n - m, suffix);
}
bool ela_secrets_compressed_name(const char *name)
{
	static const char *suffixes[] = { ".gz",  ".tgz", ".bz2", ".xz", ".lzma", ".zst",
					  ".lz4", ".lzo", ".zip", ".7z", NULL };
	size_t i;
	for (i = 0; suffixes[i]; i++)
		if (has_suffix(name, suffixes[i]))
			return true;
	return false;
}
bool ela_secrets_compressed_magic(const unsigned char *b, size_t n)
{
	if (n >= 2 && b[0] == 0x1f && b[1] == 0x8b) /* gzip */
		return true;
	if (n >= 3 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h') /* bzip2 */
		return true;
	if (n >= 4 && b[0] == 0xfd && b[1] == '7' && b[2] == 'z' && b[3] == 'X') /* xz */
		return true;
	if (n >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd) /* zstd */
		return true;
	if (n >= 4 && b[0] == 0x04 && b[1] == 0x22 && b[2] == 0x4d && b[3] == 0x18) /* lz4 */
		return true;
	if (n >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 0x03 || b[2] == 0x05 || b[2] == 0x07)) /* zip */
		return true;
	return false;
}
bool ela_secrets_candidate(const char *name)
{
	if (ela_secrets_compressed_name(name))
		return false;
	return strstr(name, ".conf") || strstr(name, ".cfg") || strstr(name, ".ini") || strstr(name, ".env") ||
	       strstr(name, ".yaml") || strstr(name, ".yml") || strstr(name, ".json") || strstr(name, ".xml") ||
	       strstr(name, ".toml") || strstr(name, ".key") || strstr(name, ".pem") || strstr(name, ".crt") ||
	       strstr(name, ".service") || !strcmp(name, "passwd") || !strcmp(name, "shadow");
}
bool ela_secrets_classify_line(const char *s, const char **rule, const char **title)
{
	if (strstr(s, "-----BEGIN") && strstr(s, "PRIVATE KEY-----")) {
		*rule = "ELA-SEC-002";
		*title = "Private key material";
		return true;
	}
	if (strstr(s, "AKIA") || strstr(s, "Authorization: Bearer") || strstr(s, "api_key") || strstr(s, "apikey") ||
	    strstr(s, "access_token") || strstr(s, "client_secret")) {
		*rule = "ELA-SEC-001";
		*title = "API key or token";
		return true;
	}
	if ((strstr(s, "password=") || strstr(s, "passwd=") || strstr(s, "default_password")) && !strstr(s, "${")) {
		*rule = "ELA-SEC-003";
		*title = "Default or embedded credential";
		return true;
	}
	size_t n = strlen(s);
	bool upper = false, lower = false, digit = false;
	size_t i;
	for (i = 0; i < n && i < 160; i++) {
		if (s[i] >= 'A' && s[i] <= 'Z')
			upper = true;
		if (s[i] >= 'a' && s[i] <= 'z')
			lower = true;
		if (s[i] >= '0' && s[i] <= '9')
			digit = true;
	}
	if (n >= 40 && upper && lower && digit) {
		*rule = "ELA-SEC-004";
		*title = "High-entropy string";
		return true;
	}
	return false;
}
