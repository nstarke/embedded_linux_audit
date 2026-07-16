// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_client.h"
#include "../../../agent/net/ws_config_util.h"
#include "../../../agent/net/ws_session_util.h"
#include "../../../agent/net/ws_frame_util.h"

#include <string.h>

/* Stub environment for ela_ws_config_resolve. */
static const char *stub_env_api_url;
static const char *stub_env_output_http;
static const char *stub_env_output_format;
static const char *stub_env_api_insecure;

static const char *stub_env_lookup(const char *name)
{
	if (!strcmp(name, "ELA_API_URL"))
		return stub_env_api_url;
	if (!strcmp(name, "ELA_OUTPUT_HTTP"))
		return stub_env_output_http;
	if (!strcmp(name, "ELA_OUTPUT_FORMAT"))
		return stub_env_output_format;
	if (!strcmp(name, "ELA_API_INSECURE"))
		return stub_env_api_insecure;
	return NULL;
}

static void reset_stub_env(void)
{
	stub_env_api_url = NULL;
	stub_env_output_http = NULL;
	stub_env_output_format = NULL;
	stub_env_api_insecure = NULL;
}

static void test_config_key_policy_refuses_secrets_and_unknowns(void)
{
	ELA_ASSERT_TRUE(ela_ws_config_key_is_readable("ELA_API_URL"));
	ELA_ASSERT_TRUE(ela_ws_config_key_is_readable("ELA_OUTPUT_HTTP"));
	ELA_ASSERT_TRUE(ela_ws_config_key_is_readable("ELA_OUTPUT_FORMAT"));
	ELA_ASSERT_TRUE(ela_ws_config_key_is_readable("ELA_API_INSECURE"));
	ELA_ASSERT_TRUE(ela_ws_config_key_is_readable("ELA_OUTPUT_INSECURE"));

	/* The bearer token must never be readable: it is excluded from ela_conf
	 * on purpose and /tmp/.ela.conf is inside the tree remote-copy uploads. */
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable("ELA_API_KEY"));

	/* setenv-only variables live in a process we cannot see; answering for
	 * them would mean confidently returning a stale value. */
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable("ELA_SCRIPT"));
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable("ELA_DEBUG"));
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable("PATH"));
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable(""));
	ELA_ASSERT_FALSE(ela_ws_config_key_is_readable(NULL));
}

/*
 * The precedence rule that matters: ELA_API_URL supplied by the launch
 * environment is never written back to conf (startup export uses overwrite=0),
 * so an unchanged conf must not shadow it.
 */
static void test_config_resolve_prefers_env_when_conf_unchanged(void)
{
	struct ela_conf startup = {0};
	struct ela_conf now = {0};
	char out[ELA_WS_CONFIG_VALUE_MAX];

	reset_stub_env();
	stub_env_api_url = "http://launch.example/upload";

	/* Conf empty and unchanged — the launch environment is the effective
	 * value. Returning "" here would reproduce the bogus "no ELA_API_URL". */
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_URL", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("http://launch.example/upload", out);

	/* Stale conf from a previous run must NOT beat the launch env. */
	snprintf(startup.output_http, sizeof(startup.output_http), "%s",
		 "http://previous-run.example/upload");
	snprintf(now.output_http, sizeof(now.output_http), "%s",
		 "http://previous-run.example/upload");
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_URL", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("http://launch.example/upload", out);
}

/* A runtime `set` writes through to conf, so a changed conf is the newest. */
static void test_config_resolve_prefers_conf_after_runtime_set(void)
{
	struct ela_conf startup = {0};
	struct ela_conf now = {0};
	char out[ELA_WS_CONFIG_VALUE_MAX];

	reset_stub_env();
	stub_env_api_url = "http://launch.example/upload";

	snprintf(now.output_http, sizeof(now.output_http), "%s",
		 "http://set-at-runtime.example/upload");

	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_URL", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("http://set-at-runtime.example/upload", out);

	/* ELA_OUTPUT_HTTP shares the same persisted field. */
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_OUTPUT_HTTP", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("http://set-at-runtime.example/upload", out);
}

static void test_config_resolve_falls_back_and_rejects(void)
{
	struct ela_conf startup = {0};
	struct ela_conf now = {0};
	char out[ELA_WS_CONFIG_VALUE_MAX];

	reset_stub_env();

	/* Nothing in env, nothing in conf — unset, not an error. */
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_URL", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("", out);

	/* Env empty falls through to the fallback name. */
	stub_env_output_http = "http://fallback.example/upload";
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_URL", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("http://fallback.example/upload", out);

	/* insecure renders as a string, matching how `set` displays it. */
	now.insecure = 1;
	ELA_ASSERT_INT_EQ(0, ela_ws_config_resolve("ELA_API_INSECURE", &startup, &now,
						   stub_env_lookup, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("true", out);

	/* A non-readable key is refused outright. */
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_resolve("ELA_API_KEY", &startup, &now,
						    stub_env_lookup, out, sizeof(out)));
}

static void test_config_parse_get_extracts_id_and_filters_keys(void)
{
	char id[ELA_WS_CONFIG_ID_MAX];
	char keys[ELA_WS_CONFIG_MAX_KEYS][ELA_WS_CONFIG_KEY_MAX];
	size_t n = 0;
	const char *req =
		"{\"_type\":\"config.get\",\"id\":\"abc-123\",\"keys\":[\"ELA_API_URL\"]}";

	ELA_ASSERT_INT_EQ(0, ela_ws_config_parse_get(req, strlen(req), id, sizeof(id),
						     keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_STR_EQ("abc-123", id);
	ELA_ASSERT_INT_EQ(1, (int)n);
	ELA_ASSERT_STR_EQ("ELA_API_URL", keys[0]);

	/* Disallowed names are dropped, not fatal: the caller gets what it may
	 * have. ELA_API_KEY must never survive the filter. */
	{
		const char *mixed =
			"{\"_type\":\"config.get\",\"id\":\"x\","
			"\"keys\":[\"ELA_API_KEY\",\"ELA_API_URL\",\"NOPE\"]}";

		ELA_ASSERT_INT_EQ(0, ela_ws_config_parse_get(mixed, strlen(mixed), id, sizeof(id),
							     keys, ELA_WS_CONFIG_MAX_KEYS, &n));
		ELA_ASSERT_INT_EQ(1, (int)n);
		ELA_ASSERT_STR_EQ("ELA_API_URL", keys[0]);
	}
}

static void test_config_parse_get_rejects_malformed(void)
{
	char id[ELA_WS_CONFIG_ID_MAX];
	char keys[ELA_WS_CONFIG_MAX_KEYS][ELA_WS_CONFIG_KEY_MAX];
	size_t n = 0;
	const char *wrong_type = "{\"_type\":\"heartbeat\",\"id\":\"a\"}";
	const char *no_id = "{\"_type\":\"config.get\",\"keys\":[\"ELA_API_URL\"]}";
	const char *not_json = "this is not json";
	const char *not_object = "[1,2,3]";

	ELA_ASSERT_INT_EQ(-1, ela_ws_config_parse_get(wrong_type, strlen(wrong_type), id,
						      sizeof(id), keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_parse_get(no_id, strlen(no_id), id,
						      sizeof(id), keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_parse_get(not_json, strlen(not_json), id,
						      sizeof(id), keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_parse_get(not_object, strlen(not_object), id,
						      sizeof(id), keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_parse_get(NULL, 0, id, sizeof(id), keys,
						      ELA_WS_CONFIG_MAX_KEYS, &n));

	/* No keys at all is a valid request with an empty answer. */
	{
		const char *no_keys = "{\"_type\":\"config.get\",\"id\":\"a\"}";

		ELA_ASSERT_INT_EQ(0, ela_ws_config_parse_get(no_keys, strlen(no_keys), id,
							     sizeof(id), keys,
							     ELA_WS_CONFIG_MAX_KEYS, &n));
		ELA_ASSERT_INT_EQ(0, (int)n);
	}
}

/* The payload is operator-supplied and not guaranteed NUL-terminated: the
 * parser must honour payload_len rather than running off the end. */
static void test_config_parse_get_honours_payload_len(void)
{
	char id[ELA_WS_CONFIG_ID_MAX];
	char keys[ELA_WS_CONFIG_MAX_KEYS][ELA_WS_CONFIG_KEY_MAX];
	size_t n = 0;
	const char *req =
		"{\"_type\":\"config.get\",\"id\":\"abc\",\"keys\":[\"ELA_API_URL\"]}TRAILING GARBAGE";
	size_t json_len = strlen("{\"_type\":\"config.get\",\"id\":\"abc\",\"keys\":[\"ELA_API_URL\"]}");

	ELA_ASSERT_INT_EQ(0, ela_ws_config_parse_get(req, json_len, id, sizeof(id),
						     keys, ELA_WS_CONFIG_MAX_KEYS, &n));
	ELA_ASSERT_STR_EQ("abc", id);
	ELA_ASSERT_INT_EQ(1, (int)n);
}

static void test_config_build_value_reply(void)
{
	char keys[ELA_WS_CONFIG_MAX_KEYS][ELA_WS_CONFIG_KEY_MAX];
	char values[ELA_WS_CONFIG_MAX_KEYS][ELA_WS_CONFIG_VALUE_MAX];
	char out[4096];
	char tiny[8];

	snprintf(keys[0], ELA_WS_CONFIG_KEY_MAX, "%s", "ELA_API_URL");
	snprintf(values[0], ELA_WS_CONFIG_VALUE_MAX, "%s", "http://a.example/upload");

	ELA_ASSERT_INT_EQ(0, ela_ws_config_build_value_reply("abc-123", keys, values, 1,
							     out, sizeof(out)));
	ELA_ASSERT_TRUE(strstr(out, "\"_type\":\"config.value\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"id\":\"abc-123\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"ELA_API_URL\":\"http:\\/\\/a.example\\/upload\"") != NULL
			|| strstr(out, "\"ELA_API_URL\":\"http://a.example/upload\"") != NULL);

	/* An empty value set is still a well-formed reply. */
	ELA_ASSERT_INT_EQ(0, ela_ws_config_build_value_reply("id0", keys, values, 0,
							     out, sizeof(out)));
	ELA_ASSERT_TRUE(strstr(out, "\"values\":{}") != NULL);

	/* Bad arguments and undersized buffers are refused, not truncated. */
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_build_value_reply(NULL, keys, values, 1,
							      out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_ws_config_build_value_reply("abc", keys, values, 1,
							      tiny, sizeof(tiny)));
}

/* config.get must be classified as a control frame, never handed to the REPL —
 * that is the whole point: the REPL may be busy for the length of a remote-copy. */
static void test_config_get_frame_is_classified_off_the_repl(void)
{
	struct ela_ws_frame_action action;
	const char *req = "{\"_type\":\"config.get\",\"id\":\"a\",\"keys\":[\"ELA_API_URL\"]}";
	const char *other = "linux arch isa\n";

	ela_ws_classify_incoming_frame(ELA_WS_OPCODE_TEXT, req, strlen(req), &action);
	ELA_ASSERT_INT_EQ(1, action.send_config_value);
	ELA_ASSERT_INT_EQ(0, action.forward_to_repl);
	ELA_ASSERT_INT_EQ(0, action.send_heartbeat_ack);

	/* Ordinary commands still reach the REPL. */
	ela_ws_classify_incoming_frame(ELA_WS_OPCODE_TEXT, other, strlen(other), &action);
	ELA_ASSERT_INT_EQ(0, action.send_config_value);
	ELA_ASSERT_INT_EQ(1, action.forward_to_repl);
}

int run_ws_config_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "config_key_policy_refuses_secrets_and_unknowns", test_config_key_policy_refuses_secrets_and_unknowns },
		{ "config_resolve_prefers_env_when_conf_unchanged", test_config_resolve_prefers_env_when_conf_unchanged },
		{ "config_resolve_prefers_conf_after_runtime_set", test_config_resolve_prefers_conf_after_runtime_set },
		{ "config_resolve_falls_back_and_rejects", test_config_resolve_falls_back_and_rejects },
		{ "config_parse_get_extracts_id_and_filters_keys", test_config_parse_get_extracts_id_and_filters_keys },
		{ "config_parse_get_rejects_malformed", test_config_parse_get_rejects_malformed },
		{ "config_parse_get_honours_payload_len", test_config_parse_get_honours_payload_len },
		{ "config_build_value_reply", test_config_build_value_reply },
		{ "config_get_frame_is_classified_off_the_repl", test_config_get_frame_is_classified_off_the_repl },
	};

	return ela_run_test_suite("ws_config_util", cases, sizeof(cases) / sizeof(cases[0]));
}
