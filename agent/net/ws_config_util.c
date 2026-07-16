// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_config_util.h"

#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

/*
 * The variables config.get will answer for. Kept in one table so the key
 * policy, the parse filter and the resolver cannot drift apart.
 *
 * `conf_field` names which ela_conf field carries the persisted value; the
 * resolver uses it both to compare against the startup snapshot and to read the
 * fresh value. `env_primary` / `env_fallback` are the environment names checked
 * when conf has not changed since startup, in the same order
 * ela_conf_update_from_env() prefers them (ELA_OUTPUT_HTTP before ELA_API_URL).
 */
enum conf_field {
	FIELD_OUTPUT_HTTP,
	FIELD_OUTPUT_FORMAT,
	FIELD_INSECURE,
};

struct config_key {
	const char     *name;
	enum conf_field field;
	const char     *env_primary;
	const char     *env_fallback;
};

static const struct config_key config_keys[] = {
	/* ELA_API_URL and ELA_OUTPUT_HTTP are the same persisted field: a
	 * `set ELA_API_URL` lands in conf.output_http (ela_conf_update_from_env
	 * prefers ELA_OUTPUT_HTTP and falls back to ELA_API_URL). They differ
	 * only in which env var is consulted first. */
	{ "ELA_API_URL",         FIELD_OUTPUT_HTTP,   "ELA_API_URL",       "ELA_OUTPUT_HTTP" },
	{ "ELA_OUTPUT_HTTP",     FIELD_OUTPUT_HTTP,   "ELA_OUTPUT_HTTP",   "ELA_API_URL" },
	{ "ELA_OUTPUT_FORMAT",   FIELD_OUTPUT_FORMAT, "ELA_OUTPUT_FORMAT", NULL },
	{ "ELA_API_INSECURE",    FIELD_INSECURE,      "ELA_API_INSECURE",  "ELA_OUTPUT_INSECURE" },
	{ "ELA_OUTPUT_INSECURE", FIELD_INSECURE,      "ELA_OUTPUT_INSECURE", "ELA_API_INSECURE" },
};

static const struct config_key *find_key(const char *name)
{
	size_t i;

	if (!name || !*name)
		return NULL;

	for (i = 0; i < sizeof(config_keys) / sizeof(config_keys[0]); i++) {
		if (!strcmp(config_keys[i].name, name))
			return &config_keys[i];
	}

	return NULL;
}

bool ela_ws_config_key_is_readable(const char *name)
{
	return find_key(name) != NULL;
}

/* The persisted value of a field, as a string. `insecure` is an int in conf but
 * a "true"/"false" string on the wire, matching how `set` displays it. */
static const char *conf_field_value(const struct ela_conf *conf,
				    enum conf_field field)
{
	if (!conf)
		return "";

	switch (field) {
	case FIELD_OUTPUT_HTTP:
		return conf->output_http;
	case FIELD_OUTPUT_FORMAT:
		return conf->output_format;
	case FIELD_INSECURE:
		return conf->insecure ? "true" : "false";
	}

	return "";
}

static bool conf_field_changed(const struct ela_conf *startup_conf,
			       const struct ela_conf *now_conf,
			       enum conf_field field)
{
	/* Without a startup snapshot we cannot tell a runtime `set` from a
	 * value left behind by a previous run, so treat conf as unchanged and
	 * let the environment answer. */
	if (!startup_conf || !now_conf)
		return false;

	return strcmp(conf_field_value(startup_conf, field),
		      conf_field_value(now_conf, field)) != 0;
}

int ela_ws_config_resolve(const char *name,
			  const struct ela_conf *startup_conf,
			  const struct ela_conf *now_conf,
			  const char *(*env_lookup)(const char *name),
			  char *out,
			  size_t out_sz)
{
	const struct config_key *key = find_key(name);
	const char *value = NULL;

	if (!key || !out || out_sz == 0)
		return -1;

	out[0] = '\0';

	if (conf_field_changed(startup_conf, now_conf, key->field)) {
		/* A runtime `set` wrote through to conf; it is the newest value. */
		value = conf_field_value(now_conf, key->field);
	} else if (env_lookup) {
		value = env_lookup(key->env_primary);
		if ((!value || !*value) && key->env_fallback)
			value = env_lookup(key->env_fallback);

		/* Nothing in the environment: fall back to whatever conf holds.
		 * Unchanged-since-startup conf is still better than nothing —
		 * it is what a fresh process would export. */
		if (!value || !*value)
			value = conf_field_value(now_conf, key->field);
	} else {
		value = conf_field_value(now_conf, key->field);
	}

	if (!value)
		value = "";

	if (strlen(value) >= out_sz)
		return -1;

	snprintf(out, out_sz, "%s", value);
	return 0;
}

int ela_ws_config_parse_get(const char *payload,
			    size_t payload_len,
			    char *id_out,
			    size_t id_sz,
			    char keys_out[][ELA_WS_CONFIG_KEY_MAX],
			    size_t max_keys,
			    size_t *n_keys_out)
{
	struct json_object *root = NULL;
	struct json_object *type_obj = NULL;
	struct json_object *id_obj = NULL;
	struct json_object *keys_obj = NULL;
	struct json_tokener *tok = NULL;
	const char *id_str;
	size_t n = 0;
	int rc = -1;

	if (!payload || payload_len == 0 || !id_out || id_sz == 0 ||
	    !keys_out || max_keys == 0 || !n_keys_out)
		return -1;

	id_out[0] = '\0';
	*n_keys_out = 0;

	/* Parse with an explicit length: the frame payload is not guaranteed to
	 * be NUL-terminated, and it is operator-supplied. */
	tok = json_tokener_new();
	if (!tok)
		return -1;
	root = json_tokener_parse_ex(tok, payload, (int)payload_len);
	json_tokener_free(tok);
	if (!root)
		return -1;

	if (!json_object_is_type(root, json_type_object))
		goto out;

	if (!json_object_object_get_ex(root, "_type", &type_obj) ||
	    !json_object_is_type(type_obj, json_type_string) ||
	    strcmp(json_object_get_string(type_obj), "config.get"))
		goto out;

	if (!json_object_object_get_ex(root, "id", &id_obj) ||
	    !json_object_is_type(id_obj, json_type_string))
		goto out;

	id_str = json_object_get_string(id_obj);
	if (!id_str || !*id_str || strlen(id_str) >= id_sz)
		goto out;
	snprintf(id_out, id_sz, "%s", id_str);

	/* A request with no usable keys is still a valid request — it gets an
	 * empty values object rather than an error, so a caller asking for a
	 * mix of allowed and disallowed names gets what it may have. */
	if (json_object_object_get_ex(root, "keys", &keys_obj) &&
	    json_object_is_type(keys_obj, json_type_array)) {
		size_t len = json_object_array_length(keys_obj);
		size_t i;

		for (i = 0; i < len && n < max_keys; i++) {
			struct json_object *item = json_object_array_get_idx(keys_obj, i);
			const char *name;

			if (!item || !json_object_is_type(item, json_type_string))
				continue;
			name = json_object_get_string(item);
			if (!name || strlen(name) >= ELA_WS_CONFIG_KEY_MAX)
				continue;
			if (!ela_ws_config_key_is_readable(name))
				continue;
			snprintf(keys_out[n], ELA_WS_CONFIG_KEY_MAX, "%s", name);
			n++;
		}
	}

	*n_keys_out = n;
	rc = 0;

out:
	json_object_put(root);
	return rc;
}

int ela_ws_config_build_value_reply(const char *id,
				    const char keys[][ELA_WS_CONFIG_KEY_MAX],
				    const char values[][ELA_WS_CONFIG_VALUE_MAX],
				    size_t n,
				    char *out,
				    size_t out_sz)
{
	struct json_object *root = NULL;
	struct json_object *values_obj = NULL;
	const char *rendered;
	size_t i;
	int rc = -1;

	if (!id || !*id || !out || out_sz == 0 || (n > 0 && (!keys || !values)))
		return -1;

	root = json_object_new_object();
	values_obj = json_object_new_object();
	if (!root || !values_obj) {
		if (root)
			json_object_put(root);
		if (values_obj)
			json_object_put(values_obj);
		return -1;
	}

	json_object_object_add(root, "_type", json_object_new_string("config.value"));
	json_object_object_add(root, "id", json_object_new_string(id));

	for (i = 0; i < n; i++)
		json_object_object_add(values_obj, keys[i],
				       json_object_new_string(values[i]));

	json_object_object_add(root, "values", values_obj);

	rendered = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
	if (!rendered || strlen(rendered) >= out_sz)
		goto out;

	snprintf(out, out_sz, "%s", rendered);
	rc = 0;

out:
	json_object_put(root);
	return rc;
}
