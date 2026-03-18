// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_CONF_UTIL_H
#define ELA_CONF_UTIL_H

#include "ela_conf.h"

#include <stdbool.h>

void ela_conf_trim_right(char *s);
void ela_conf_apply_line(struct ela_conf *conf, const char *line);
bool ela_conf_string_is_true(const char *value);

#endif
