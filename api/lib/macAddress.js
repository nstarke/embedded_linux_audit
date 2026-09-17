// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Compare MAC spellings independently of case and separators. Validation is
// left to callers so each endpoint keeps its existing accepted input forms.
function macKey(mac) {
  return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

module.exports = { macKey };
