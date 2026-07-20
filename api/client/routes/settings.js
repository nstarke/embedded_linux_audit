// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');
const { DEFAULT_RING_SIZE, MAX_RING_SIZE } = require('../../lib/fuzzRing');

// Lazily resolve the settings store so importing this module (e.g. in tests)
// does not pull in db/index, mirroring routes/gdb.js.
function appSettings() {
  return require('../../lib/db/appSettings');
}

/**
 * Register the deployment-settings routes on the client API.
 *
 * These are global (not device-scoped), so unlike the terminal/gdb routes they
 * carry no MAC and no per-device ACL — any authenticated client user may read
 * and write them. There is no admin role in the key scopes today; if one is
 * added, the write below is where it belongs.
 *
 * @param {object} app
 * @param {object} deps
 * @param {Function} [deps.getFuzzRingSize] () => Promise<number>.
 * @param {Function} [deps.setFuzzRingSize] (size) => Promise<number>; throws RangeError.
 * @param {Function} [deps.parseBody] body-parser middleware override.
 */
function registerSettingsRoutes(app, deps = {}) {
  const {
    getFuzzRingSize = () => appSettings().getFuzzRingSize(),
    setFuzzRingSize = (size) => appSettings().setFuzzRingSize(size),
    parseBody = express.json({ limit: 64 * 1024, type: () => true }),
  } = deps;

  // GET /settings/fuzz-ring-size — how many streamed fuzz cases the companion
  // server retains per connection for host-panic crash capture.
  app.get('/settings/fuzz-ring-size', async (req, res) => {
    let ringSize;
    try {
      ringSize = await getFuzzRingSize();
    } catch {
      res.status(500).json({ error: 'internal error' });
      return;
    }
    res.status(200).json({ ringSize, default: DEFAULT_RING_SIZE, max: MAX_RING_SIZE });
  });

  // PUT /settings/fuzz-ring-size — takes effect on the next fuzz connection;
  // runs already streaming keep the size they opened with.
  app.put('/settings/fuzz-ring-size', parseBody, async (req, res) => {
    const { ringSize } = req.body || {};
    let saved;
    try {
      saved = await setFuzzRingSize(ringSize);
    } catch (err) {
      if (err instanceof RangeError) {
        res.status(400).json({ error: err.message });
        return;
      }
      res.status(500).json({ error: 'internal error' });
      return;
    }
    res.status(200).json({ ringSize: saved, default: DEFAULT_RING_SIZE, max: MAX_RING_SIZE });
  });
}

module.exports = registerSettingsRoutes;
