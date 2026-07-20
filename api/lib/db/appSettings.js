// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { getModels } = require('./index');
const {
  normalizeRingSize,
  DEFAULT_RING_SIZE,
  MAX_RING_SIZE,
} = require('../fuzzRing');

const FUZZ_RING_SIZE_KEY = 'fuzz_ring_size';

// Deliberately NOT cached. The agent API and the client API are separate
// processes with separate pools, so an in-process cache would let a client-side
// write go unseen by the agent until restart. Reads are one indexed lookup per
// fuzz connection, which is nothing next to a fuzz run.
async function getSetting(key) {
  const { AppSetting } = getModels();
  const row = await AppSetting.findOne({ where: { key } });
  return row ? row.value : null;
}

async function setSetting(key, value) {
  const { AppSetting } = getModels();
  const [row, created] = await AppSetting.findOrCreate({
    where: { key },
    defaults: { key, value: String(value) },
  });
  if (!created) await row.update({ value: String(value) });
  return row;
}

// The number of streamed fuzz cases the companion server holds per connection.
// An unset, malformed, or out-of-range stored value falls back to the default
// rather than failing the fuzz -- crash capture matters more than the knob.
async function getFuzzRingSize() {
  return normalizeRingSize(await getSetting(FUZZ_RING_SIZE_KEY));
}

async function setFuzzRingSize(size) {
  const n = Number(size);
  if (!Number.isInteger(n) || n < 1 || n > MAX_RING_SIZE) {
    throw new RangeError(`ring size must be an integer between 1 and ${MAX_RING_SIZE}`);
  }
  await setSetting(FUZZ_RING_SIZE_KEY, n);
  return n;
}

module.exports = {
  FUZZ_RING_SIZE_KEY,
  DEFAULT_RING_SIZE,
  MAX_RING_SIZE,
  getSetting,
  setSetting,
  getFuzzRingSize,
  setFuzzRingSize,
};
