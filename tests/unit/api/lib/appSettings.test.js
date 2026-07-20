'use strict';

const { normalizeRingSize, DEFAULT_RING_SIZE, MAX_RING_SIZE } = require('../../../../api/lib/fuzzRing');

function loadAppSettings(AppSetting) {
  jest.resetModules();
  jest.doMock('../../../../api/lib/db/index', () => ({ getModels: () => ({ AppSetting }) }));
  return require('../../../../api/lib/db/appSettings');
}

describe('fuzz ring size setting', () => {
  afterEach(() => { jest.resetModules(); });

  test('normalizeRingSize falls back rather than throwing on junk', () => {
    expect(normalizeRingSize(25)).toBe(25);
    expect(normalizeRingSize('25')).toBe(25); // stored as TEXT, read back as a string
    expect(normalizeRingSize(null)).toBe(DEFAULT_RING_SIZE);
    expect(normalizeRingSize('abc')).toBe(DEFAULT_RING_SIZE);
    expect(normalizeRingSize(0)).toBe(DEFAULT_RING_SIZE);
    expect(normalizeRingSize(-5)).toBe(DEFAULT_RING_SIZE);
    expect(normalizeRingSize(2.5)).toBe(DEFAULT_RING_SIZE);
    expect(normalizeRingSize(999999)).toBe(MAX_RING_SIZE); // clamped, not rejected
  });

  test('getFuzzRingSize returns the default when the setting was never written', async () => {
    const AppSetting = { findOne: jest.fn().mockResolvedValue(null) };
    const { getFuzzRingSize } = loadAppSettings(AppSetting);
    await expect(getFuzzRingSize()).resolves.toBe(DEFAULT_RING_SIZE);
    expect(AppSetting.findOne).toHaveBeenCalledWith({ where: { key: 'fuzz_ring_size' } });
  });

  test('getFuzzRingSize coerces the stored TEXT value to a number', async () => {
    const AppSetting = { findOne: jest.fn().mockResolvedValue({ value: '42' }) };
    const { getFuzzRingSize } = loadAppSettings(AppSetting);
    await expect(getFuzzRingSize()).resolves.toBe(42);
  });

  test('setFuzzRingSize updates an existing row instead of creating a second one', async () => {
    const row = { update: jest.fn().mockResolvedValue({}) };
    const AppSetting = { findOrCreate: jest.fn().mockResolvedValue([row, false]) };
    const { setFuzzRingSize } = loadAppSettings(AppSetting);

    await expect(setFuzzRingSize(30)).resolves.toBe(30);
    expect(row.update).toHaveBeenCalledWith({ value: '30' });
  });

  test('setFuzzRingSize leaves a freshly created row alone', async () => {
    const row = { update: jest.fn() };
    const AppSetting = { findOrCreate: jest.fn().mockResolvedValue([row, true]) };
    const { setFuzzRingSize } = loadAppSettings(AppSetting);

    await expect(setFuzzRingSize(7)).resolves.toBe(7);
    expect(row.update).not.toHaveBeenCalled();
    expect(AppSetting.findOrCreate).toHaveBeenCalledWith({
      where: { key: 'fuzz_ring_size' },
      defaults: { key: 'fuzz_ring_size', value: '7' },
    });
  });

  test('setFuzzRingSize rejects out-of-range values rather than clamping them', async () => {
    // reads clamp (never break a fuzz); writes reject (tell the operator)
    const AppSetting = { findOrCreate: jest.fn() };
    const { setFuzzRingSize } = loadAppSettings(AppSetting);

    for (const bad of [0, -1, 2.5, 'abc', undefined, null, MAX_RING_SIZE + 1]) {
      await expect(setFuzzRingSize(bad)).rejects.toThrow(RangeError);
    }
    expect(AppSetting.findOrCreate).not.toHaveBeenCalled();
  });
});
