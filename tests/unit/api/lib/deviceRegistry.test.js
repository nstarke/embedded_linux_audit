'use strict';

function loadDeviceRegistry({ models, sequelize } = {}) {
  jest.resetModules();

  const getModels = jest.fn(() => models);
  const getSequelize = jest.fn(() => sequelize);

  jest.doMock('../../../../api/lib/db/index', () => ({
    getModels,
    getSequelize,
  }));

  const registry = require('../../../../api/lib/db/deviceRegistry');
  return { registry, getModels, getSequelize };
}

describe('device registry', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  describe('normalizeMac', () => {
    test('collapses colon, dash, and bare 12-hex spellings to one dash form', () => {
      const { registry } = loadDeviceRegistry({ models: {} });
      const canonical = '20-4c-03-32-75-5c';
      expect(registry.normalizeMac('20:4C:03:32:75:5C')).toBe(canonical);
      expect(registry.normalizeMac('20-4c-03-32-75-5c')).toBe(canonical);
      expect(registry.normalizeMac('204c0332755c')).toBe(canonical);
    });

    test('passes through non-canonical inputs lowercased (no 12-hex MAC)', () => {
      const { registry } = loadDeviceRegistry({ models: {} });
      expect(registry.normalizeMac('aa:bb')).toBe('aa:bb');
      expect(registry.normalizeMac(null)).toBeNull();
    });
  });

  test('ensureDevice canonicalizes a colon MAC to dash form before findOrCreate', async () => {
    const device = { id: 9, lastSeenAt: new Date('2026-01-01T00:00:00Z'), save: jest.fn() };
    const models = { Device: { findOrCreate: jest.fn().mockResolvedValue([device]) } };
    const { registry } = loadDeviceRegistry({ models });
    const seenAt = new Date('2026-01-01T00:00:00Z');

    await registry.ensureDevice('20:4C:03:32:75:5C', 'tx', seenAt);

    expect(models.Device.findOrCreate).toHaveBeenCalledWith({
      where: { macAddress: '20-4c-03-32-75-5c' },
      defaults: { macAddress: '20-4c-03-32-75-5c', firstSeenAt: seenAt, lastSeenAt: seenAt },
      transaction: 'tx',
    });
  });

  test('ensureDevice updates lastSeenAt when a newer timestamp is observed', async () => {
    const device = {
      id: 1,
      lastSeenAt: new Date('2026-01-01T00:00:00Z'),
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([device]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });
    const seenAt = new Date('2026-02-01T00:00:00Z');

    const result = await registry.ensureDevice('aa:bb', 'tx1', seenAt);

    expect(models.Device.findOrCreate).toHaveBeenCalledWith({
      where: { macAddress: 'aa:bb' },
      defaults: {
        macAddress: 'aa:bb',
        firstSeenAt: seenAt,
        lastSeenAt: seenAt,
      },
      transaction: 'tx1',
    });
    expect(device.save).toHaveBeenCalledWith({ transaction: 'tx1' });
    expect(result).toBe(device);
  });

  test('getDeviceAlias returns null when device is not found', async () => {
    const DeviceAlias = { name: 'DeviceAlias' };
    const models = {
      Device,
      DeviceAlias,
    };
    function Device() {}
    Device.findOne = jest.fn().mockResolvedValue(null);

    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.getDeviceAlias('aa:bb')).resolves.toBeNull();
  });

  test('getDeviceAlias returns alias text when present', async () => {
    const DeviceAlias = { name: 'DeviceAlias' };
    const models = {
      Device,
      DeviceAlias,
    };
    function Device() {}
    Device.findOne = jest.fn().mockResolvedValue({ DeviceAlias: { alias: 'router' } });

    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.getDeviceAlias('aa:bb')).resolves.toBe('router');
    expect(Device.findOne).toHaveBeenCalledWith({
      where: { macAddress: 'aa:bb' },
      include: [{ model: DeviceAlias }],
    });
  });

  test('setDeviceAlias updates an existing alias record', async () => {
    const existing = {
      alias: 'old',
      source: 'old_source',
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
        create: jest.fn(),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceAlias('aa:bb', 'new-name', 'terminal_api')).resolves.toBe('new-name');
    expect(existing.alias).toBe('new-name');
    expect(existing.source).toBe('terminal_api');
    expect(existing.save).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('setDeviceAlias clears alias but keeps row when group is set', async () => {
    const existing = {
      alias: 'old',
      group: '10.0.0.1',
      source: 'terminal_api',
      save: jest.fn().mockResolvedValue(undefined),
      destroy: jest.fn(),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
        create: jest.fn(),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceAlias('aa:bb', '')).resolves.toBeNull();
    expect(existing.alias).toBeNull();
    expect(existing.save).toHaveBeenCalledWith({ transaction: 'tx1' });
    expect(existing.destroy).not.toHaveBeenCalled();
  });

  test('setDeviceAlias removes an existing alias when alias is empty', async () => {
    const existing = {
      destroy: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
        create: jest.fn(),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceAlias('aa:bb', '')).resolves.toBeNull();
    expect(existing.destroy).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('setDeviceAlias creates a new alias when none exists', async () => {
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 9,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ alias: 'router' }),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceAlias('aa:bb', 'router', 'legacy_terminal_file')).resolves.toBe('router');
    expect(models.DeviceAlias.create).toHaveBeenCalledWith({
      deviceId: 9,
      alias: 'router',
      source: 'legacy_terminal_file',
    }, { transaction: 'tx1' });
  });

  test('setDeviceGroup updates an existing record', async () => {
    const existing = {
      alias: 'router',
      group: null,
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceGroup('aa:bb', 'factory-floor')).resolves.toBe('factory-floor');
    expect(existing.group).toBe('factory-floor');
    expect(existing.save).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('setDeviceGroup creates a new record when none exists', async () => {
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 9,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ group: 'lab-bench' }),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceGroup('aa:bb', 'lab-bench')).resolves.toBe('lab-bench');
    expect(models.DeviceAlias.create).toHaveBeenCalledWith({
      deviceId: 9,
      group: 'lab-bench',
    }, { transaction: 'tx1' });
  });

  test('setDeviceGroup clears group but keeps row when alias is set', async () => {
    const existing = {
      alias: 'router',
      group: 'factory-floor',
      save: jest.fn().mockResolvedValue(undefined),
      destroy: jest.fn(),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceGroup('aa:bb', null)).resolves.toBeNull();
    expect(existing.group).toBeNull();
    expect(existing.save).toHaveBeenCalledWith({ transaction: 'tx1' });
    expect(existing.destroy).not.toHaveBeenCalled();
  });

  test('setDeviceGroup removes row when clearing group with no alias', async () => {
    const existing = {
      alias: null,
      group: 'factory-floor',
      destroy: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 7,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(existing),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.setDeviceGroup('aa:bb', null)).resolves.toBeNull();
    expect(existing.destroy).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('recordTerminalConnection returns the connection id, alias, and group', async () => {
    const aliasRecord = {
      alias: 'edge-router',
      group: '10.0.0.1',
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 11,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(aliasRecord),
      },
      TerminalConnection: {
        create: jest.fn().mockResolvedValue({ id: 42 }),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.recordTerminalConnection('aa:bb', '10.0.0.2')).resolves.toEqual({
      connectionId: 42,
      alias: 'edge-router',
      group: '10.0.0.1',
    });
    // group already set — no save needed
    expect(aliasRecord.save).not.toHaveBeenCalled();
    expect(models.TerminalConnection.create).toHaveBeenCalledWith(expect.objectContaining({
      deviceId: 11,
      remoteAddress: '10.0.0.2',
      connectedAt: expect.any(Date),
    }), { transaction: 'tx1' });
  });

  test('recordTerminalConnection initializes group to remoteAddress when no group is set', async () => {
    const aliasRecord = {
      alias: 'edge-router',
      group: null,
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 11,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(aliasRecord),
      },
      TerminalConnection: {
        create: jest.fn().mockResolvedValue({ id: 43 }),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.recordTerminalConnection('aa:bb', '10.0.0.5')).resolves.toEqual({
      connectionId: 43,
      alias: 'edge-router',
      group: '10.0.0.5',
    });
    expect(aliasRecord.group).toBe('10.0.0.5');
    expect(aliasRecord.save).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('recordTerminalConnection creates a new alias record to store group when none exists', async () => {
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 11,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ alias: null, group: '10.0.0.3' }),
      },
      TerminalConnection: {
        create: jest.fn().mockResolvedValue({ id: 44 }),
      },
    };
    const sequelize = {
      transaction: jest.fn(async (fn) => fn('tx1')),
    };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.recordTerminalConnection('aa:bb', '10.0.0.3')).resolves.toEqual({
      connectionId: 44,
      alias: null,
      group: '10.0.0.3',
    });
    expect(models.DeviceAlias.create).toHaveBeenCalledWith({
      deviceId: 11,
      group: '10.0.0.3',
    }, { transaction: 'tx1' });
  });

  test('recordTerminalConnection uses authenticatedUser as group and associates the user with the device', async () => {
    const aliasRecord = {
      alias: null,
      group: null,
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 12,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(aliasRecord),
      },
      TerminalConnection: {
        create: jest.fn().mockResolvedValue({ id: 55 }),
      },
      User: { findOne: jest.fn().mockResolvedValue({ id: 99 }) },
      UserDevice: { findOrCreate: jest.fn().mockResolvedValue([{}, true]) },
    };
    const sequelize = { transaction: jest.fn(async (fn) => fn('tx1')) };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await expect(registry.recordTerminalConnection('aa:bb', '10.0.0.9', 'alice')).resolves.toEqual({
      connectionId: 55,
      alias: null,
      group: 'alice',
    });
    expect(aliasRecord.group).toBe('alice');
    expect(aliasRecord.save).toHaveBeenCalledWith({ transaction: 'tx1' });
    expect(models.User.findOne).toHaveBeenCalledWith({ where: { username: 'alice' }, transaction: 'tx1' });
    expect(models.UserDevice.findOrCreate).toHaveBeenCalledWith({
      where: { userId: 99, deviceId: 12 },
      defaults: { userId: 99, deviceId: 12 },
      transaction: 'tx1',
    });
  });

  test('recordTerminalConnection does not associate when the username is unknown', async () => {
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 12,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: { findOne: jest.fn().mockResolvedValue(null), create: jest.fn().mockResolvedValue({ alias: null, group: 'ghost' }) },
      TerminalConnection: { create: jest.fn().mockResolvedValue({ id: 56 }) },
      User: { findOne: jest.fn().mockResolvedValue(null) },
      UserDevice: { findOrCreate: jest.fn() },
    };
    const sequelize = { transaction: jest.fn(async (fn) => fn('tx1')) };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await registry.recordTerminalConnection('aa:bb', '10.0.0.9', 'ghost');
    expect(models.UserDevice.findOrCreate).not.toHaveBeenCalled();
  });

  test('associateUserDevice creates the link and touches an existing one', async () => {
    const link = { changed: jest.fn(), save: jest.fn().mockResolvedValue(undefined) };
    const models = { UserDevice: { findOrCreate: jest.fn().mockResolvedValue([link, false]) } };
    const { registry } = loadDeviceRegistry({ models });

    await registry.associateUserDevice(99, 12, 'tx1');
    expect(models.UserDevice.findOrCreate).toHaveBeenCalledWith({
      where: { userId: 99, deviceId: 12 },
      defaults: { userId: 99, deviceId: 12 },
      transaction: 'tx1',
    });
    // existing link is touched
    expect(link.changed).toHaveBeenCalledWith('updatedAt', true);
    expect(link.save).toHaveBeenCalledWith({ transaction: 'tx1' });
  });

  test('isUserAssociatedWithDevice returns true when the link exists', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
      Device: { findOne: jest.fn().mockResolvedValue({ id: 3 }) },
      UserDevice: { findOne: jest.fn().mockResolvedValue({ id: 1 }) },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.isUserAssociatedWithDevice('alice', 'aa:bb')).resolves.toBe(true);
    expect(models.User.findOne).toHaveBeenCalledWith({ where: { username: 'alice' } });
    expect(models.Device.findOne).toHaveBeenCalledWith({ where: { macAddress: 'aa:bb' } });
    expect(models.UserDevice.findOne).toHaveBeenCalledWith({ where: { userId: 7, deviceId: 3 } });
  });

  test('isUserAssociatedWithDevice returns false when there is no link', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
      Device: { findOne: jest.fn().mockResolvedValue({ id: 3 }) },
      UserDevice: { findOne: jest.fn().mockResolvedValue(null) },
    };
    const { registry } = loadDeviceRegistry({ models });
    await expect(registry.isUserAssociatedWithDevice('alice', 'aa:bb')).resolves.toBe(false);
  });

  test('isUserAssociatedWithDevice short-circuits on missing inputs, unknown user, or unknown device', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue(null) },
      Device: { findOne: jest.fn() },
      UserDevice: { findOne: jest.fn() },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.isUserAssociatedWithDevice('', 'aa:bb')).resolves.toBe(false);
    await expect(registry.isUserAssociatedWithDevice('alice', '')).resolves.toBe(false);
    expect(models.User.findOne).not.toHaveBeenCalled();

    // unknown user -> false without touching Device
    await expect(registry.isUserAssociatedWithDevice('ghost', 'aa:bb')).resolves.toBe(false);
    expect(models.Device.findOne).not.toHaveBeenCalled();

    // known user, unknown device -> false without touching UserDevice
    models.User.findOne.mockResolvedValueOnce({ id: 7 });
    models.Device.findOne.mockResolvedValueOnce(null);
    await expect(registry.isUserAssociatedWithDevice('alice', 'zz:zz')).resolves.toBe(false);
    expect(models.UserDevice.findOne).not.toHaveBeenCalled();
  });

  test('listUserDeviceMacs returns the MACs of the user\'s associated devices', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
      Device: { name: 'Device' },
      UserDevice: {
        findAll: jest.fn().mockResolvedValue([
          { Device: { macAddress: 'aa:bb' } },
          { Device: { macAddress: 'cc:dd' } },
          { Device: null }, // a link whose device row is missing is skipped
        ]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.listUserDeviceMacs('alice')).resolves.toEqual(['aa:bb', 'cc:dd']);
    expect(models.User.findOne).toHaveBeenCalledWith({ where: { username: 'alice' } });
    expect(models.UserDevice.findAll).toHaveBeenCalledWith({
      where: { userId: 7 },
      include: [{ model: models.Device, attributes: ['macAddress'] }],
    });
  });

  test('listUserDeviceMacs returns [] for a missing or unknown user', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue(null) },
      Device: {},
      UserDevice: { findAll: jest.fn() },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.listUserDeviceMacs('')).resolves.toEqual([]);
    expect(models.User.findOne).not.toHaveBeenCalled();

    await expect(registry.listUserDeviceMacs('ghost')).resolves.toEqual([]);
    expect(models.UserDevice.findAll).not.toHaveBeenCalled();
  });

  test('addBlockedRemote creates a new entry and returns true', async () => {
    const models = {
      BlockedRemote: {
        findOrCreate: jest.fn().mockResolvedValue([{ cidr: '10.0.0.0/8' }, true]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.addBlockedRemote('10.0.0.0/8')).resolves.toBe(true);
    expect(models.BlockedRemote.findOrCreate).toHaveBeenCalledWith({
      where: { cidr: '10.0.0.0/8' },
      defaults: { cidr: '10.0.0.0/8' },
    });
  });

  test('addBlockedRemote returns false when the entry already exists', async () => {
    const models = {
      BlockedRemote: {
        findOrCreate: jest.fn().mockResolvedValue([{ cidr: '10.0.0.0/8' }, false]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.addBlockedRemote('10.0.0.0/8')).resolves.toBe(false);
  });

  test('getBlockedRemotes returns all records', async () => {
    const records = [{ cidr: '10.0.0.0/8' }, { cidr: '192.168.1.1/32' }];
    const models = {
      BlockedRemote: {
        findAll: jest.fn().mockResolvedValue(records),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.getBlockedRemotes()).resolves.toEqual(records);
  });

  test('deleteDeviceAliasByGroupAndName clears the alias when found', async () => {
    const record = {
      alias: 'edge-router',
      group: 'factory-floor',
      save: jest.fn().mockResolvedValue(undefined),
    };
    const models = {
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(record),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.deleteDeviceAliasByGroupAndName('factory-floor', 'edge-router')).resolves.toBe(true);
    expect(models.DeviceAlias.findOne).toHaveBeenCalledWith({
      where: { alias: 'edge-router', group: 'factory-floor' },
    });
    expect(record.alias).toBeNull();
    expect(record.save).toHaveBeenCalled();
  });

  test('deleteDeviceAliasByGroupAndName returns false when not found', async () => {
    const models = {
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue(null),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.deleteDeviceAliasByGroupAndName('factory-floor', 'nonexistent')).resolves.toBe(false);
  });

  test('loadApiKeyHashes returns key hashes paired with their usernames', async () => {
    const User = { name: 'User' };
    const models = {
      ApiKey: {
        findAll: jest.fn().mockResolvedValue([
          { keyHash: 'abc123', User: { username: 'alice' } },
          { keyHash: 'def456', User: { username: 'bob' } },
        ]),
      },
      User,
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.loadApiKeyHashes()).resolves.toEqual([
      { keyHash: 'abc123', username: 'alice' },
      { keyHash: 'def456', username: 'bob' },
    ]);
    expect(models.ApiKey.findAll).toHaveBeenCalledWith({ where: {}, include: [{ model: User }] });
  });

  test('loadApiKeyHashes filters by scope when one is provided', async () => {
    const User = { name: 'User' };
    const models = {
      ApiKey: {
        findAll: jest.fn().mockResolvedValue([
          { keyHash: 'cli789', User: { username: 'carol' } },
        ]),
      },
      User,
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.loadApiKeyHashes('client')).resolves.toEqual([
      { keyHash: 'cli789', username: 'carol' },
    ]);
    expect(models.ApiKey.findAll).toHaveBeenCalledWith({ where: { scope: 'client' }, include: [{ model: User }] });
  });

  test('loadApiKeyHashes returns an empty array when no keys exist', async () => {
    const User = { name: 'User' };
    const models = {
      ApiKey: { findAll: jest.fn().mockResolvedValue([]) },
      User,
    };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.loadApiKeyHashes()).resolves.toEqual([]);
  });

  test('createUser creates a new user and returns created=true', async () => {
    const user = { id: 1, username: 'alice' };
    const models = {
      User: {
        findOrCreate: jest.fn().mockResolvedValue([user, true]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    const result = await registry.createUser('alice');

    expect(result).toEqual({ user, created: true });
    expect(models.User.findOrCreate).toHaveBeenCalledWith({
      where: { username: 'alice' },
      defaults: { username: 'alice' },
    });
  });

  test('createUser returns created=false when user already exists', async () => {
    const user = { id: 1, username: 'alice' };
    const models = {
      User: {
        findOrCreate: jest.fn().mockResolvedValue([user, false]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });

    const result = await registry.createUser('alice');

    expect(result).toEqual({ user, created: false });
  });

  test('createApiKey upserts user and creates a new key', async () => {
    const user = { id: 7, username: 'bob' };
    const key = { id: 1, userId: 7, keyHash: 'deadbeef', label: 'my key' };
    const models = {
      User: {
        findOrCreate: jest.fn().mockResolvedValue([user, true]),
      },
      ApiKey: {
        findOrCreate: jest.fn().mockResolvedValue([key, true]),
      },
    };
    const sequelize = { transaction: jest.fn(async (fn) => fn('tx1')) };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    const result = await registry.createApiKey('bob', 'deadbeef', 'my key');

    expect(result).toEqual({ key, created: true });
    expect(models.User.findOrCreate).toHaveBeenCalledWith({
      where: { username: 'bob' },
      defaults: { username: 'bob' },
      transaction: 'tx1',
    });
    expect(models.ApiKey.findOrCreate).toHaveBeenCalledWith({
      where: { keyHash: 'deadbeef' },
      defaults: { userId: 7, keyHash: 'deadbeef', label: 'my key', scope: 'agent' },
      transaction: 'tx1',
    });
  });

  test('createApiKey threads an explicit scope into the created key', async () => {
    const user = { id: 7, username: 'bob' };
    const key = { id: 2, userId: 7, keyHash: 'cafebabe', label: 'client', scope: 'client' };
    const models = {
      User: {
        findOrCreate: jest.fn().mockResolvedValue([user, true]),
      },
      ApiKey: {
        findOrCreate: jest.fn().mockResolvedValue([key, true]),
      },
    };
    const sequelize = { transaction: jest.fn(async (fn) => fn('tx1')) };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    await registry.createApiKey('bob', 'cafebabe', 'client', 'client');

    expect(models.ApiKey.findOrCreate).toHaveBeenCalledWith({
      where: { keyHash: 'cafebabe' },
      defaults: { userId: 7, keyHash: 'cafebabe', label: 'client', scope: 'client' },
      transaction: 'tx1',
    });
  });

  test('createApiKey returns created=false when key hash already exists', async () => {
    const user = { id: 7, username: 'bob' };
    const key = { id: 1, userId: 7, keyHash: 'deadbeef', label: null };
    const models = {
      User: {
        findOrCreate: jest.fn().mockResolvedValue([user, false]),
      },
      ApiKey: {
        findOrCreate: jest.fn().mockResolvedValue([key, false]),
      },
    };
    const sequelize = { transaction: jest.fn(async (fn) => fn('tx1')) };
    const { registry } = loadDeviceRegistry({ models, sequelize });

    const result = await registry.createApiKey('bob', 'deadbeef', null);

    expect(result).toEqual({ key, created: false });
  });

  test('getUserWithKeys returns null when the user does not exist', async () => {
    const ApiKey = { name: 'ApiKey' };
    const models = { User: { findOne: jest.fn().mockResolvedValue(null) }, ApiKey };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.getUserWithKeys('ghost')).resolves.toBeNull();
  });

  test('getUserWithKeys returns the user and its keys', async () => {
    const ApiKey = { name: 'ApiKey' };
    const user = {
      id: 5,
      username: 'alice',
      ApiKeys: [
        { keyHash: 'agenthash', scope: 'agent', label: null },
        { keyHash: 'clienthash', scope: 'client', label: 'client' },
      ],
    };
    const models = { User: { findOne: jest.fn().mockResolvedValue(user) }, ApiKey };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.getUserWithKeys('alice')).resolves.toEqual({
      id: 5,
      username: 'alice',
      keys: [
        { keyHash: 'agenthash', scope: 'agent', label: null },
        { keyHash: 'clienthash', scope: 'client', label: 'client' },
      ],
    });
    expect(models.User.findOne).toHaveBeenCalledWith({
      where: { username: 'alice' },
      include: [{ model: ApiKey }],
    });
  });

  test('deleteUserByUsername destroys the user row (keys cascade at the db level)', async () => {
    const models = { User: { destroy: jest.fn().mockResolvedValue(1) } };
    const { registry } = loadDeviceRegistry({ models });

    await expect(registry.deleteUserByUsername('alice')).resolves.toBe(1);
    expect(models.User.destroy).toHaveBeenCalledWith({ where: { username: 'alice' } });
  });

  test('touchTerminalHeartbeat and closeTerminalConnection update the connection record', async () => {
    const models = {
      TerminalConnection: {
        update: jest.fn().mockResolvedValue([1]),
      },
    };
    const { registry } = loadDeviceRegistry({ models });
    const heartbeatAt = new Date('2026-03-01T00:00:00Z');
    const disconnectedAt = new Date('2026-03-02T00:00:00Z');

    await registry.touchTerminalHeartbeat(5, heartbeatAt);
    await registry.closeTerminalConnection(5, disconnectedAt);

    expect(models.TerminalConnection.update).toHaveBeenNthCalledWith(1, {
      lastHeartbeatAt: heartbeatAt,
    }, {
      where: { id: 5 },
    });
    expect(models.TerminalConnection.update).toHaveBeenNthCalledWith(2, {
      disconnectedAt,
    }, {
      where: { id: 5 },
    });
  });
});
