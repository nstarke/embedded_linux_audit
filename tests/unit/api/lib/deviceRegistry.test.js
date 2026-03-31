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
