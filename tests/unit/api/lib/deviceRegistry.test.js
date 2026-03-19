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

  test('recordTerminalConnection returns the connection id and alias', async () => {
    const models = {
      Device: {
        findOrCreate: jest.fn().mockResolvedValue([{
          id: 11,
          lastSeenAt: new Date('2026-01-01T00:00:00Z'),
          save: jest.fn().mockResolvedValue(undefined),
        }]),
      },
      DeviceAlias: {
        findOne: jest.fn().mockResolvedValue({ alias: 'edge-router' }),
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
    });
    expect(models.TerminalConnection.create).toHaveBeenCalledWith(expect.objectContaining({
      deviceId: 11,
      remoteAddress: '10.0.0.2',
      connectedAt: expect.any(Date),
    }), { transaction: 'tx1' });
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
