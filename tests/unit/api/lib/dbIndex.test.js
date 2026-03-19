'use strict';

const path = require('path');

function loadDbModule({ config = {}, defineModelsImpl } = {}) {
  jest.resetModules();

  const sequelizeInstances = [];
  const Sequelize = jest.fn(function (...args) {
    this.args = args;
    this.authenticate = jest.fn().mockResolvedValue(undefined);
    this.close = jest.fn().mockResolvedValue(undefined);
    this.getQueryInterface = jest.fn(() => ({ qi: true }));
    sequelizeInstances.push(this);
  });
  const SequelizeStorage = jest.fn((value) => ({ storageArgs: value }));
  const Umzug = jest.fn(function (value) {
    this.options = value;
    this.up = jest.fn().mockResolvedValue([{ name: '0001-initial' }]);
  });
  const defineModels = jest.fn(defineModelsImpl || ((sequelize) => ({ Device: { sequelize } })));

  jest.doMock('../../../../api/lib/config', () => ({
    getDatabaseConfig: jest.fn(() => ({
      host: 'db',
      port: 5432,
      database: 'ela',
      username: 'ela',
      password: 'ela',
      ssl: false,
      logging: false,
      url: null,
      ...config,
    })),
  }));
  jest.doMock('sequelize', () => ({ Sequelize }), { virtual: true });
  jest.doMock('umzug', () => ({ Umzug, SequelizeStorage }), { virtual: true });
  jest.doMock('../../../../api/lib/db/models', () => ({ defineModels }));

  const mod = require('../../../../api/lib/db');
  return { mod, Sequelize, Umzug, SequelizeStorage, defineModels, sequelizeInstances };
}

describe('db index', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('createSequelize uses database URL with ssl and logging options', () => {
    const { mod, Sequelize } = loadDbModule({
      config: {
        url: 'postgres://ela:pw@db/ela',
        ssl: true,
        logging: true,
      },
    });

    mod.createSequelize();

    expect(Sequelize).toHaveBeenCalledWith('postgres://ela:pw@db/ela', expect.objectContaining({
      dialect: 'postgres',
      logging: console.log,
      dialectOptions: {
        ssl: {
          require: true,
          rejectUnauthorized: false,
        },
      },
    }));
  });

  test('createSequelize uses discrete connection fields when no URL is provided', () => {
    const { mod, Sequelize } = loadDbModule({
      config: {
        host: 'db.internal',
        port: 6543,
        database: 'audit',
        username: 'audit_user',
        password: 'secret',
      },
    });

    mod.createSequelize();

    expect(Sequelize).toHaveBeenCalledWith('audit', 'audit_user', 'secret', expect.objectContaining({
      host: 'db.internal',
      port: 6543,
      dialect: 'postgres',
      logging: false,
      dialectOptions: {},
    }));
  });

  test('getSequelize and getModels are singletons until closeDatabase', async () => {
    const { mod, defineModels, sequelizeInstances } = loadDbModule();

    const firstSequelize = mod.getSequelize();
    const secondSequelize = mod.getSequelize();
    const firstModels = mod.getModels();
    const secondModels = mod.getModels();

    expect(firstSequelize).toBe(secondSequelize);
    expect(firstModels).toBe(secondModels);
    expect(defineModels).toHaveBeenCalledTimes(1);

    await mod.closeDatabase();

    expect(firstSequelize.close).toHaveBeenCalledTimes(1);

    const reopened = mod.getSequelize();
    expect(reopened).not.toBe(firstSequelize);
    expect(sequelizeInstances).toHaveLength(2);
  });

  test('createMigrator wires Umzug to the current sequelize query interface', () => {
    const { mod, Umzug, SequelizeStorage } = loadDbModule();
    const sequelize = mod.getSequelize();

    const migrator = mod.createMigrator();

    expect(Umzug).toHaveBeenCalledWith(expect.objectContaining({
      migrations: expect.objectContaining({
        glob: expect.stringContaining(`${path.sep}migrations${path.sep}*.js`),
      }),
      context: sequelize.getQueryInterface(),
      storage: { storageArgs: { sequelize } },
      logger: console,
    }));
    expect(SequelizeStorage).toHaveBeenCalledWith({ sequelize });
    expect(migrator).toBeInstanceOf(Umzug);
  });

  test('initializeDatabase authenticates and returns sequelize plus models', async () => {
    const { mod } = loadDbModule({
      defineModelsImpl: () => ({ Device: { name: 'Device' } }),
    });

    const initialized = await mod.initializeDatabase();

    expect(initialized.sequelize.authenticate).toHaveBeenCalledTimes(1);
    expect(initialized.models).toEqual({ Device: { name: 'Device' } });
  });

  test('runMigrations delegates to migrator.up', async () => {
    const { mod } = loadDbModule();

    await expect(mod.runMigrations()).resolves.toEqual([{ name: '0001-initial' }]);
  });
});
