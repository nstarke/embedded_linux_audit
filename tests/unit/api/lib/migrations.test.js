'use strict';

jest.mock('sequelize', () => ({
  DataTypes: new Proxy({}, {
    get(_target, prop) {
      if (prop === 'BLOB') {
        return (...args) => ({ kind: 'BLOB', args });
      }
      if (prop === 'STRING') {
        return (...args) => ({ kind: 'STRING', args });
      }
      return { kind: String(prop) };
    },
  }),
}), { virtual: true });

const migration0001 = require('../../../../api/lib/db/migrations/0001-initial-schema');
const migration0002 = require('../../../../api/lib/db/migrations/0002-device-aliases-and-new-upload-types');
const migration0003 = require('../../../../api/lib/db/migrations/0003-upload-local-artifact-path');
const migration0004 = require('../../../../api/lib/db/migrations/0004-device-group');
const migration0005 = require('../../../../api/lib/db/migrations/0005-alias-group-unique');
const migration0006 = require('../../../../api/lib/db/migrations/0006-blocked-remotes');
const migration0007 = require('../../../../api/lib/db/migrations/0007-users');
const migration0008 = require('../../../../api/lib/db/migrations/0008-api-keys');

function createQueryInterface() {
  return {
    createTable: jest.fn().mockResolvedValue(undefined),
    addIndex: jest.fn().mockResolvedValue(undefined),
    removeIndex: jest.fn().mockResolvedValue(undefined),
    dropTable: jest.fn().mockResolvedValue(undefined),
    addColumn: jest.fn().mockResolvedValue(undefined),
    removeColumn: jest.fn().mockResolvedValue(undefined),
    changeColumn: jest.fn().mockResolvedValue(undefined),
  };
}

describe('db migrations', () => {
  test('0001 initial schema creates and drops the core upload tables', async () => {
    const queryInterface = createQueryInterface();

    await migration0001.up({ context: queryInterface });

    expect(queryInterface.createTable).toHaveBeenCalledWith('devices', expect.objectContaining({
      mac_address: expect.objectContaining({ allowNull: false, unique: true }),
      first_seen_at: expect.any(Object),
      last_seen_at: expect.any(Object),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('uploads', expect.objectContaining({
      device_id: expect.objectContaining({
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      }),
      upload_type: expect.any(Object),
      payload_binary: expect.any(Object),
      payload_sha256: expect.any(Object),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('command_uploads', expect.objectContaining({
      upload_id: expect.objectContaining({
        primaryKey: true,
        references: { model: 'uploads', key: 'id' },
      }),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('log_events', expect.objectContaining({
      event_type: expect.any(Object),
      metadata: expect.any(Object),
    }));
    expect(queryInterface.addIndex).toHaveBeenCalledWith('uploads', ['device_id', 'upload_type']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('uploads', ['api_timestamp']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('file_list_entries', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('symlink_list_entries', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('efi_variables', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('uboot_env_candidates', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('uboot_env_variables', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('log_events', ['upload_id']);

    await migration0001.down({ context: queryInterface });
    expect(queryInterface.dropTable).toHaveBeenNthCalledWith(1, 'log_events');
    expect(queryInterface.dropTable).toHaveBeenNthCalledWith(9, 'devices');
  });

  test('0002 alias and new upload type migration creates indexes and drops in reverse order', async () => {
    const queryInterface = createQueryInterface();

    await migration0002.up({ context: queryInterface });

    expect(queryInterface.createTable).toHaveBeenCalledWith('device_aliases', expect.objectContaining({
      device_id: expect.objectContaining({
        unique: true,
        references: { model: 'devices', key: 'id' },
      }),
      source: expect.objectContaining({ defaultValue: 'terminal_api' }),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('terminal_connections', expect.objectContaining({
      device_id: expect.objectContaining({
        references: { model: 'devices', key: 'id' },
      }),
      last_heartbeat_at: expect.any(Object),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('arch_reports', expect.objectContaining({
      upload_id: expect.objectContaining({
        primaryKey: true,
        references: { model: 'uploads', key: 'id' },
      }),
    }));
    expect(queryInterface.createTable).toHaveBeenCalledWith('grep_matches', expect.objectContaining({
      upload_id: expect.objectContaining({
        references: { model: 'uploads', key: 'id' },
      }),
      file_path: expect.any(Object),
    }));
    expect(queryInterface.addIndex).toHaveBeenCalledWith('device_aliases', ['alias'], { unique: true });
    expect(queryInterface.addIndex).toHaveBeenCalledWith('terminal_connections', ['device_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('terminal_connections', ['connected_at']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('grep_matches', ['upload_id']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('grep_matches', ['file_path']);

    await migration0002.down({ context: queryInterface });
    expect(queryInterface.dropTable).toHaveBeenNthCalledWith(1, 'grep_matches');
    expect(queryInterface.dropTable).toHaveBeenNthCalledWith(4, 'device_aliases');
  });

  test('0003 adds and removes local_artifact_path on uploads', async () => {
    const queryInterface = createQueryInterface();

    await migration0003.up({ context: queryInterface });
    expect(queryInterface.addColumn).toHaveBeenCalledWith('uploads', 'local_artifact_path', {
      type: expect.any(Object),
      allowNull: true,
    });

    await migration0003.down({ context: queryInterface });
    expect(queryInterface.removeColumn).toHaveBeenCalledWith('uploads', 'local_artifact_path');
  });

  test('0005 replaces global alias uniqueness with per-group uniqueness', async () => {
    const queryInterface = createQueryInterface();

    await migration0005.up({ context: queryInterface });
    expect(queryInterface.removeIndex).toHaveBeenCalledWith('device_aliases', ['alias']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('device_aliases', ['alias', 'group'], { unique: true });

    await migration0005.down({ context: queryInterface });
    expect(queryInterface.removeIndex).toHaveBeenCalledWith('device_aliases', ['alias', 'group']);
    expect(queryInterface.addIndex).toHaveBeenCalledWith('device_aliases', ['alias'], { unique: true });
  });

  test('0004 adds group column and makes alias nullable', async () => {
    const queryInterface = createQueryInterface();

    await migration0004.up({ context: queryInterface });
    expect(queryInterface.changeColumn).toHaveBeenCalledWith('device_aliases', 'alias', {
      type: expect.any(Object),
      allowNull: true,
    });
    expect(queryInterface.addColumn).toHaveBeenCalledWith('device_aliases', 'group', {
      type: expect.any(Object),
      allowNull: true,
    });

    await migration0004.down({ context: queryInterface });
    expect(queryInterface.removeColumn).toHaveBeenCalledWith('device_aliases', 'group');
    expect(queryInterface.changeColumn).toHaveBeenCalledWith('device_aliases', 'alias', {
      type: expect.any(Object),
      allowNull: false,
    });
  });

  test('0006 creates and drops the blocked_remotes table', async () => {
    const queryInterface = createQueryInterface();

    await migration0006.up({ context: queryInterface });
    expect(queryInterface.createTable).toHaveBeenCalledWith('blocked_remotes', expect.objectContaining({
      cidr: expect.objectContaining({ allowNull: false, unique: true }),
      created_at: expect.any(Object),
    }));

    await migration0006.down({ context: queryInterface });
    expect(queryInterface.dropTable).toHaveBeenCalledWith('blocked_remotes');
  });

  test('0007 creates and drops the users table', async () => {
    const queryInterface = createQueryInterface();

    await migration0007.up({ context: queryInterface });
    expect(queryInterface.createTable).toHaveBeenCalledWith('users', expect.objectContaining({
      username: expect.objectContaining({ allowNull: false, unique: true }),
      created_at: expect.any(Object),
    }));

    await migration0007.down({ context: queryInterface });
    expect(queryInterface.dropTable).toHaveBeenCalledWith('users');
  });

  test('0008 creates the api_keys table with a user_id index and drops it', async () => {
    const queryInterface = createQueryInterface();

    await migration0008.up({ context: queryInterface });
    expect(queryInterface.createTable).toHaveBeenCalledWith('api_keys', expect.objectContaining({
      user_id: expect.objectContaining({
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onDelete: 'CASCADE',
      }),
      key_hash: expect.objectContaining({ allowNull: false, unique: true }),
      label: expect.objectContaining({ allowNull: true }),
    }));
    expect(queryInterface.addIndex).toHaveBeenCalledWith('api_keys', ['user_id']);

    await migration0008.down({ context: queryInterface });
    expect(queryInterface.dropTable).toHaveBeenCalledWith('api_keys');
  });
});
