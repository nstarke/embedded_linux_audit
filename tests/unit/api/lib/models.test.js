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

const { defineModels } = require('../../../../api/lib/db/models');

describe('db models', () => {
  test('defines expected models and wires associations', () => {
    const models = {};
    const define = jest.fn((name, attrs, options) => {
      const model = {
        name,
        rawAttributes: attrs,
        options,
        hasMany: jest.fn(),
        belongsTo: jest.fn(),
        hasOne: jest.fn(),
      };
      models[name] = model;
      return model;
    });
    const sequelize = { define };

    const result = defineModels(sequelize);

    expect(Object.keys(result).sort()).toEqual([
      'ArchReport',
      'CommandUpload',
      'Device',
      'DeviceAlias',
      'EfiVariable',
      'FileListEntry',
      'GrepMatch',
      'LogEvent',
      'SymlinkListEntry',
      'TerminalConnection',
      'UbootEnvCandidate',
      'UbootEnvVariable',
      'Upload',
    ]);

    expect(models.Device.options).toEqual(expect.objectContaining({
      tableName: 'devices',
      underscored: true,
    }));
    expect(models.Device.rawAttributes.macAddress).toEqual(expect.objectContaining({
      allowNull: false,
      unique: true,
      field: 'mac_address',
    }));
    expect(models.Upload.options).toEqual(expect.objectContaining({
      tableName: 'uploads',
      underscored: true,
    }));
    expect(models.CommandUpload.options).toEqual(expect.objectContaining({
      tableName: 'command_uploads',
      timestamps: false,
    }));
    expect(models.DeviceAlias.rawAttributes.source.defaultValue).toBe('terminal_api');
    expect(models.TerminalConnection.options).toEqual(expect.objectContaining({
      tableName: 'terminal_connections',
      updatedAt: false,
      createdAt: 'created_at',
    }));

    expect(models.Device.hasMany).toHaveBeenCalledWith(models.Upload, { foreignKey: 'deviceId' });
    expect(models.Upload.belongsTo).toHaveBeenCalledWith(models.Device, { foreignKey: 'deviceId' });
    expect(models.Upload.hasOne).toHaveBeenCalledWith(models.CommandUpload, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.FileListEntry, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.SymlinkListEntry, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.EfiVariable, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.UbootEnvCandidate, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.UbootEnvVariable, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.LogEvent, { foreignKey: 'uploadId' });
    expect(models.Upload.hasOne).toHaveBeenCalledWith(models.ArchReport, { foreignKey: 'uploadId' });
    expect(models.Upload.hasMany).toHaveBeenCalledWith(models.GrepMatch, { foreignKey: 'uploadId' });
    expect(models.Device.hasOne).toHaveBeenCalledWith(models.DeviceAlias, { foreignKey: 'deviceId' });
    expect(models.DeviceAlias.belongsTo).toHaveBeenCalledWith(models.Device, { foreignKey: 'deviceId' });
    expect(models.Device.hasMany).toHaveBeenCalledWith(models.TerminalConnection, { foreignKey: 'deviceId' });
    expect(models.TerminalConnection.belongsTo).toHaveBeenCalledWith(models.Device, { foreignKey: 'deviceId' });
  });
});
