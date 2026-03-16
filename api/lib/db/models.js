'use strict';

const { DataTypes } = require('sequelize');

function defineModels(sequelize) {
  const Device = sequelize.define('Device', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    macAddress: {
      type: DataTypes.STRING(17),
      allowNull: false,
      unique: true,
      field: 'mac_address',
    },
    firstSeenAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'first_seen_at',
    },
    lastSeenAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'last_seen_at',
    },
  }, {
    tableName: 'devices',
    underscored: true,
  });

  const Upload = sequelize.define('Upload', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    deviceId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'device_id',
    },
    uploadType: {
      type: DataTypes.STRING(64),
      allowNull: false,
      field: 'upload_type',
    },
    contentType: {
      type: DataTypes.STRING(128),
      allowNull: false,
      field: 'content_type',
    },
    srcIp: {
      type: DataTypes.STRING(64),
      allowNull: true,
      field: 'src_ip',
    },
    apiTimestamp: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'api_timestamp',
    },
    requestFilePath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'request_file_path',
    },
    isSymlink: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'is_symlink',
    },
    symlinkPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'symlink_path',
    },
    payloadText: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'payload_text',
    },
    payloadJson: {
      type: DataTypes.JSONB,
      allowNull: true,
      field: 'payload_json',
    },
    payloadBinary: {
      type: DataTypes.BLOB('long'),
      allowNull: true,
      field: 'payload_binary',
    },
    payloadSha256: {
      type: DataTypes.STRING(64),
      allowNull: false,
      field: 'payload_sha256',
    },
    payloadBytes: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'payload_bytes',
    },
  }, {
    tableName: 'uploads',
    underscored: true,
  });

  const CommandUpload = sequelize.define('CommandUpload', {
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      primaryKey: true,
      field: 'upload_id',
    },
    commandText: {
      type: DataTypes.TEXT,
      allowNull: false,
      field: 'command_text',
    },
    commandOutput: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'command_output',
    },
    commandFormat: {
      type: DataTypes.STRING(32),
      allowNull: false,
      field: 'command_format',
    },
  }, {
    tableName: 'command_uploads',
    underscored: true,
    timestamps: false,
  });

  const FileListEntry = sequelize.define('FileListEntry', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    rootPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'root_path',
    },
    entryPath: {
      type: DataTypes.TEXT,
      allowNull: false,
      field: 'entry_path',
    },
  }, {
    tableName: 'file_list_entries',
    underscored: true,
    timestamps: false,
  });

  const SymlinkListEntry = sequelize.define('SymlinkListEntry', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    rootPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'root_path',
    },
    linkPath: {
      type: DataTypes.TEXT,
      allowNull: false,
      field: 'link_path',
    },
    targetPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'target_path',
    },
  }, {
    tableName: 'symlink_list_entries',
    underscored: true,
    timestamps: false,
  });

  const EfiVariable = sequelize.define('EfiVariable', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    guid: {
      type: DataTypes.STRING(128),
      allowNull: false,
    },
    name: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    attributes: {
      type: DataTypes.BIGINT,
      allowNull: true,
    },
    sizeBytes: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'size_bytes',
    },
    dataHex: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'data_hex',
    },
  }, {
    tableName: 'efi_variables',
    underscored: true,
    timestamps: false,
  });

  const UbootEnvCandidate = sequelize.define('UbootEnvCandidate', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    recordType: {
      type: DataTypes.STRING(64),
      allowNull: false,
      field: 'record_type',
    },
    device: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    offset: {
      type: DataTypes.BIGINT,
      allowNull: true,
    },
    crcEndian: {
      type: DataTypes.STRING(32),
      allowNull: true,
      field: 'crc_endian',
    },
    mode: {
      type: DataTypes.STRING(64),
      allowNull: true,
    },
    hasKnownVars: {
      type: DataTypes.BOOLEAN,
      allowNull: true,
      field: 'has_known_vars',
    },
    cfgOffset: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'cfg_offset',
    },
    envSize: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'env_size',
    },
    eraseSize: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'erase_size',
    },
    sectorCount: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'sector_count',
    },
    pairOffset: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'pair_offset',
    },
  }, {
    tableName: 'uboot_env_candidates',
    underscored: true,
    timestamps: false,
  });

  const UbootEnvVariable = sequelize.define('UbootEnvVariable', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    device: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    offset: {
      type: DataTypes.BIGINT,
      allowNull: true,
    },
    key: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    value: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
  }, {
    tableName: 'uboot_env_variables',
    underscored: true,
    timestamps: false,
  });

  const LogEvent = sequelize.define('LogEvent', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'upload_id',
    },
    recordIndex: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'record_index',
    },
    eventType: {
      type: DataTypes.STRING(64),
      allowNull: false,
      field: 'event_type',
    },
    message: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    phase: {
      type: DataTypes.STRING(64),
      allowNull: true,
    },
    command: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    rc: {
      type: DataTypes.INTEGER,
      allowNull: true,
    },
    mode: {
      type: DataTypes.STRING(64),
      allowNull: true,
    },
    romPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'rom_path',
    },
    sizeBytes: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'size_bytes',
    },
    metadata: {
      type: DataTypes.JSONB,
      allowNull: true,
    },
  }, {
    tableName: 'log_events',
    underscored: true,
    timestamps: false,
  });

  Device.hasMany(Upload, { foreignKey: 'deviceId' });
  Upload.belongsTo(Device, { foreignKey: 'deviceId' });
  Upload.hasOne(CommandUpload, { foreignKey: 'uploadId' });
  Upload.hasMany(FileListEntry, { foreignKey: 'uploadId' });
  Upload.hasMany(SymlinkListEntry, { foreignKey: 'uploadId' });
  Upload.hasMany(EfiVariable, { foreignKey: 'uploadId' });
  Upload.hasMany(UbootEnvCandidate, { foreignKey: 'uploadId' });
  Upload.hasMany(UbootEnvVariable, { foreignKey: 'uploadId' });
  Upload.hasMany(LogEvent, { foreignKey: 'uploadId' });

  return {
    Device,
    Upload,
    CommandUpload,
    FileListEntry,
    SymlinkListEntry,
    EfiVariable,
    UbootEnvCandidate,
    UbootEnvVariable,
    LogEvent,
  };
}

module.exports = {
  defineModels,
};
