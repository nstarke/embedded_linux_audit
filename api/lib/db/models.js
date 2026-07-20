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
    userId: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'user_id',
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
    localArtifactPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'local_artifact_path',
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

  const DeviceAlias = sequelize.define('DeviceAlias', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    deviceId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      unique: true,
      field: 'device_id',
    },
    alias: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    source: {
      type: DataTypes.STRING(64),
      allowNull: false,
      defaultValue: 'terminal_api',
    },
    group: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
  }, {
    tableName: 'device_aliases',
    underscored: true,
  });

  const TerminalConnection = sequelize.define('TerminalConnection', {
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
    remoteAddress: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'remote_address',
    },
    connectedAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'connected_at',
    },
    disconnectedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'disconnected_at',
    },
    lastHeartbeatAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'last_heartbeat_at',
    },
  }, {
    tableName: 'terminal_connections',
    underscored: true,
    updatedAt: false,
    createdAt: 'created_at',
  });

  const ArchReport = sequelize.define('ArchReport', {
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      primaryKey: true,
      field: 'upload_id',
    },
    subcommand: {
      type: DataTypes.STRING(64),
      allowNull: true,
    },
    value: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
  }, {
    tableName: 'arch_reports',
    underscored: true,
    timestamps: false,
  });

  const KernelBuildInfo = sequelize.define('KernelBuildInfo', {
    uploadId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      primaryKey: true,
      field: 'upload_id',
    },
    kernelRelease: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'kernel_release',
    },
    procVersion: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'proc_version',
    },
    vermagic: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    modulePath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'module_path',
    },
    isa: {
      type: DataTypes.STRING(64),
      allowNull: true,
    },
    bits: {
      type: DataTypes.STRING(8),
      allowNull: true,
    },
    endianness: {
      type: DataTypes.STRING(16),
      allowNull: true,
    },
    configSource: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'config_source',
    },
    configAvailable: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'config_available',
    },
    configCompressed: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'config_compressed',
    },
  }, {
    tableName: 'kernel_build_infos',
    underscored: true,
    timestamps: false,
  });

  const ModuleBuildRequest = sequelize.define('ModuleBuildRequest', {
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
    userId: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'user_id',
    },
    buildinfoUploadId: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'buildinfo_upload_id',
    },
    // queued -> building -> succeeded | failed
    status: {
      type: DataTypes.STRING(32),
      allowNull: false,
      defaultValue: 'queued',
    },
    kernelRelease: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'kernel_release',
    },
    isa: {
      type: DataTypes.STRING(64),
      allowNull: false,
    },
    endianness: {
      type: DataTypes.STRING(16),
      allowNull: false,
    },
    deviceVermagic: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'device_vermagic',
    },
    configArtifactPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'config_artifact_path',
    },
    builtVermagic: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'built_vermagic',
    },
    // match | release-match | mismatch | unverified (see kernelTarget.compareVermagic)
    vermagicResult: {
      type: DataTypes.STRING(32),
      allowNull: true,
      field: 'vermagic_result',
    },
    // upstream-exact | upstream-nearest (vendor suffix rebuilt via LOCALVERSION)
    source: {
      type: DataTypes.STRING(32),
      allowNull: true,
    },
    artifactPath: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'artifact_path',
    },
    downloadTokenHash: {
      type: DataTypes.STRING(64),
      allowNull: true,
      field: 'download_token_hash',
    },
    downloadTokenExpiresAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'download_token_expires_at',
    },
    errorMessage: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'error_message',
    },
  }, {
    tableName: 'module_build_requests',
    underscored: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
  });

  const GhidraAnalysisJob = sequelize.define('GhidraAnalysisJob', {
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
    userId: {
      type: DataTypes.BIGINT,
      allowNull: true,
      field: 'user_id',
    },
    // queued -> copying -> analyzing -> succeeded | failed
    status: {
      type: DataTypes.STRING(32),
      allowNull: false,
      defaultValue: 'queued',
    },
    // On-disk directories the worker resolved for this run: the uploaded
    // filesystem root (<data>/<mac>/fs) and the decompiler output root
    // (<data>/<mac>/ghidra), a parallel hierarchy so the .c files never mix
    // with the uploaded binaries.
    fsRoot: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'fs_root',
    },
    outputRoot: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'output_root',
    },
    filesFound: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'files_found',
    },
    filesAnalyzed: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'files_analyzed',
    },
    errorMessage: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'error_message',
    },
  }, {
    tableName: 'ghidra_analysis_jobs',
    underscored: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
  });

  const GrepMatch = sequelize.define('GrepMatch', {
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
    filePath: {
      type: DataTypes.TEXT,
      allowNull: false,
      field: 'file_path',
    },
    lineNumber: {
      type: DataTypes.INTEGER,
      allowNull: true,
      field: 'line_number',
    },
    lineText: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'line_text',
    },
  }, {
    tableName: 'grep_matches',
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
  Upload.hasOne(ArchReport, { foreignKey: 'uploadId' });
  Upload.hasOne(KernelBuildInfo, { foreignKey: 'uploadId' });
  Upload.hasMany(GrepMatch, { foreignKey: 'uploadId' });
  Device.hasMany(ModuleBuildRequest, { foreignKey: 'deviceId' });
  ModuleBuildRequest.belongsTo(Device, { foreignKey: 'deviceId' });
  Device.hasMany(GhidraAnalysisJob, { foreignKey: 'deviceId' });
  GhidraAnalysisJob.belongsTo(Device, { foreignKey: 'deviceId' });
  const BlockedRemote = sequelize.define('BlockedRemote', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    cidr: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
    },
  }, {
    tableName: 'blocked_remotes',
    underscored: true,
    updatedAt: false,
    createdAt: 'created_at',
  });

  // Global operator-tunable settings (deployment-wide, not per device/user).
  const AppSetting = sequelize.define('AppSetting', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    key: {
      type: DataTypes.STRING(128),
      allowNull: false,
      unique: true,
    },
    value: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
  }, {
    tableName: 'app_settings',
    underscored: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
  });

  const User = sequelize.define('User', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    username: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
    },
  }, {
    tableName: 'users',
    underscored: true,
    updatedAt: false,
    createdAt: 'created_at',
  });

  const ApiKey = sequelize.define('ApiKey', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'user_id',
    },
    keyHash: {
      type: DataTypes.STRING(64),
      allowNull: false,
      unique: true,
      field: 'key_hash',
    },
    label: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    scope: {
      type: DataTypes.STRING(32),
      allowNull: false,
      defaultValue: 'agent',
    },
  }, {
    tableName: 'api_keys',
    underscored: true,
    updatedAt: false,
    createdAt: 'created_at',
  });

  const UserDevice = sequelize.define('UserDevice', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'user_id',
    },
    deviceId: {
      type: DataTypes.BIGINT,
      allowNull: false,
      field: 'device_id',
    },
  }, {
    tableName: 'user_devices',
    underscored: true,
  });

  const CommandLog = sequelize.define('CommandLog', {
    id: {
      type: DataTypes.BIGINT,
      autoIncrement: true,
      primaryKey: true,
    },
    userId: { type: DataTypes.BIGINT, allowNull: true, field: 'user_id' },
    deviceId: { type: DataTypes.BIGINT, allowNull: true, field: 'device_id' },
    macAddress: { type: DataTypes.STRING, allowNull: true, field: 'mac_address' },
    commandType: { type: DataTypes.STRING, allowNull: false, field: 'command_type' },
    command: { type: DataTypes.TEXT, allowNull: false },
    status: { type: DataTypes.INTEGER, allowNull: true },
  }, {
    tableName: 'command_logs',
    underscored: true,
    updatedAt: false,
  });

  Device.hasOne(DeviceAlias, { foreignKey: 'deviceId' });
  DeviceAlias.belongsTo(Device, { foreignKey: 'deviceId' });
  User.hasMany(UserDevice, { foreignKey: 'userId' });
  UserDevice.belongsTo(User, { foreignKey: 'userId' });
  Device.hasMany(UserDevice, { foreignKey: 'deviceId' });
  UserDevice.belongsTo(Device, { foreignKey: 'deviceId' });
  Device.hasMany(TerminalConnection, { foreignKey: 'deviceId' });
  TerminalConnection.belongsTo(Device, { foreignKey: 'deviceId' });
  User.hasMany(ApiKey, { foreignKey: 'userId' });
  ApiKey.belongsTo(User, { foreignKey: 'userId' });
  User.hasMany(Upload, { foreignKey: 'userId' });
  Upload.belongsTo(User, { foreignKey: 'userId' });
  User.hasMany(CommandLog, { foreignKey: 'userId' });
  CommandLog.belongsTo(User, { foreignKey: 'userId' });
  Device.hasMany(CommandLog, { foreignKey: 'deviceId' });
  CommandLog.belongsTo(Device, { foreignKey: 'deviceId' });

  return {
    Device,
    CommandLog,
    Upload,
    CommandUpload,
    FileListEntry,
    SymlinkListEntry,
    EfiVariable,
    UbootEnvCandidate,
    UbootEnvVariable,
    LogEvent,
    DeviceAlias,
    TerminalConnection,
    ArchReport,
    KernelBuildInfo,
    ModuleBuildRequest,
    GhidraAnalysisJob,
    GrepMatch,
    BlockedRemote,
    AppSetting,
    User,
    ApiKey,
    UserDevice,
  };
}

module.exports = {
  defineModels,
};
