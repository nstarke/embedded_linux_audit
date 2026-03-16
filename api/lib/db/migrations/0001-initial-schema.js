'use strict';

const { DataTypes } = require('sequelize');

async function createCommonColumns(queryInterface, tableName) {
  await queryInterface.addIndex(tableName, ['upload_id']);
}

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('devices', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      mac_address: { type: DataTypes.STRING(17), allowNull: false, unique: true },
      first_seen_at: { type: DataTypes.DATE, allowNull: false },
      last_seen_at: { type: DataTypes.DATE, allowNull: false },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });

    await queryInterface.createTable('uploads', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      },
      upload_type: { type: DataTypes.STRING(64), allowNull: false },
      content_type: { type: DataTypes.STRING(128), allowNull: false },
      src_ip: { type: DataTypes.STRING(64), allowNull: true },
      api_timestamp: { type: DataTypes.DATE, allowNull: false },
      request_file_path: { type: DataTypes.TEXT, allowNull: true },
      is_symlink: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      symlink_path: { type: DataTypes.TEXT, allowNull: true },
      payload_text: { type: DataTypes.TEXT, allowNull: true },
      payload_json: { type: DataTypes.JSONB, allowNull: true },
      payload_binary: { type: DataTypes.BLOB('long'), allowNull: true },
      payload_sha256: { type: DataTypes.STRING(64), allowNull: false },
      payload_bytes: { type: DataTypes.INTEGER, allowNull: false },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('uploads', ['device_id', 'upload_type']);
    await queryInterface.addIndex('uploads', ['api_timestamp']);

    await queryInterface.createTable('command_uploads', {
      upload_id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      command_text: { type: DataTypes.TEXT, allowNull: false },
      command_output: { type: DataTypes.TEXT, allowNull: true },
      command_format: { type: DataTypes.STRING(32), allowNull: false },
    });

    await queryInterface.createTable('file_list_entries', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      root_path: { type: DataTypes.TEXT, allowNull: true },
      entry_path: { type: DataTypes.TEXT, allowNull: false },
    });
    await createCommonColumns(queryInterface, 'file_list_entries');

    await queryInterface.createTable('symlink_list_entries', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      root_path: { type: DataTypes.TEXT, allowNull: true },
      link_path: { type: DataTypes.TEXT, allowNull: false },
      target_path: { type: DataTypes.TEXT, allowNull: true },
    });
    await createCommonColumns(queryInterface, 'symlink_list_entries');

    await queryInterface.createTable('efi_variables', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      guid: { type: DataTypes.STRING(128), allowNull: false },
      name: { type: DataTypes.TEXT, allowNull: false },
      attributes: { type: DataTypes.BIGINT, allowNull: true },
      size_bytes: { type: DataTypes.BIGINT, allowNull: true },
      data_hex: { type: DataTypes.TEXT, allowNull: true },
    });
    await createCommonColumns(queryInterface, 'efi_variables');

    await queryInterface.createTable('uboot_env_candidates', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      record_type: { type: DataTypes.STRING(64), allowNull: false },
      device: { type: DataTypes.TEXT, allowNull: true },
      offset: { type: DataTypes.BIGINT, allowNull: true },
      crc_endian: { type: DataTypes.STRING(32), allowNull: true },
      mode: { type: DataTypes.STRING(64), allowNull: true },
      has_known_vars: { type: DataTypes.BOOLEAN, allowNull: true },
      cfg_offset: { type: DataTypes.BIGINT, allowNull: true },
      env_size: { type: DataTypes.BIGINT, allowNull: true },
      erase_size: { type: DataTypes.BIGINT, allowNull: true },
      sector_count: { type: DataTypes.BIGINT, allowNull: true },
      pair_offset: { type: DataTypes.BIGINT, allowNull: true },
    });
    await createCommonColumns(queryInterface, 'uboot_env_candidates');

    await queryInterface.createTable('uboot_env_variables', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      device: { type: DataTypes.TEXT, allowNull: true },
      offset: { type: DataTypes.BIGINT, allowNull: true },
      key: { type: DataTypes.TEXT, allowNull: false },
      value: { type: DataTypes.TEXT, allowNull: true },
    });
    await createCommonColumns(queryInterface, 'uboot_env_variables');

    await queryInterface.createTable('log_events', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      event_type: { type: DataTypes.STRING(64), allowNull: false },
      message: { type: DataTypes.TEXT, allowNull: true },
      phase: { type: DataTypes.STRING(64), allowNull: true },
      command: { type: DataTypes.TEXT, allowNull: true },
      rc: { type: DataTypes.INTEGER, allowNull: true },
      mode: { type: DataTypes.STRING(64), allowNull: true },
      rom_path: { type: DataTypes.TEXT, allowNull: true },
      size_bytes: { type: DataTypes.BIGINT, allowNull: true },
      metadata: { type: DataTypes.JSONB, allowNull: true },
    });
    await createCommonColumns(queryInterface, 'log_events');
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('log_events');
    await queryInterface.dropTable('uboot_env_variables');
    await queryInterface.dropTable('uboot_env_candidates');
    await queryInterface.dropTable('efi_variables');
    await queryInterface.dropTable('symlink_list_entries');
    await queryInterface.dropTable('file_list_entries');
    await queryInterface.dropTable('command_uploads');
    await queryInterface.dropTable('uploads');
    await queryInterface.dropTable('devices');
  },
};
