'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('device_aliases', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        unique: true,
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      },
      alias: { type: DataTypes.STRING(255), allowNull: false },
      source: { type: DataTypes.STRING(64), allowNull: false, defaultValue: 'terminal_api' },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('device_aliases', ['alias'], { unique: true });

    await queryInterface.createTable('terminal_connections', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      },
      remote_address: { type: DataTypes.STRING(255), allowNull: true },
      connected_at: { type: DataTypes.DATE, allowNull: false },
      disconnected_at: { type: DataTypes.DATE, allowNull: true },
      last_heartbeat_at: { type: DataTypes.DATE, allowNull: true },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('terminal_connections', ['device_id']);
    await queryInterface.addIndex('terminal_connections', ['connected_at']);

    await queryInterface.createTable('arch_reports', {
      upload_id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      subcommand: { type: DataTypes.STRING(64), allowNull: true },
      value: { type: DataTypes.STRING(255), allowNull: true },
    });

    await queryInterface.createTable('grep_matches', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      upload_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      record_index: { type: DataTypes.INTEGER, allowNull: false },
      root_path: { type: DataTypes.TEXT, allowNull: true },
      file_path: { type: DataTypes.TEXT, allowNull: false },
      line_number: { type: DataTypes.INTEGER, allowNull: true },
      line_text: { type: DataTypes.TEXT, allowNull: true },
    });
    await queryInterface.addIndex('grep_matches', ['upload_id']);
    await queryInterface.addIndex('grep_matches', ['file_path']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('grep_matches');
    await queryInterface.dropTable('arch_reports');
    await queryInterface.dropTable('terminal_connections');
    await queryInterface.dropTable('device_aliases');
  },
};
