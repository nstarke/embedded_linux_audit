// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// One row per requested kernel-module build: the device kernel facts the
// build was created from, queue/lifecycle status, and (on success) the built
// artifact + vermagic verification result. download_token_hash backs the
// pre-auth agent download route (Phase 5), mirroring the /isa/:token pattern.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('module_build_requests', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      },
      user_id: {
        type: DataTypes.BIGINT,
        allowNull: true,
        references: { model: 'users', key: 'id' },
        onDelete: 'SET NULL',
      },
      buildinfo_upload_id: {
        type: DataTypes.BIGINT,
        allowNull: true,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'SET NULL',
      },
      status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'queued' },
      kernel_release: { type: DataTypes.STRING(255), allowNull: false },
      isa: { type: DataTypes.STRING(64), allowNull: false },
      endianness: { type: DataTypes.STRING(16), allowNull: false },
      device_vermagic: { type: DataTypes.STRING(255), allowNull: true },
      config_artifact_path: { type: DataTypes.TEXT, allowNull: true },
      built_vermagic: { type: DataTypes.STRING(255), allowNull: true },
      vermagic_result: { type: DataTypes.STRING(32), allowNull: true },
      source: { type: DataTypes.STRING(32), allowNull: true },
      artifact_path: { type: DataTypes.TEXT, allowNull: true },
      download_token_hash: { type: DataTypes.STRING(64), allowNull: true },
      error_message: { type: DataTypes.TEXT, allowNull: true },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('module_build_requests', ['device_id']);
    await queryInterface.addIndex('module_build_requests', ['user_id']);
    await queryInterface.addIndex('module_build_requests', ['status']);
    await queryInterface.addIndex('module_build_requests', ['download_token_hash']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('module_build_requests');
  },
};
