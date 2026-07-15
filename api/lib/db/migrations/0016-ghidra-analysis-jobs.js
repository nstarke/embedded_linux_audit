// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// One row per requested Ghidra decompilation run. The client API creates a row
// (status 'queued'), the ghidra-analysis worker drives it through
// copying -> analyzing -> succeeded|failed while it pulls the device rootfs via
// `linux remote-copy --recursive /` and decompiles every ELF it finds. fs_root
// / output_root are the on-disk directories the worker resolved for this run;
// files_found / files_analyzed are progress counters the GET route surfaces.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('ghidra_analysis_jobs', {
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
      status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'queued' },
      fs_root: { type: DataTypes.TEXT, allowNull: true },
      output_root: { type: DataTypes.TEXT, allowNull: true },
      files_found: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      files_analyzed: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      error_message: { type: DataTypes.TEXT, allowNull: true },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('ghidra_analysis_jobs', ['device_id']);
    await queryInterface.addIndex('ghidra_analysis_jobs', ['user_id']);
    await queryInterface.addIndex('ghidra_analysis_jobs', ['status']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('ghidra_analysis_jobs');
  },
};
