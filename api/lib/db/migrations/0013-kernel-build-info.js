// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// Normalized rows for module-buildinfo uploads: the facts the module builder
// needs to reproduce a device's kernel build environment (release, vermagic,
// config availability). One row per upload, like arch_reports.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('kernel_build_infos', {
      upload_id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        allowNull: false,
        references: { model: 'uploads', key: 'id' },
        onDelete: 'CASCADE',
      },
      kernel_release: { type: DataTypes.STRING(255), allowNull: true },
      proc_version: { type: DataTypes.TEXT, allowNull: true },
      vermagic: { type: DataTypes.STRING(255), allowNull: true },
      module_path: { type: DataTypes.TEXT, allowNull: true },
      isa: { type: DataTypes.STRING(64), allowNull: true },
      bits: { type: DataTypes.STRING(8), allowNull: true },
      endianness: { type: DataTypes.STRING(16), allowNull: true },
      config_source: { type: DataTypes.TEXT, allowNull: true },
      config_available: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      config_compressed: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    });
    await queryInterface.addIndex('kernel_build_infos', ['kernel_release']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('kernel_build_infos');
  },
};
