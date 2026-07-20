// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// A small global key/value store for operator-tunable settings that belong to
// the deployment rather than to any one device or user. First tenant:
// `fuzz_ring_size`, the number of streamed fuzz cases the agent API holds per
// connection for host-panic crash capture.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('app_settings', {
      id: {
        type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false,
      },
      key: { type: DataTypes.STRING(128), allowNull: false, unique: true },
      value: { type: DataTypes.TEXT, allowNull: false },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('app_settings');
  },
};
