// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('blocked_remotes', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      cidr: { type: DataTypes.STRING(50), allowNull: false, unique: true },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('blocked_remotes');
  },
};
