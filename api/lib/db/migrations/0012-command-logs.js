// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// Audit log of operator commands issued through the client API against
// connected devices — both Linux shell commands (`linux execute-command`) and
// raw ELA agent commands. Records who ran what, against which device, when, and
// the resulting HTTP status.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('command_logs', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      user_id: {
        type: DataTypes.BIGINT,
        allowNull: true,
        references: { model: 'users', key: 'id' },
        onDelete: 'SET NULL',
      },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: true,
        references: { model: 'devices', key: 'id' },
        onDelete: 'SET NULL',
      },
      mac_address: { type: DataTypes.STRING, allowNull: true },
      command_type: { type: DataTypes.STRING, allowNull: false },
      command: { type: DataTypes.TEXT, allowNull: false },
      status: { type: DataTypes.INTEGER, allowNull: true },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('command_logs', ['user_id']);
    await queryInterface.addIndex('command_logs', ['device_id']);
    await queryInterface.addIndex('command_logs', ['created_at']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('command_logs');
  },
};
