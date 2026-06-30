// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.createTable('user_devices', {
      id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true, allowNull: false },
      user_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onDelete: 'CASCADE',
      },
      device_id: {
        type: DataTypes.BIGINT,
        allowNull: false,
        references: { model: 'devices', key: 'id' },
        onDelete: 'CASCADE',
      },
      created_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      updated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    });
    await queryInterface.addIndex('user_devices', ['user_id']);
    await queryInterface.addConstraint('user_devices', {
      fields: ['user_id', 'device_id'],
      type: 'unique',
      name: 'user_devices_user_id_device_id_unique',
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.dropTable('user_devices');
  },
};
