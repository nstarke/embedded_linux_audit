// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.addColumn('uploads', 'user_id', {
      type: DataTypes.BIGINT,
      allowNull: true,
      references: { model: 'users', key: 'id' },
      onDelete: 'SET NULL',
    });
    await queryInterface.addIndex('uploads', ['user_id', 'upload_type']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeIndex('uploads', ['user_id', 'upload_type']);
    await queryInterface.removeColumn('uploads', 'user_id');
  },
};
