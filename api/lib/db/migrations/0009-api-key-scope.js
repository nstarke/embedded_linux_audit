// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.addColumn('api_keys', 'scope', {
      type: DataTypes.STRING(32),
      allowNull: false,
      defaultValue: 'agent',
    });
    await queryInterface.addIndex('api_keys', ['scope']);
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeIndex('api_keys', ['scope']);
    await queryInterface.removeColumn('api_keys', 'scope');
  },
};
