// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    // Allow alias to be null so a row can exist with only a group set
    await queryInterface.changeColumn('device_aliases', 'alias', {
      type: DataTypes.STRING(255),
      allowNull: true,
    });
    await queryInterface.addColumn('device_aliases', 'group', {
      type: DataTypes.STRING(255),
      allowNull: true,
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeColumn('device_aliases', 'group');
    await queryInterface.changeColumn('device_aliases', 'alias', {
      type: DataTypes.STRING(255),
      allowNull: false,
    });
  },
};
