'use strict';

const { DataTypes } = require('sequelize');

module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.addColumn('uploads', 'local_artifact_path', {
      type: DataTypes.TEXT,
      allowNull: true,
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeColumn('uploads', 'local_artifact_path');
  },
};
