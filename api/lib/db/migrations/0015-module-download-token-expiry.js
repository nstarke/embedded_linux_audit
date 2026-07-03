// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { DataTypes } = require('sequelize');

// Expiry for module download tokens: a token is valid until this timestamp
// and is single-use (the hash is cleared when the artifact is served), so a
// leaked URL has a short and bounded life.
module.exports = {
  async up({ context: queryInterface }) {
    await queryInterface.addColumn('module_build_requests', 'download_token_expires_at', {
      type: DataTypes.DATE,
      allowNull: true,
    });
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeColumn('module_build_requests', 'download_token_expires_at');
  },
};
