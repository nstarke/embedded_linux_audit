// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

module.exports = {
  async up({ context: queryInterface }) {
    // Replace global alias uniqueness with per-group uniqueness
    await queryInterface.removeIndex('device_aliases', ['alias']);
    await queryInterface.addIndex('device_aliases', ['alias', 'group'], { unique: true });
  },

  async down({ context: queryInterface }) {
    await queryInterface.removeIndex('device_aliases', ['alias', 'group']);
    await queryInterface.addIndex('device_aliases', ['alias'], { unique: true });
  },
};
