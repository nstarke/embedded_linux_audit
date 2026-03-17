'use strict';

const fs = require('fs');

function loadLegacyAliases(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return {};
  }
}

module.exports = {
  loadLegacyAliases,
};
