'use strict';

const path = require('path');
const { Sequelize } = require('sequelize');
const { Umzug, SequelizeStorage } = require('umzug');
const { getDatabaseConfig } = require('../config');
const { defineModels } = require('./models');

let sequelizeInstance;
let modelsInstance;

function createSequelize(config = getDatabaseConfig()) {
  const common = {
    dialect: 'postgres',
    logging: config.logging ? console.log : false,
    dialectOptions: config.ssl ? {
      ssl: {
        require: true,
        rejectUnauthorized: config.sslRejectUnauthorized !== false,
      },
    } : {},
  };

  if (config.url) {
    return new Sequelize(config.url, common);
  }

  return new Sequelize(config.database, config.username, config.password, {
    ...common,
    host: config.host,
    port: config.port,
  });
}

function getSequelize() {
  if (!sequelizeInstance) {
    sequelizeInstance = createSequelize();
  }
  return sequelizeInstance;
}

function getModels() {
  if (!modelsInstance) {
    modelsInstance = defineModels(getSequelize());
  }
  return modelsInstance;
}

function createMigrator() {
  return new Umzug({
    migrations: {
      glob: path.join(__dirname, 'migrations', '*.js'),
    },
    context: getSequelize().getQueryInterface(),
    storage: new SequelizeStorage({ sequelize: getSequelize() }),
    logger: console,
  });
}

async function initializeDatabase() {
  const sequelize = getSequelize();
  await sequelize.authenticate();
  getModels();
  return { sequelize, models: getModels() };
}

async function runMigrations() {
  const migrator = createMigrator();
  return migrator.up();
}

async function closeDatabase() {
  if (sequelizeInstance) {
    await sequelizeInstance.close();
    sequelizeInstance = null;
    modelsInstance = null;
  }
}

module.exports = {
  createSequelize,
  getSequelize,
  getModels,
  createMigrator,
  initializeDatabase,
  runMigrations,
  closeDatabase,
};
