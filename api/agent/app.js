'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fsp = require('fs/promises');
const mime = require('mime-types');
const crypto = require('crypto');
const auth = require('../auth');
const registerRootRoute = require('./routes/root');
const registerScriptsRoute = require('./routes/scripts');
const registerTestsRoute = require('./routes/tests');
const registerUbootEnvRoute = require('./routes/ubootEnv');
const registerIsaRoute = require('./routes/isa');
const registerAssetRoute = require('./routes/assets');
const registerUploadRoute = require('./routes/upload');
const {
  normalizeContentType,
  sanitizeUploadPath,
  writeUploadFile,
  augmentJsonPayload,
  logPathForContentType,
  isValidMacAddress,
  isWithinRoot,
  getClientIp,
} = require('./serverUtils');

function createApp({
  logPrefix,
  assetsDir,
  dataDir,
  testsDir,
  verbose,
  releaseStateFile,
  validUploadTypes,
  validContentTypes,
  persistUpload,
}) {
  const app = express();
  app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  }));
  app.use(express.raw({ type: '*/*', limit: '100mb' }));
  app.use(auth.middleware);
  const envDir = path.join(dataDir, 'env');
  const scriptsDir = path.join(testsDir, 'scripts');

  if (verbose) {
    app.use((req, res, next) => {
      console.log(`[${new Date().toISOString()}] ${getClientIp(req)} ${req.method} ${req.originalUrl}`);

      res.on('finish', () => {
        const contentLength = res.getHeader('content-length');
        const size = Number.isFinite(Number(contentLength)) ? Number(contentLength) : 0;
        console.log(`[${new Date().toISOString()}] ${getClientIp(req)} ${req.method} ${req.originalUrl} -> ${res.statusCode} (${size} bytes)`);
      });

      next();
    });
  }

  const routeDeps = {
    path,
    fsp,
    mime,
    crypto,
    assetsDir,
    testsDir,
    scriptsDir,
    envDir,
    dataDir,
    releaseStateFile,
    validUploadTypes,
    validContentTypes,
    normalizeContentType,
    sanitizeUploadPath,
    writeUploadFile,
    augmentJsonPayload,
    logPathForContentType: (prefix, header) => logPathForContentType(prefix, header, validContentTypes),
    persistUpload,
    isValidMacAddress,
    isWithinRoot,
    getClientIp,
    verboseRequestLog: () => {},
    verboseResponseLog: () => {},
  };

  registerRootRoute(app, routeDeps);
  registerScriptsRoute(app, routeDeps);
  registerTestsRoute(app, routeDeps);
  registerUbootEnvRoute(app, routeDeps);
  registerIsaRoute(app, routeDeps);
  registerUploadRoute(app, routeDeps);
  registerAssetRoute(app, routeDeps);

  return app;
}

module.exports = {
  createApp,
};
