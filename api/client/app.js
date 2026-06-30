'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const auth = require('../auth');
const registerUploadsRoutes = require('./routes/uploads');
const { openapiSpec } = require('./openapi');

/**
 * Build the client API express app.  Every route is scoped to the
 * authenticated user, so a request without a resolved user (no client token,
 * or a token that does not map to a specific user) is rejected with 401 before
 * any route runs.
 */
function createApp(deps = {}) {
  const app = express();
  app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  }));

  // API documentation is public so the docs page can load and the user can then
  // enter their client token to try requests. Mounted BEFORE auth.middleware.
  app.get('/openapi.json', (req, res) => res.json(openapiSpec));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec, {
    customSiteTitle: 'ELA Client API',
  }));

  app.use(auth.middleware);
  app.use((req, res, next) => {
    if (!req.authUser) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  });

  registerUploadsRoutes(app, deps);

  return app;
}

module.exports = {
  createApp,
};
