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
  //
  // The OpenAPI `servers[0].url` is derived per-request from X-Forwarded-Prefix
  // (set by nginx for the /client/ location) so Swagger UI "Try it out" targets
  // the right base path: `/uploads` when reached directly, `/client/uploads`
  // through the reverse proxy.
  app.get('/openapi.json', (req, res) => {
    const prefix = String(req.headers['x-forwarded-prefix'] || '').replace(/\/+$/, '');
    res.json({ ...openapiSpec, servers: [{ url: prefix || '/' }] });
  });
  // Load the spec by URL (relative to /docs/) rather than embedding it, so the
  // dynamic servers above are honored. `../openapi.json` resolves to
  // `/openapi.json` directly and `/client/openapi.json` behind nginx.
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(null, {
    customSiteTitle: 'ELA Client API',
    swaggerOptions: { url: '../openapi.json' },
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
