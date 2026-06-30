'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const auth = require('../auth');
const registerUploadsRoutes = require('./routes/uploads');

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
