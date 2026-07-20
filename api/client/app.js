'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const auth = require('../auth');
const registerUploadsRoutes = require('./routes/uploads');
const registerTerminalRoutes = require('./routes/terminal');
const registerGdbRoutes = require('./routes/gdb');
const registerModuleBuildRoutes = require('./routes/moduleBuilds');
const registerGhidraAnalysisRoutes = require('./routes/ghidraAnalysis');
const registerSettingsRoutes = require('./routes/settings');
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
    // tryItOutEnabled makes the request-body editors (e.g. the `command` field
    // on the exec/spawn endpoints) editable by default, instead of showing a
    // read-only example until "Try it out" is clicked.
    swaggerOptions: { url: '../openapi.json', tryItOutEnabled: true },
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
  // Operator terminal-control routes: enqueue commands to the terminal API over
  // the queue and relay the result. ACL'd to the caller's associated devices.
  registerTerminalRoutes(app, deps.terminal || {});
  // Operator GDB routes: list active gdbserver sessions on the caller's devices,
  // answered by the GDB bridge API over its own queue. ACL'd the same way.
  registerGdbRoutes(app, deps.gdb || {});
  // Kernel-module build routes: create a build request from a device's latest
  // module-buildinfo upload (enqueued to the builder) and poll its status.
  registerModuleBuildRoutes(app, deps.moduleBuilds || {});
  // Ghidra-analysis routes: pull a device's rootfs via remote-copy and
  // decompile every ELF with Ghidra in the background ghidra-analysis worker;
  // create/list/poll the resulting jobs. ACL'd to the caller's devices.
  registerGhidraAnalysisRoutes(app, deps.ghidraAnalysis || {});
  // Deployment-wide settings (no device scope): currently the fuzz case-ring
  // size the agent API holds per streaming connection for panic capture.
  registerSettingsRoutes(app, deps.settings || {});

  // Translate JSON body-parser failures on the terminal POST routes into the
  // same error shapes the routes use.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
      res.status(413).json({ error: 'payload too large' });
      return;
    }
    if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
      res.status(400).json({ error: 'invalid JSON body' });
      return;
    }
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}

module.exports = {
  createApp,
};
