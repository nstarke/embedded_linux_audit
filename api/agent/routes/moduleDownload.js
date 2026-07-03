// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Lazily resolve the DB helper so importing this module in tests does not
// pull in sequelize.
function defaultConsumeToken(token) {
  return require('../../lib/db/moduleBuilds').consumeDownloadToken(token);
}

/**
 * Serve a built kernel module to the agent that will load it.
 *
 * GET /module/:token — registered BEFORE auth.middleware (like /isa/:token):
 * the deliver flow drives the agent's `linux download-file`, which sends no
 * Authorization header, so the single-use short-TTL token in the path IS the
 * credential. The token was minted by the operator's deliver call, only its
 * sha256 is stored, and it is cleared atomically when served — an unknown,
 * expired, or already-used token is one uniform 404.
 */
module.exports = function registerModuleDownloadRoute(app, deps) {
  const { fsp, path, verboseRequestLog, verboseResponseLog } = deps;
  const consumeToken = deps.consumeDownloadToken || defaultConsumeToken;

  app.get('/module/:token', async (req, res) => {
    verboseRequestLog(req);

    let row = null;
    try {
      row = await consumeToken(req.params.token);
    } catch {
      row = null;
    }
    if (!row) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    let size;
    try {
      const stat = await fsp.stat(row.artifactPath);
      if (!stat.isFile()) {
        throw new Error('not a file');
      }
      size = stat.size;
    } catch {
      // The row said succeeded but the artifact is gone (volume wiped?):
      // still a uniform 404 for the caller, but worth a server-side trace.
      console.error(`[module-download] artifact missing for request ${row.id}: ${row.artifactPath}`);
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    res.status(200);
    res.type('application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(row.artifactPath)}"`);
    // Stream the artifact from disk (the convention the other download routes
    // use) rather than buffering it into memory and writing to the response.
    // artifactPath is a trusted absolute path stored server-side, never
    // user-controlled.
    res.sendFile(row.artifactPath, (err) => {
      if (err && !res.headersSent) {
        res.status(404).type('text').send('not found\n');
        verboseResponseLog(req, 404, 10);
        return;
      }
      verboseResponseLog(req, 200, size);
    });
  });
};
