const { listBinaryEntries, isSafeSinglePathSegment } = require('./shared');

module.exports = function registerIsaRoute(app, deps) {
  const { assetsDir, fsp, isWithinRoot, mime, crypto, path, verboseRequestLog, verboseResponseLog } = deps;

  // Unauthenticated by design: a freshly provisioned host has no agent and no
  // way to send an Authorization header, so the per-user token is supplied in
  // the URL path instead. The token is hashed to locate that user's launcher set
  // (the dir name is sha256(token), never the raw token, so there is no path
  // traversal). Each file is a self-extracting shell launcher that sets the
  // token/URL and runs the embedded generic binary. Registered BEFORE
  // auth.middleware in app.js.
  app.get('/isa/:token/:isa', async (req, res) => {
    verboseRequestLog(req);
    if (!isSafeSinglePathSegment(req.params.isa)) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    const keyHash = crypto.createHash('sha256').update(req.params.token, 'utf8').digest('hex');
    const baseDir = path.join(assetsDir, 'users', keyHash);
    const binaryEntries = await listBinaryEntries(baseDir, fsp, deps.releaseStateFile);
    const match = binaryEntries.find((entry) => entry.isa === req.params.isa);
    if (!match) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    const candidate = path.resolve(baseDir, match.fileName);
    if (!isWithinRoot(candidate, baseDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    res.type(mime.lookup(candidate) || 'application/octet-stream');
    // Suggest a sensible filename so the download saves as the launcher name.
    res.setHeader('Content-Disposition', `attachment; filename="ela-${req.params.isa}"`);
    // Send via a path relative to the validated baseDir with the `root` option
    // (the convention the other static routes use): Express re-resolves against
    // root and rejects any traversal, so the sink never receives a raw
    // user-controlled absolute path.
    res.sendFile(path.relative(baseDir, candidate), { root: baseDir });
  });
};
