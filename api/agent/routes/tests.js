const { isSafeSinglePathSegment } = require('./shared');

module.exports = function registerTestsRoute(app, deps) {
  const { testsDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;
  const configuredAgentTestsDir = deps.path.join(testsDir, 'agent', 'shell');
  const repoAgentTestsDir = deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'agent', 'shell');

  function getAgentTestDirs() {
    const dirs = [configuredAgentTestsDir];
    if (repoAgentTestsDir !== configuredAgentTestsDir) {
      dirs.push(repoAgentTestsDir);
    }
    return dirs;
  }

  app.get('/tests/agent/:name', async (req, res) => {
    verboseRequestLog(req);
    const requestedPath = req.params.name;
    if (!isSafeSinglePathSegment(requestedPath) || !requestedPath.endsWith('.sh')) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    for (const agentTestsDir of getAgentTestDirs()) {
      const candidate = deps.path.resolve(agentTestsDir, requestedPath);
      if (!isWithinRoot(candidate, agentTestsDir)) {
        continue;
      }
      try {
        const stat = await fsp.stat(candidate);
        if (!stat.isFile()) {
          continue;
        }
        res.sendFile(candidate);
        return;
      } catch {
        // Try the next known agent test directory.
      }
    }

    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  });

  app.get('/tests/*', (req, res) => {
    verboseRequestLog(req);
    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  });
};