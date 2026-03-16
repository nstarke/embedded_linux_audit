const { isSafeRelativePath } = require('./shared');

module.exports = function registerTestsRoute(app, deps) {
  const { testsDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;
  const configuredAgentTestDirs = {
    shell: deps.path.join(testsDir, 'agent', 'shell'),
    scripts: deps.path.join(testsDir, 'agent', 'scripts')
  };
  const repoAgentTestDirs = {
    shell: deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'agent', 'shell'),
    scripts: deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'agent', 'scripts')
  };
  const validAgentTestTypes = new Set(['shell', 'scripts']);

  function getAgentTestDirs(type) {
    const configuredAgentTestsDir = configuredAgentTestDirs[type];
    const repoAgentTestsDir = repoAgentTestDirs[type];
    const dirs = [configuredAgentTestsDir];
    if (repoAgentTestsDir !== configuredAgentTestsDir) {
      dirs.push(repoAgentTestsDir);
    }
    return dirs;
  }

  async function sendAgentTest(req, res, type, requestedPath) {
    verboseRequestLog(req);

    if (typeof type !== 'string' || typeof requestedPath !== 'string') {
      res.status(400).type('text').send('invalid request\n');
      verboseResponseLog(req, 400, 16);
      return;
    }

    const expectedSuffix = type === 'shell' ? '.sh' : '.ela';

    if (!validAgentTestTypes.has(type)) {
      res.status(400).type('text').send('invalid type\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    if (!isSafeRelativePath(requestedPath) || !requestedPath.endsWith(expectedSuffix)) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    for (const agentTestsDir of getAgentTestDirs(type)) {
      const candidate = deps.path.resolve(agentTestsDir, requestedPath);
      if (!isWithinRoot(candidate, agentTestsDir)) {
        continue;
      }
      try {
        const stat = await fsp.stat(candidate);
        if (!stat.isFile()) {
          continue;
        }
        res.sendFile(candidate, (err) => {
          if (err && !res.headersSent) {
            res.status(500).type('text').send('internal error\n');
          }
        });
        return;
      } catch {
        // Try the next known agent test directory.
      }
    }

    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  }

  app.get('/tests/agent/:type/:scriptName', async (req, res) => {
    try {
      await sendAgentTest(req, res, req.params.type, req.params.scriptName);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).type('text').send('internal error\n');
      }
    }
  });

  app.get(/^\/tests\/agent\/([^/]+)\/(.+)$/, async (req, res) => {
    try {
      const type = typeof req.params[0] === 'string' ? req.params[0] : '';
      const scriptPath = typeof req.params[1] === 'string' ? req.params[1] : '';
      await sendAgentTest(req, res, type, scriptPath);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).type('text').send('internal error\n');
      }
    }
  });

  // Serve the shared redaction helper needed by common.sh when running standalone.
  app.get('/tests/common_redaction.sh', async (req, res) => {
    verboseRequestLog(req);
    const helperPath = deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'common_redaction.sh');
    try {
      await fsp.access(helperPath);
      res.sendFile(helperPath, (err) => {
        if (err && !res.headersSent) {
          res.status(500).type('text').send('internal error\n');
        }
      });
    } catch {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
    }
  });

  app.get('/tests/*', (req, res) => {
    verboseRequestLog(req);
    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  });
};