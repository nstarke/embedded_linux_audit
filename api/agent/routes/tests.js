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
    const expectedSuffix = type === 'shell' ? '.sh' : '.ela';

    if (!validAgentTestTypes.has(type)) {
      res.status(400).type('text').send('invalid type\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    const pathIsValid = isSafeRelativePath(requestedPath);

    if (!pathIsValid || !requestedPath.endsWith(expectedSuffix)) {
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
        res.sendFile(candidate);
        return;
      } catch {
        // Try the next known agent test directory.
      }
    }

    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  }

  app.get('/tests/agent/:type/:scriptName', async (req, res) => {
    await sendAgentTest(req, res, req.params.type, req.params.scriptName);
  });

  app.get(/^\/tests\/agent\/([^/]+)\/(.+)$/, async (req, res) => {
    const [type, scriptPath] = req.params;
    await sendAgentTest(req, res, type, scriptPath);
  });

  app.get('/tests/*', (req, res) => {
    verboseRequestLog(req);
    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  });
};