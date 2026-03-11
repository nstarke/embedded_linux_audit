const { listBinaryEntries } = require('./shared');

module.exports = function registerRootRoute(app, deps) {
  const { testsDir, scriptsDir, fsp, verboseRequestLog, verboseResponseLog } = deps;
  const configuredAgentTestDirs = {
    shell: deps.path.join(testsDir, 'agent', 'shell'),
    scripts: deps.path.join(testsDir, 'agent', 'scripts')
  };
  const repoAgentTestDirs = {
    shell: deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'agent', 'shell'),
    scripts: deps.path.resolve(__dirname, '..', '..', '..', 'tests', 'agent', 'scripts')
  };
  const agentTestTypeMeta = {
    shell: {
      suffix: '.sh',
      labelPrefix: 'tests/agent/shell/'
    },
    scripts: {
      suffix: '.ela',
      labelPrefix: 'tests/agent/scripts/'
    }
  };

  function getAgentTestDirs(type) {
    const configuredAgentTestsDir = configuredAgentTestDirs[type];
    const repoAgentTestsDir = repoAgentTestDirs[type];
    const dirs = [configuredAgentTestsDir];
    if (repoAgentTestsDir !== configuredAgentTestsDir) {
      dirs.push(repoAgentTestsDir);
    }
    return dirs;
  }

  async function listAgentTestEntries() {
    const entries = [];

    for (const [type, meta] of Object.entries(agentTestTypeMeta)) {
      const byName = new Map();
      for (const dir of getAgentTestDirs(type)) {
        const dirEntries = await fsp.readdir(dir, { withFileTypes: true }).catch(() => []);
        for (const entry of dirEntries) {
          if (!entry.isFile() || !entry.name.endsWith(meta.suffix) || byName.has(entry.name)) {
            continue;
          }
          byName.set(entry.name, {
            name: entry.name,
            pathLabel: `${meta.labelPrefix}${entry.name}`,
            url: `/tests/agent/${encodeURIComponent(type)}/${encodeURIComponent(entry.name)}`
          });
        }
      }
      entries.push(...byName.values());
    }

    return entries.sort((a, b) => a.pathLabel.localeCompare(b.pathLabel));
  }

  async function listScriptEntries(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true }).catch(() => []);
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) => ({
        name: entry.name,
        url: `/scripts/${encodeURIComponent(entry.name)}`
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  app.get('/', async (req, res) => {
    verboseRequestLog(req);
    const binaryEntries = await listBinaryEntries(deps.assetsDir, fsp, deps.releaseStateFile);
    const agentTestDirs = Object.keys(agentTestTypeMeta).flatMap((type) => getAgentTestDirs(type));
    const testEntries = await listAgentTestEntries();
    const scriptEntries = await listScriptEntries(scriptsDir);

    const assetItems = binaryEntries.length
      ? binaryEntries.map(({ fileName, url }) => `      <li><a href="${escapeHtml(url)}">${escapeHtml(fileName)}</a></li>`).join('\n')
      : '      <li><em>No binaries downloaded.</em></li>';

    const testItems = testEntries.length
      ? testEntries.map(({ pathLabel, url }) => `      <li><a href="${escapeHtml(url)}">${escapeHtml(pathLabel)}</a></li>`).join('\n')
      : '      <li><em>No agent test shell or script files found.</em></li>';

    const scriptItems = scriptEntries.length
      ? scriptEntries.map(({ name, url }) => `      <li><a href="${escapeHtml(url)}">scripts/${escapeHtml(name)}</a></li>`).join('\n')
      : '      <li><em>No command scripts found.</em></li>';

    const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Release Binaries and Test Scripts</title>
  </head>
  <body>
    <h1>Release Binaries</h1>
    <p>Serving files from: ${escapeHtml(deps.assetsDir)}</p>
    <ul>
${assetItems}
    </ul>

    <h1>Test Scripts</h1>
    <p>Serving agent scripts from: ${escapeHtml(agentTestDirs.join(', '))}</p>
    <ul>
${testItems}
    </ul>

    <h1>Command Scripts</h1>
    <p>Serving command scripts from: ${escapeHtml(scriptsDir)}</p>
    <ul>
${scriptItems}
    </ul>
  </body>
</html>
`;

    res.type('text/html').send(html);
    verboseResponseLog(req, 200, Buffer.byteLength(html));
  });
};