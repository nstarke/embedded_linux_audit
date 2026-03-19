'use strict';

const path = require('path');

function fileEntry(name) {
  return {
    name,
    isFile: () => true,
    isDirectory: () => false,
  };
}

function dirEntry(name) {
  return {
    name,
    isFile: () => false,
    isDirectory: () => true,
  };
}

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    type(value) {
      this.headers['content-type'] = value;
      return this;
    },
    send(value) {
      this.body = value;
      return this;
    },
  };
}

function loadRegisterRootRoute(listBinaryEntriesImpl) {
  jest.resetModules();
  const listBinaryEntries = jest.fn(listBinaryEntriesImpl);

  jest.doMock('../../../../api/agent/routes/shared', () => ({
    listBinaryEntries,
  }));

  const registerRootRoute = require('../../../../api/agent/routes/root');
  return { registerRootRoute, listBinaryEntries };
}

describe('agent root route', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('lists configured and repo tests recursively, suppresses duplicates, and escapes html', async () => {
    const { registerRootRoute, listBinaryEntries } = loadRegisterRootRoute(async () => ([
      {
        fileName: 'ela-x86_64<script>.bin',
        url: '/isa/x86_64?x=<y>&z="1"',
      },
    ]));
    const app = { get: jest.fn() };
    const testsDir = '/configured/tests';
    const scriptsDir = path.join(testsDir, 'scripts');
    const configuredShellDir = path.join(testsDir, 'agent', 'shell');
    const configuredScriptsDir = path.join(testsDir, 'agent', 'scripts');
    const repoShellDir = path.resolve(__dirname, '../../../../tests/agent/shell');
    const repoScriptsDir = path.resolve(__dirname, '../../../../tests/agent/scripts');

    const tree = new Map([
      [configuredShellDir, [fileEntry('dup.sh'), fileEntry('configured.sh'), dirEntry('nested')]],
      [path.join(configuredShellDir, 'nested'), [fileEntry('deep.sh')]],
      [repoShellDir, [fileEntry('dup.sh'), fileEntry('repo-only.sh')]],
      [configuredScriptsDir, [fileEntry('dup.ela')]],
      [repoScriptsDir, [fileEntry('dup.ela'), dirEntry('subdir'), fileEntry('repo-only.ela')]],
      [path.join(repoScriptsDir, 'subdir'), [fileEntry('deep.ela')]],
      [scriptsDir, [fileEntry('run.sh'), fileEntry('z-last.ela'), fileEntry('a-first<bad>.ela')]],
    ]);

    registerRootRoute(app, {
      assetsDir: '/assets',
      testsDir,
      scriptsDir,
      releaseStateFile: '.release_state.json',
      path,
      fsp: {
        readdir: jest.fn(async (dir) => tree.get(dir) || []),
      },
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
    });

    const handler = app.get.mock.calls[0][1];
    const req = { url: '/' };
    const res = createRes();

    await handler(req, res);

    expect(listBinaryEntries).toHaveBeenCalledWith('/assets', expect.any(Object), '.release_state.json');
    expect(res.headers['content-type']).toBe('text/html');
    expect(res.body).toContain('ela-x86_64&lt;script&gt;.bin');
    expect(res.body).toContain('/isa/x86_64?x=&lt;y&gt;&amp;z=&quot;1&quot;');
    expect(res.body).toContain('tests/agent/shell/configured.sh');
    expect(res.body).toContain('tests/agent/shell/nested/deep.sh');
    expect(res.body).toContain('tests/agent/shell/repo-only.sh');
    expect(res.body.match(/>tests\/agent\/shell\/dup\.sh</g)).toHaveLength(1);
    expect(res.body).toContain('tests/agent/scripts/repo-only.ela');
    expect(res.body).toContain('tests/agent/scripts/subdir/deep.ela');
    expect(res.body.match(/>tests\/agent\/scripts\/dup\.ela</g)).toHaveLength(1);
    expect(res.body).toContain('scripts/a-first&lt;bad&gt;.ela');
    expect(res.body).toContain('scripts/run.sh');
    expect(res.body).toContain('Serving agent scripts from:');
  });

  test('renders empty-state messages when no assets or scripts are present', async () => {
    const { registerRootRoute } = loadRegisterRootRoute(async () => []);
    const app = { get: jest.fn() };
    const verboseRequestLog = jest.fn();
    const verboseResponseLog = jest.fn();

    registerRootRoute(app, {
      assetsDir: '/assets',
      testsDir: '/configured/tests',
      scriptsDir: '/configured/tests/scripts',
      releaseStateFile: '.release_state.json',
      path,
      fsp: {
        readdir: jest.fn(async () => []),
      },
      verboseRequestLog,
      verboseResponseLog,
    });

    const handler = app.get.mock.calls[0][1];
    const req = { url: '/' };
    const res = createRes();

    await handler(req, res);

    expect(verboseRequestLog).toHaveBeenCalledWith(req);
    expect(verboseResponseLog).toHaveBeenCalledWith(req, 200, Buffer.byteLength(res.body));
    expect(res.body).toContain('No binaries downloaded.');
    expect(res.body).toContain('No agent test shell or script files found.');
    expect(res.body).toContain('No command scripts found.');
  });
});
