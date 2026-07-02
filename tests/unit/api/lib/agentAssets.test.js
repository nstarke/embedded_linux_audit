'use strict';

const path = require('path');

function loadAgentAssets(agentServiceConfig) {
  jest.resetModules();
  jest.doMock('../../../../api/lib/config', () => ({
    getAgentServiceConfig: jest.fn(() => agentServiceConfig),
  }));
  return require('../../../../api/lib/agentAssets');
}

describe('agentAssets', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('resolveAssetsDir prefers an explicit --assets-dir (absolute)', () => {
    const a = loadAgentAssets({ assetsDir: null, dataDir: 'x' });
    expect(a.resolveAssetsDir({ assetsDirArg: '/abs/assets' })).toBe('/abs/assets');
  });

  test('resolveAssetsDir resolves a relative --assets-dir against repoRoot', () => {
    const a = loadAgentAssets({ assetsDir: null, dataDir: 'x' });
    expect(a.resolveAssetsDir({ assetsDirArg: 'rel/assets', repoRoot: '/repo' })).toBe('/repo/rel/assets');
  });

  test('resolveAssetsDir falls back to ELA_AGENT_ASSETS_DIR (svc.assetsDir)', () => {
    const a = loadAgentAssets({ assetsDir: '/data/agent/release_binaries', dataDir: '/data/agent' });
    expect(a.resolveAssetsDir()).toBe('/data/agent/release_binaries');
  });

  test('resolveAssetsDir falls back to <dataDir>/release_binaries', () => {
    const a = loadAgentAssets({ assetsDir: null, dataDir: '/data/agent' });
    expect(a.resolveAssetsDir()).toBe(path.join('/data/agent', 'release_binaries'));
  });

  test('genericDir and userDir compose the expected layout', () => {
    const a = loadAgentAssets({ assetsDir: null, dataDir: '/d' });
    expect(a.genericDir('/assets')).toBe(path.join('/assets', 'generic'));
    expect(a.userDir('/assets', 'abc123')).toBe(path.join('/assets', 'users', 'abc123'));
  });
});
