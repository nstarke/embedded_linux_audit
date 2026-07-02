'use strict';

const { runBuild } = require('../../../../api/builder/runBuild');

function fakeChild() {
  const handlers = {};
  return {
    on(event, cb) { handlers[event] = cb; return this; },
    emit(event, ...args) { if (handlers[event]) handlers[event](...args); },
  };
}

describe('runBuild', () => {
  test('spawns the compile script with the embedded-key env and resolves on exit 0', async () => {
    const child = fakeChild();
    const spawn = jest.fn(() => child);
    const payload = { embeddedKey: 'tok123', outDir: '/data/agent/release_binaries/users/abc', username: 'alice' };

    const promise = runBuild(payload, { spawn, repoRoot: '/src' });

    expect(spawn).toHaveBeenCalledWith('sh', ['/src/tests/compile_release_binaries_locally.sh'], expect.objectContaining({
      cwd: '/src',
      stdio: 'inherit',
      env: expect.objectContaining({
        RELEASE_BINARIES_DIR: '/data/agent/release_binaries/users/abc',
        DEST_RELEASE_DIR: '/data/agent/release_binaries/users/abc',
        ELA_EMBEDDED_API_KEY: 'tok123',
        ELA_RELEASE_FLAT_OUTPUT: '1',
      }),
    }));

    child.emit('close', 0);
    await expect(promise).resolves.toEqual({ outDir: '/data/agent/release_binaries/users/abc' });
  });

  test('generic build (no embeddedKey) steers output via RELEASE_BINARIES_DIR and embeds nothing', async () => {
    const child = fakeChild();
    const spawn = jest.fn(() => child);

    const promise = runBuild({ outDir: '/data/agent/release_binaries/generic' }, { spawn, repoRoot: '/src' });

    const env = spawn.mock.calls[0][2].env;
    expect(env).toEqual(expect.objectContaining({
      RELEASE_BINARIES_DIR: '/data/agent/release_binaries/generic',
      DEST_RELEASE_DIR: '/data/agent/release_binaries/generic',
      ELA_RELEASE_FLAT_OUTPUT: '1',
    }));
    expect(env).not.toHaveProperty('ELA_EMBEDDED_API_KEY');
    expect(env).not.toHaveProperty('ELA_EMBEDDED_SERVER_URL');

    child.emit('close', 0);
    await expect(promise).resolves.toEqual({ outDir: '/data/agent/release_binaries/generic' });
  });

  test('passes ELA_EMBEDDED_SERVER_URL only when serverUrl is present', async () => {
    const withUrl = fakeChild();
    const spawnWith = jest.fn(() => withUrl);
    const p1 = runBuild({ embeddedKey: 't', outDir: '/o', serverUrl: 'wss://h' }, { spawn: spawnWith });
    expect(spawnWith.mock.calls[0][2].env).toEqual(expect.objectContaining({
      ELA_EMBEDDED_API_KEY: 't',
      ELA_EMBEDDED_SERVER_URL: 'wss://h',
    }));
    withUrl.emit('close', 0);
    await p1;

    const noUrl = fakeChild();
    const spawnNo = jest.fn(() => noUrl);
    const p2 = runBuild({ embeddedKey: 't', outDir: '/o' }, { spawn: spawnNo });
    expect(spawnNo.mock.calls[0][2].env).not.toHaveProperty('ELA_EMBEDDED_SERVER_URL');
    noUrl.emit('close', 0);
    await p2;
  });

  test('rejects when the build exits non-zero', async () => {
    const child = fakeChild();
    const promise = runBuild({ embeddedKey: 't', outDir: '/o' }, { spawn: () => child });
    child.emit('close', 2);
    await expect(promise).rejects.toThrow('build script exited with status 2');
  });

  test('rejects when the build process cannot be launched', async () => {
    const child = fakeChild();
    const promise = runBuild({ embeddedKey: 't', outDir: '/o' }, { spawn: () => child });
    child.emit('error', new Error('ENOENT'));
    await expect(promise).rejects.toThrow('failed to launch build script: ENOENT');
  });

  test('rejects (without spawning) when outDir is missing', async () => {
    const spawn = jest.fn();
    await expect(runBuild({ embeddedKey: 't' }, { spawn })).rejects.toThrow('missing outDir');
    await expect(runBuild({}, { spawn })).rejects.toThrow('missing outDir');
    expect(spawn).not.toHaveBeenCalled();
  });
});
