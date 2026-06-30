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
        DEST_RELEASE_DIR: '/data/agent/release_binaries/users/abc',
        ELA_EMBEDDED_API_KEY: 'tok123',
        ELA_RELEASE_FLAT_OUTPUT: '1',
      }),
    }));

    child.emit('close', 0);
    await expect(promise).resolves.toEqual({ outDir: '/data/agent/release_binaries/users/abc' });
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

  test('rejects (without spawning) when required job fields are missing', async () => {
    const spawn = jest.fn();
    await expect(runBuild({ outDir: '/o' }, { spawn })).rejects.toThrow('missing embeddedKey');
    await expect(runBuild({ embeddedKey: 't' }, { spawn })).rejects.toThrow('missing outDir');
    expect(spawn).not.toHaveBeenCalled();
  });
});
