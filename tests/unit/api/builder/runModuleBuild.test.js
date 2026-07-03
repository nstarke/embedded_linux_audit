'use strict';

const { runModuleBuild } = require('../../../../api/builder/runModuleBuild');

function fakeChild() {
  const handlers = {};
  return {
    on(event, cb) { handlers[event] = cb; return this; },
    emit(event, ...args) { if (handlers[event]) handlers[event](...args); },
  };
}

function fakeFsp(vermagic = '6.1.0 SMP mod_unload aarch64') {
  return {
    readFile: jest.fn().mockResolvedValue(`${vermagic}\n`),
  };
}

const BASE_PAYLOAD = {
  outDir: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7',
  kernelRelease: '6.1.0',
  isa: 'aarch64',
  endianness: 'little',
  vermagic: '6.1.0 SMP mod_unload aarch64',
};

describe('runModuleBuild', () => {
  test('spawns the build script with target env and resolves with vermagic verification', async () => {
    const child = fakeChild();
    const spawn = jest.fn(() => child);
    const fsp = fakeFsp();

    const promise = runModuleBuild(BASE_PAYLOAD, { spawn, fsp, repoRoot: '/src' });

    expect(spawn).toHaveBeenCalledWith('sh', ['/src/api/builder/build-kernel-module.sh'], expect.objectContaining({
      cwd: '/src',
      stdio: 'inherit',
      env: expect.objectContaining({
        ELA_KMOD_KERNEL_VERSION: '6.1.0',
        ELA_KMOD_LOCALVERSION: '',
        ELA_KMOD_ARCH: 'arm64',
        ELA_KMOD_CROSS_COMPILE: 'aarch64-linux-gnu-',
        ELA_KMOD_OUT_DIR: BASE_PAYLOAD.outDir,
      }),
    }));

    child.emit('close', 0);
    await expect(promise).resolves.toEqual({
      outDir: BASE_PAYLOAD.outDir,
      koPath: `${BASE_PAYLOAD.outDir}/ela_kmod.ko`,
      builtVermagic: '6.1.0 SMP mod_unload aarch64',
      vermagicResult: 'match',
      source: 'upstream-exact',
    });
    expect(fsp.readFile).toHaveBeenCalledWith(`${BASE_PAYLOAD.outDir}/vermagic.txt`, 'utf8');
  });

  test('vendor-suffixed releases build the upstream base with LOCALVERSION and report upstream-nearest', async () => {
    const child = fakeChild();
    const spawn = jest.fn(() => child);
    const fsp = fakeFsp('3.12.19-rt30 SMP mod_unload ARMv7');

    const promise = runModuleBuild({
      ...BASE_PAYLOAD,
      kernelRelease: '3.12.19-rt30',
      isa: 'arm32',
      vermagic: '3.12.19-rt30 SMP mod_unload ARMv7',
    }, { spawn, fsp, repoRoot: '/src' });

    expect(spawn.mock.calls[0][2].env).toEqual(expect.objectContaining({
      ELA_KMOD_KERNEL_VERSION: '3.12.19',
      ELA_KMOD_LOCALVERSION: '-rt30',
      ELA_KMOD_ARCH: 'arm',
      ELA_KMOD_CROSS_COMPILE: 'arm-linux-gnueabi-',
    }));

    child.emit('close', 0);
    const result = await promise;
    expect(result.source).toBe('upstream-nearest');
    expect(result.vermagicResult).toBe('match');
  });

  test('passes the device config path only when provided', async () => {
    const withConfig = fakeChild();
    const spawnWith = jest.fn(() => withConfig);
    const p1 = runModuleBuild({ ...BASE_PAYLOAD, configPath: '/data/x/kernel-config/upload_1.bin' }, {
      spawn: spawnWith, fsp: fakeFsp(),
    });
    expect(spawnWith.mock.calls[0][2].env).toEqual(expect.objectContaining({
      ELA_KMOD_CONFIG_PATH: '/data/x/kernel-config/upload_1.bin',
    }));
    withConfig.emit('close', 0);
    await p1;

    const noConfig = fakeChild();
    const spawnNo = jest.fn(() => noConfig);
    const p2 = runModuleBuild(BASE_PAYLOAD, { spawn: spawnNo, fsp: fakeFsp() });
    expect(spawnNo.mock.calls[0][2].env).not.toHaveProperty('ELA_KMOD_CONFIG_PATH');
    noConfig.emit('close', 0);
    await p2;
  });

  test('reports unverified when the payload has no device vermagic', async () => {
    const child = fakeChild();
    const promise = runModuleBuild({ ...BASE_PAYLOAD, vermagic: undefined }, {
      spawn: () => child, fsp: fakeFsp(),
    });
    child.emit('close', 0);
    await expect(promise).resolves.toEqual(expect.objectContaining({ vermagicResult: 'unverified' }));
  });

  test('rejects without spawning on missing outDir, bad release, or unsupported target', async () => {
    const spawn = jest.fn();
    await expect(runModuleBuild({ ...BASE_PAYLOAD, outDir: undefined }, { spawn }))
      .rejects.toThrow('missing outDir');
    await expect(runModuleBuild({ ...BASE_PAYLOAD, kernelRelease: 'not-a-kernel' }, { spawn }))
      .rejects.toThrow('unparseable kernel release');
    await expect(runModuleBuild({ ...BASE_PAYLOAD, isa: 'riscv32' }, { spawn }))
      .rejects.toThrow('unsupported build target');
    expect(spawn).not.toHaveBeenCalled();
  });

  test('rejects when the build exits non-zero', async () => {
    const child = fakeChild();
    const promise = runModuleBuild(BASE_PAYLOAD, { spawn: () => child, fsp: fakeFsp() });
    child.emit('close', 3);
    await expect(promise).rejects.toThrow('module build script exited with status 3');
  });

  test('rejects when artifacts are unreadable after a zero exit', async () => {
    const child = fakeChild();
    const fsp = { readFile: jest.fn().mockRejectedValue(new Error('ENOENT')) };
    const promise = runModuleBuild(BASE_PAYLOAD, { spawn: () => child, fsp });
    child.emit('close', 0);
    await expect(promise).rejects.toThrow('module build produced no readable artifacts');
  });

  test('rejects when the build process cannot be launched', async () => {
    const child = fakeChild();
    const promise = runModuleBuild(BASE_PAYLOAD, { spawn: () => child, fsp: fakeFsp() });
    child.emit('error', new Error('ENOENT'));
    await expect(promise).rejects.toThrow('failed to launch module build script: ENOENT');
  });
});
