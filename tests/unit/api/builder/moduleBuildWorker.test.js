'use strict';

// The worker constructs a real BullMQ Worker (which wants a Redis connection);
// mock bullmq virtually (it lives in api/node_modules, not the test root) and
// capture the processor callback instead of connecting.
function loadWorker() {
  jest.resetModules();
  const workerInstances = [];
  const Worker = jest.fn().mockImplementation((queueName, processor) => {
    const instance = {
      queueName,
      processor,
      handlers: {},
      on(event, cb) { this.handlers[event] = cb; return this; },
      close: jest.fn(),
    };
    workerInstances.push(instance);
    return instance;
  });
  jest.doMock('bullmq', () => ({ Worker }), { virtual: true });

  const { startModuleBuildWorker } = require('../../../../api/builder/moduleBuildWorker');
  const { MODULE_BUILD_QUEUE_NAME } = require('../../../../api/lib/queue');
  return { startModuleBuildWorker, MODULE_BUILD_QUEUE_NAME, workerInstances };
}

function fakeDb() {
  return {
    markBuildStarted: jest.fn().mockResolvedValue(undefined),
    markBuildSucceeded: jest.fn().mockResolvedValue(undefined),
    markBuildFailed: jest.fn().mockResolvedValue(undefined),
  };
}

const JOB_DATA = {
  requestId: 7,
  outDir: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7',
  kernelRelease: '6.1.0',
  isa: 'aarch64',
  endianness: 'little',
  vermagic: '6.1.0 SMP mod_unload aarch64',
};

const BUILD_RESULT = {
  outDir: JOB_DATA.outDir,
  koPath: `${JOB_DATA.outDir}/ela_kmod.ko`,
  builtVermagic: '6.1.0 SMP mod_unload aarch64',
  vermagicResult: 'match',
  source: 'upstream-exact',
};

describe('module build worker', () => {
  afterEach(() => {
    jest.resetModules();
  });

  test('listens on the module-build queue', () => {
    const { startModuleBuildWorker, MODULE_BUILD_QUEUE_NAME, workerInstances } = loadWorker();
    startModuleBuildWorker({ runBuild: jest.fn(), db: fakeDb() });
    expect(workerInstances).toHaveLength(1);
    expect(workerInstances[0].queueName).toBe(MODULE_BUILD_QUEUE_NAME);
  });

  test('marks the request building then succeeded around a successful build', async () => {
    const { startModuleBuildWorker, workerInstances } = loadWorker();
    const db = fakeDb();
    const runBuild = jest.fn().mockResolvedValue(BUILD_RESULT);
    startModuleBuildWorker({ runBuild, db });

    const result = await workerInstances[0].processor({ id: 'j1', data: JOB_DATA });

    expect(db.markBuildStarted).toHaveBeenCalledWith(7);
    expect(runBuild).toHaveBeenCalledWith(JOB_DATA);
    expect(db.markBuildSucceeded).toHaveBeenCalledWith(7, {
      builtVermagic: BUILD_RESULT.builtVermagic,
      vermagicResult: 'match',
      source: 'upstream-exact',
      artifactPath: BUILD_RESULT.koPath,
    });
    expect(db.markBuildFailed).not.toHaveBeenCalled();
    expect(result).toEqual(BUILD_RESULT);
  });

  test('marks the request failed and rethrows when the build rejects', async () => {
    const { startModuleBuildWorker, workerInstances } = loadWorker();
    const db = fakeDb();
    const runBuild = jest.fn().mockRejectedValue(new Error('modules_prepare exploded'));
    startModuleBuildWorker({ runBuild, db });

    await expect(workerInstances[0].processor({ id: 'j1', data: JOB_DATA }))
      .rejects.toThrow('modules_prepare exploded');

    expect(db.markBuildFailed).toHaveBeenCalledWith(7, 'modules_prepare exploded');
    expect(db.markBuildSucceeded).not.toHaveBeenCalled();
  });

  test('a status-write failure does not fail the build', async () => {
    const { startModuleBuildWorker, workerInstances } = loadWorker();
    const db = fakeDb();
    db.markBuildStarted.mockRejectedValue(new Error('db down'));
    db.markBuildSucceeded.mockRejectedValue(new Error('db down'));
    const runBuild = jest.fn().mockResolvedValue(BUILD_RESULT);
    startModuleBuildWorker({ runBuild, db });

    await expect(workerInstances[0].processor({ id: 'j1', data: JOB_DATA }))
      .resolves.toEqual(BUILD_RESULT);
  });

  test('runs without a requestId (no status writes)', async () => {
    const { startModuleBuildWorker, workerInstances } = loadWorker();
    const db = fakeDb();
    const runBuild = jest.fn().mockResolvedValue(BUILD_RESULT);
    startModuleBuildWorker({ runBuild, db });

    const { requestId, ...withoutId } = JOB_DATA;
    await workerInstances[0].processor({ id: 'j1', data: withoutId });

    expect(db.markBuildStarted).not.toHaveBeenCalled();
    expect(db.markBuildSucceeded).not.toHaveBeenCalled();
  });
});
