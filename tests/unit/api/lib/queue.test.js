'use strict';

function loadQueue(env = {}) {
  jest.resetModules();
  const instances = [];
  const eventsInstances = [];
  const Queue = jest.fn(function Queue(name, opts) {
    this.name = name;
    this.opts = opts;
    this.add = jest.fn(async (jobName, data, jobOpts) => ({
      id: '1',
      name: jobName,
      data,
      opts: jobOpts,
      waitUntilFinished: jest.fn().mockResolvedValue({ status: 200, body: { ok: true } }),
    }));
    this.close = jest.fn().mockResolvedValue(undefined);
    instances.push(this);
  });
  const QueueEvents = jest.fn(function QueueEvents(name, opts) {
    this.name = name;
    this.opts = opts;
    this.waitUntilReady = jest.fn().mockResolvedValue(undefined);
    this.close = jest.fn().mockResolvedValue(undefined);
    eventsInstances.push(this);
  });
  jest.doMock('bullmq', () => ({ Queue, QueueEvents }), { virtual: true });

  const prev = {};
  for (const [k, v] of Object.entries(env)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }

  const mod = require('../../../../api/lib/queue');
  return { mod, Queue, QueueEvents, instances, eventsInstances, restore: () => {
    for (const [k] of Object.entries(env)) {
      if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k];
    }
  } };
}

describe('build queue', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('getConnection reads REDIS_HOST/REDIS_PORT with sensible defaults', () => {
    let { mod, restore } = loadQueue();
    expect(mod.getConnection()).toEqual({ host: 'redis', port: 6379 });
    restore();

    ({ mod, restore } = loadQueue({ REDIS_HOST: 'cache.internal', REDIS_PORT: '6380' }));
    expect(mod.getConnection()).toEqual({ host: 'cache.internal', port: 6380 });
    restore();
  });

  test('getWorkerOptions uses build-appropriate defaults', () => {
    const { mod, restore } = loadQueue();
    expect(mod.getWorkerOptions()).toEqual({
      connection: { host: 'redis', port: 6379 },
      concurrency: 1,
      lockDuration: 30 * 60 * 1000,
      stalledInterval: 30 * 1000,
      maxStalledCount: 3,
    });
    restore();
  });

  test('getWorkerOptions honours env overrides', () => {
    const { mod, restore } = loadQueue({
      ELA_BUILD_CONCURRENCY: '2',
      ELA_BUILD_LOCK_DURATION_MS: '600000',
      ELA_BUILD_STALLED_INTERVAL_MS: '45000',
      ELA_BUILD_MAX_STALLED_COUNT: '5',
    });
    expect(mod.getWorkerOptions()).toMatchObject({
      concurrency: 2,
      lockDuration: 600000,
      stalledInterval: 45000,
      maxStalledCount: 5,
    });
    restore();
  });

  test('getWorkerOptions falls back to defaults for invalid/non-positive values', () => {
    const { mod, restore } = loadQueue({
      ELA_BUILD_CONCURRENCY: '0',
      ELA_BUILD_LOCK_DURATION_MS: 'abc',
      ELA_BUILD_MAX_STALLED_COUNT: '-3',
    });
    expect(mod.getWorkerOptions()).toMatchObject({
      concurrency: 1,
      lockDuration: 30 * 60 * 1000,
      maxStalledCount: 3,
    });
    restore();
  });

  test('getBuildQueue creates one Queue with the configured name and connection', () => {
    const { mod, Queue, instances, restore } = loadQueue();
    const q1 = mod.getBuildQueue();
    const q2 = mod.getBuildQueue();

    expect(q1).toBe(q2); // singleton
    expect(Queue).toHaveBeenCalledTimes(1);
    expect(instances[0].name).toBe('ela-binary-builds');
    expect(instances[0].opts).toEqual({ connection: { host: 'redis', port: 6379 } });
    restore();
  });

  test('closeBuildQueue closes and allows a fresh queue afterward', async () => {
    const { mod, Queue, instances, restore } = loadQueue();
    const q1 = mod.getBuildQueue();
    await mod.closeBuildQueue();
    expect(instances[0].close).toHaveBeenCalledTimes(1);

    const q2 = mod.getBuildQueue();
    expect(q2).not.toBe(q1);
    expect(Queue).toHaveBeenCalledTimes(2);
    restore();
  });

  test('getCommandQueue creates one command Queue (separate from the build queue)', () => {
    const { mod, Queue, instances, restore } = loadQueue();
    const c1 = mod.getCommandQueue();
    const c2 = mod.getCommandQueue();
    expect(c1).toBe(c2);
    expect(Queue).toHaveBeenCalledTimes(1);
    expect(instances[0].name).toBe('ela-terminal-commands');
    restore();
  });

  test('getCommandWorkerOptions defaults concurrency to 8 and honours the env override', () => {
    let { mod, restore } = loadQueue();
    expect(mod.getCommandWorkerOptions()).toEqual({ connection: { host: 'redis', port: 6379 }, concurrency: 8 });
    restore();

    ({ mod, restore } = loadQueue({ ELA_TERMINAL_CONCURRENCY: '4' }));
    expect(mod.getCommandWorkerOptions().concurrency).toBe(4);
    restore();
  });

  test('sendTerminalCommand enqueues the payload and resolves with the worker result', async () => {
    const { mod, instances, eventsInstances, restore } = loadQueue();

    const result = await mod.sendTerminalCommand({ type: 'exec', mac: 'aa:bb', command: 'id' }, { waitMs: 5000 });

    // Queue + QueueEvents created for the command queue.
    expect(instances[0].name).toBe('ela-terminal-commands');
    expect(eventsInstances[0].name).toBe('ela-terminal-commands');
    expect(eventsInstances[0].waitUntilReady).toHaveBeenCalled();

    const addCall = instances[0].add.mock.calls[0];
    expect(addCall[0]).toBe('exec');
    expect(addCall[1]).toEqual({ type: 'exec', mac: 'aa:bb', command: 'id' });
    expect(addCall[2]).toEqual({ removeOnComplete: true, removeOnFail: true });
    expect(result).toEqual({ status: 200, body: { ok: true } });
    restore();
  });

  test('closeCommandQueue closes both the queue and its events stream', async () => {
    const { mod, instances, eventsInstances, restore } = loadQueue();
    mod.getCommandQueue();
    mod.getCommandQueueEvents();
    await mod.closeCommandQueue();
    expect(instances[0].close).toHaveBeenCalledTimes(1);
    expect(eventsInstances[0].close).toHaveBeenCalledTimes(1);
    restore();
  });
});
