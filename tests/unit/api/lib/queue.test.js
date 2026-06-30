'use strict';

function loadQueue(env = {}) {
  jest.resetModules();
  const instances = [];
  const Queue = jest.fn(function Queue(name, opts) {
    this.name = name;
    this.opts = opts;
    this.add = jest.fn();
    this.close = jest.fn().mockResolvedValue(undefined);
    instances.push(this);
  });
  jest.doMock('bullmq', () => ({ Queue }), { virtual: true });

  const prev = {};
  for (const [k, v] of Object.entries(env)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }

  const mod = require('../../../../api/lib/queue');
  return { mod, Queue, instances, restore: () => {
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
});
