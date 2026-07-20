'use strict';

const { EventEmitter } = require('events');
const { Readable, PassThrough } = require('stream');

const registerGhidraAnalysisRoutes = require('../../../../api/client/routes/ghidraAnalysis');

function createApp() {
  const gets = {};
  const posts = {};
  return {
    gets,
    posts,
    get(routePath, ...handlers) { gets[routePath] = handlers[handlers.length - 1]; },
    post(routePath, ...handlers) { posts[routePath] = handlers[handlers.length - 1]; },
  };
}

function createRes() {
  return {
    statusCode: 200,
    jsonBody: undefined,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.jsonBody = value; return this; },
  };
}

// A streaming response stub: a real Writable (so child.stdout.pipe(res) works)
// plus the express-ish surface the download route touches.
function createStreamRes() {
  const sink = new PassThrough();
  const chunks = [];
  sink.on('data', (c) => chunks.push(c));
  sink.statusCode = 200;
  sink.headers = {};
  sink.headersSent = false;
  sink.jsonBody = undefined;
  sink.status = function status(code) { this.statusCode = code; return this; };
  sink.type = function type(t) { this.headers['content-type'] = t; return this; };
  sink.setHeader = function setHeader(k, v) { this.headers[k.toLowerCase()] = v; };
  sink.json = function json(v) { this.jsonBody = v; return this; };
  sink.collected = () => Buffer.concat(chunks);
  return sink;
}

// A fake `zip` child: emits the given stdout bytes then closes with `code`.
function fakeZipChild(bytes, code = 0) {
  const child = new EventEmitter();
  child.stdout = Readable.from([Buffer.from(bytes)]);
  child.killed = false;
  child.kill = () => { child.killed = true; };
  child.stdout.on('end', () => {
    setImmediate(() => child.emit('close', code));
  });
  return child;
}

const MAC = 'aa:bb:cc:dd:ee:ff';

function baseDeps(overrides = {}) {
  // BIGINT PKs arrive from the pg driver as strings; serializers must emit numbers.
  const createdRow = { id: '7', status: 'queued', filesFound: 0, filesAnalyzed: 0 };
  const succeededRow = {
    id: '7', status: 'succeeded', filesFound: 2, filesAnalyzed: 2,
    outputRoot: `/data/agent/${MAC}/ghidra`,
  };
  const queue = { add: jest.fn().mockResolvedValue({ id: 'job-1' }) };
  return {
    createdRow,
    succeededRow,
    queue,
    deps: {
      listUserDeviceMacs: jest.fn().mockResolvedValue([MAC]),
      findDeviceByMac: jest.fn().mockResolvedValue({ id: 3, macAddress: MAC }),
      getQueue: () => queue,
      statDir: jest.fn().mockResolvedValue(true),
      walkOutputs: jest.fn().mockResolvedValue([
        { binary: 'lib/libbar.so', files: 4 },
        { binary: 'usr/bin/foo', files: 12 },
      ]),
      spawnZip: jest.fn(() => fakeZipChild('PK\x03\x04zipbytes')),
      db: {
        createGhidraJob: jest.fn().mockResolvedValue(createdRow),
        listGhidraJobs: jest.fn().mockResolvedValue([createdRow]),
        getGhidraJob: jest.fn().mockResolvedValue(succeededRow),
        ...overrides.db,
      },
      ...overrides.deps,
    },
  };
}

function register(overrides = {}) {
  const app = createApp();
  const setup = baseDeps(overrides);
  registerGhidraAnalysisRoutes(app, setup.deps);
  return { app, ...setup };
}

describe('ghidra analysis routes', () => {
  describe('POST /devices/:mac/ghidra-analysis', () => {
    test('creates a job and enqueues it', async () => {
      const { app, queue, deps } = register();
      const res = createRes();
      await app.posts['/devices/:mac/ghidra-analysis']({ params: { mac: MAC }, authUser: 'alice' }, res);

      expect(res.statusCode).toBe(202);
      expect(res.jsonBody.ghidraAnalysis).toEqual(expect.objectContaining({ id: 7, status: 'queued' }));
      expect(deps.db.createGhidraJob).toHaveBeenCalledWith({ deviceId: 3, username: 'alice' });
      expect(queue.add).toHaveBeenCalledWith('ghidra-analysis', expect.objectContaining({
        jobId: 7, deviceId: 3, mac: MAC,
      }), expect.any(Object));
    });

    test('rejects an invalid mac', async () => {
      const { app } = register();
      const res = createRes();
      await app.posts['/devices/:mac/ghidra-analysis']({ params: { mac: 'nope' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(400);
    });

    test('404 when the device is not associated with the caller', async () => {
      const { app } = register({ deps: { listUserDeviceMacs: jest.fn().mockResolvedValue([]) } });
      const res = createRes();
      await app.posts['/devices/:mac/ghidra-analysis']({ params: { mac: MAC }, authUser: 'mallory' }, res);
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /ghidra-analysis and /:id', () => {
    test('lists the caller jobs', async () => {
      const { app } = register();
      const res = createRes();
      await app.gets['/ghidra-analysis']({ query: {}, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(200);
      expect(res.jsonBody.ghidraAnalyses).toHaveLength(1);
    });

    test('404 for an unknown/unowned job', async () => {
      const { app } = register({ db: { getGhidraJob: jest.fn().mockResolvedValue(null) } });
      const res = createRes();
      await app.gets['/ghidra-analysis/:id']({ params: { id: '99' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /ghidra-analysis/:id/outputs', () => {
    test('lists the downloadable binaries', async () => {
      const { app } = register();
      const res = createRes();
      await app.gets['/ghidra-analysis/:id/outputs']({ params: { id: '7' }, query: {}, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(200);
      expect(res.jsonBody.outputs).toEqual([
        { binary: 'lib/libbar.so', files: 4 },
        { binary: 'usr/bin/foo', files: 12 },
      ]);
    });

    test('409 when the job has not succeeded', async () => {
      const { app } = register({ db: { getGhidraJob: jest.fn().mockResolvedValue({ id: 7, status: 'analyzing' }) } });
      const res = createRes();
      await app.gets['/ghidra-analysis/:id/outputs']({ params: { id: '7' }, query: {}, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(409);
    });
  });

  describe('GET /ghidra-analysis/:id/output.zip', () => {
    test('streams a zip of the whole output tree', async () => {
      const { app, deps } = register();
      const res = createStreamRes();
      await app.gets['/ghidra-analysis/:id/output.zip']({ params: { id: '7' }, query: {}, authUser: 'alice' }, res);
      await new Promise((r) => res.on('finish', r));

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/zip');
      expect(res.headers['content-disposition']).toContain('ghidra-analysis-7.zip');
      expect(deps.spawnZip).toHaveBeenCalledWith(`/data/agent/${MAC}/ghidra`, ['-r', '-q', '-', '.']);
      expect(res.collected().toString()).toContain('zipbytes');
    });

    test('scopes the archive to one binary via ?binary=', async () => {
      const { app, deps } = register();
      const res = createStreamRes();
      await app.gets['/ghidra-analysis/:id/output.zip'](
        { params: { id: '7' }, query: { binary: 'usr/bin/foo' }, authUser: 'alice' }, res,
      );
      await new Promise((r) => res.on('finish', r));
      expect(deps.spawnZip).toHaveBeenCalledWith(`/data/agent/${MAC}/ghidra`, ['-r', '-q', '-', 'usr/bin/foo']);
    });

    test('rejects a traversal ?binary=', async () => {
      const { app, deps } = register();
      const res = createRes();
      await app.gets['/ghidra-analysis/:id/output.zip'](
        { params: { id: '7' }, query: { binary: '../../etc' }, authUser: 'alice' }, res,
      );
      expect(res.statusCode).toBe(400);
      expect(deps.spawnZip).not.toHaveBeenCalled();
    });

    test('409 when the job output is not available', async () => {
      const { app } = register({ db: { getGhidraJob: jest.fn().mockResolvedValue({ id: 7, status: 'analyzing' }) } });
      const res = createRes();
      await app.gets['/ghidra-analysis/:id/output.zip']({ params: { id: '7' }, query: {}, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(409);
    });
  });
});
