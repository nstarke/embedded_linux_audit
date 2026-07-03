'use strict';

const registerModuleBuildRoutes = require('../../../../api/client/routes/moduleBuilds');

function createApp() {
  const gets = {};
  const posts = {};
  return {
    gets,
    posts,
    // Routes may register with middlewares (e.g. a body parser) between the
    // path and the handler; the handler is always last.
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

const MAC = 'aa:bb:cc:dd:ee:ff';

const BUILD_INFO = {
  kernelRelease: '6.1.0-test',
  isa: 'aarch64',
  endianness: 'little',
  vermagic: '6.1.0-test SMP mod_unload aarch64',
  configAvailable: true,
};

function baseDeps(overrides = {}) {
  const createdRow = {
    id: 7,
    status: 'queued',
    kernelRelease: BUILD_INFO.kernelRelease,
    isa: BUILD_INFO.isa,
    endianness: BUILD_INFO.endianness,
    deviceVermagic: BUILD_INFO.vermagic,
  };
  const queue = { add: jest.fn().mockResolvedValue({ id: 'job-1' }) };
  const sendCommand = jest.fn().mockResolvedValue({ status: 200, body: { output: 'ok' } });
  const recordCommandLog = jest.fn().mockResolvedValue(undefined);
  return {
    createdRow,
    queue,
    sendCommand,
    recordCommandLog,
    deps: {
      dataDir: '/data/agent',
      listUserDeviceMacs: jest.fn().mockResolvedValue([MAC]),
      findDeviceByMac: jest.fn().mockResolvedValue({ id: 3, macAddress: MAC }),
      findDeviceById: jest.fn().mockResolvedValue({ id: 3, macAddress: MAC }),
      getQueue: () => queue,
      sendCommand,
      recordCommandLog,
      parseBody: (req, res, next) => next(),
      moduleBaseUrl: 'https://ela.example.com',
      db: {
        latestBuildInfoForDevice: jest.fn().mockResolvedValue({
          upload: { id: 55 },
          buildInfo: { ...BUILD_INFO },
        }),
        latestKernelConfigPath: jest.fn().mockResolvedValue('/data/agent/aa:bb:cc:dd:ee:ff/kernel-config/upload_1.bin'),
        createModuleBuildRequest: jest.fn().mockResolvedValue(createdRow),
        listModuleBuildRequests: jest.fn().mockResolvedValue([createdRow]),
        getModuleBuildRequest: jest.fn().mockResolvedValue(createdRow),
        issueDownloadToken: jest.fn().mockResolvedValue({
          token: 'raw-token-abc',
          expiresAt: new Date('2026-07-02T12:00:00Z'),
        }),
        ...overrides.db,
      },
      ...overrides.deps,
    },
  };
}

function register(overrides = {}) {
  const app = createApp();
  const setup = baseDeps(overrides);
  registerModuleBuildRoutes(app, setup.deps);
  return { app, ...setup };
}

describe('module build routes', () => {
  describe('POST /devices/:mac/module-builds', () => {
    test('creates a request from the latest buildinfo and enqueues the build', async () => {
      const { app, queue, deps } = register();
      const res = createRes();

      await app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);

      expect(res.statusCode).toBe(202);
      expect(res.jsonBody.moduleBuild).toEqual(expect.objectContaining({ id: 7, status: 'queued' }));
      expect(deps.db.createModuleBuildRequest).toHaveBeenCalledWith(expect.objectContaining({
        deviceId: 3,
        username: 'alice',
        buildinfoUploadId: 55,
        kernelRelease: BUILD_INFO.kernelRelease,
        isa: 'aarch64',
        endianness: 'little',
        deviceVermagic: BUILD_INFO.vermagic,
        configArtifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/kernel-config/upload_1.bin',
      }));
      expect(queue.add).toHaveBeenCalledWith('module-build', expect.objectContaining({
        requestId: 7,
        outDir: `/data/agent/${MAC}/modules/7`,
        kernelRelease: BUILD_INFO.kernelRelease,
        isa: 'aarch64',
        endianness: 'little',
        vermagic: BUILD_INFO.vermagic,
        configPath: '/data/agent/aa:bb:cc:dd:ee:ff/kernel-config/upload_1.bin',
      }), expect.any(Object));
    });

    test('skips config lookup when buildinfo reports no config', async () => {
      const { app, deps } = register({
        db: {
          latestBuildInfoForDevice: jest.fn().mockResolvedValue({
            upload: { id: 55 },
            buildInfo: { ...BUILD_INFO, configAvailable: false },
          }),
        },
      });
      const res = createRes();

      await app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);

      expect(res.statusCode).toBe(202);
      expect(deps.db.latestKernelConfigPath).not.toHaveBeenCalled();
      expect(deps.db.createModuleBuildRequest).toHaveBeenCalledWith(expect.objectContaining({
        configArtifactPath: null,
      }));
    });

    test('rejects an invalid mac', async () => {
      const { app } = register();
      const res = createRes();
      await app.posts['/devices/:mac/module-builds']({ params: { mac: 'nope' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(400);
    });

    test('404s a device the caller is not associated with', async () => {
      const { app, deps } = register({
        deps: { listUserDeviceMacs: jest.fn().mockResolvedValue(['11:22:33:44:55:66']) },
      });
      const res = createRes();
      await app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(404);
      expect(deps.db.createModuleBuildRequest).not.toHaveBeenCalled();
    });

    test('matches the ACL separator-insensitively and resolves the stored MAC form', async () => {
      const stored = 'aa-bb-cc-dd-ee-ff';
      const { app, deps, queue } = register({
        deps: {
          listUserDeviceMacs: jest.fn().mockResolvedValue([stored]),
          findDeviceByMac: jest.fn().mockResolvedValue({ id: 3, macAddress: stored }),
        },
      });
      const res = createRes();
      await app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(202);
      expect(deps.findDeviceByMac).toHaveBeenCalledWith(stored);
      expect(queue.add.mock.calls[0][1].outDir).toBe(`/data/agent/${stored}/modules/7`);
    });

    test('409s when the device has no buildinfo upload', async () => {
      const { app } = register({
        db: { latestBuildInfoForDevice: jest.fn().mockResolvedValue(null) },
      });
      const res = createRes();
      await app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(409);
    });

    test('422s an unusable kernel release or unsupported target', async () => {
      const badRelease = register({
        db: {
          latestBuildInfoForDevice: jest.fn().mockResolvedValue({
            upload: { id: 55 },
            buildInfo: { ...BUILD_INFO, kernelRelease: 'garbage' },
          }),
        },
      });
      let res = createRes();
      await badRelease.app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(422);

      const badTarget = register({
        db: {
          latestBuildInfoForDevice: jest.fn().mockResolvedValue({
            upload: { id: 55 },
            buildInfo: { ...BUILD_INFO, isa: 'riscv32' },
          }),
        },
      });
      res = createRes();
      await badTarget.app.posts['/devices/:mac/module-builds']({ params: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(422);
      expect(badTarget.queue.add).not.toHaveBeenCalled();
    });
  });

  describe('POST /module-builds/:id/deliver', () => {
    const SUCCEEDED_ROW = {
      id: 7,
      status: 'succeeded',
      deviceId: 3,
      artifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko',
      vermagicResult: 'match',
    };

    function deliverSetup(overrides = {}) {
      return register({
        ...overrides,
        db: {
          getModuleBuildRequest: jest.fn().mockResolvedValue(SUCCEEDED_ROW),
          ...overrides.db,
        },
      });
    }

    test('mints a token and pushes download then load commands', async () => {
      const { app, deps, sendCommand, recordCommandLog } = deliverSetup();
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'alice' }, res,
      );

      expect(res.statusCode).toBe(200);
      expect(res.jsonBody.delivered).toBe(true);
      expect(deps.db.issueDownloadToken).toHaveBeenCalledWith(7);

      expect(sendCommand).toHaveBeenCalledTimes(2);
      expect(sendCommand.mock.calls[0][0]).toEqual({
        type: 'exec',
        mode: 'ela',
        mac: MAC,
        command: 'linux download-file https://ela.example.com/module/raw-token-abc /tmp/ela_kmod.ko',
      });
      expect(sendCommand.mock.calls[1][0]).toEqual(expect.objectContaining({
        command: 'linux modules load /tmp/ela_kmod.ko',
      }));

      // The audit log and the response must not carry the raw token.
      expect(recordCommandLog.mock.calls[0][0].command).toContain('<token>');
      expect(recordCommandLog.mock.calls[0][0].command).not.toContain('raw-token-abc');
      expect(JSON.stringify(res.jsonBody)).not.toContain('raw-token-abc');
    });

    test('defaults to --force when the built vermagic was not an exact match', async () => {
      const { app, sendCommand } = deliverSetup({
        db: {
          getModuleBuildRequest: jest.fn().mockResolvedValue({
            ...SUCCEEDED_ROW, vermagicResult: 'release-match',
          }),
        },
      });
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'alice' }, res,
      );

      expect(res.jsonBody.force).toBe(true);
      expect(sendCommand.mock.calls[1][0].command)
        .toBe('linux modules load --force /tmp/ela_kmod.ko');
    });

    test('load=false only downloads; explicit force=false overrides the default', async () => {
      const { app, sendCommand } = deliverSetup();
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: { load: false, force: false }, authUser: 'alice' }, res,
      );

      expect(sendCommand).toHaveBeenCalledTimes(1);
      expect(sendCommand.mock.calls[0][0].command).toContain('download-file');
      expect(res.jsonBody.force).toBe(false);
    });

    test('requires a usable baseUrl', async () => {
      const { app, sendCommand } = deliverSetup({ deps: { moduleBaseUrl: null } });
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'alice' }, res,
      );

      expect(res.statusCode).toBe(400);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test('rejects a destPath with shell metacharacters', async () => {
      const { app, sendCommand } = deliverSetup();
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: { destPath: '/tmp/x; rm -rf /' }, authUser: 'alice' }, res,
      );

      expect(res.statusCode).toBe(400);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test('409s a build that is not succeeded', async () => {
      const { app } = deliverSetup({
        db: {
          getModuleBuildRequest: jest.fn().mockResolvedValue({
            ...SUCCEEDED_ROW, status: 'building', artifactPath: null,
          }),
        },
      });
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'alice' }, res,
      );

      expect(res.statusCode).toBe(409);
    });

    test('404s an invisible build (ACL) without minting a token', async () => {
      const { app, deps } = deliverSetup({
        db: { getModuleBuildRequest: jest.fn().mockResolvedValue(null) },
      });
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'mallory' }, res,
      );

      expect(res.statusCode).toBe(404);
      expect(deps.db.issueDownloadToken).not.toHaveBeenCalled();
    });

    test('stops after a failed download and reports 502', async () => {
      const { app, sendCommand } = deliverSetup();
      sendCommand.mockResolvedValueOnce({ status: 500, body: { error: 'download failed' } });
      const res = createRes();

      await app.posts['/module-builds/:id/deliver'](
        { params: { id: '7' }, body: {}, authUser: 'alice' }, res,
      );

      expect(res.statusCode).toBe(502);
      expect(res.jsonBody.delivered).toBe(false);
      // The load command must not run after a failed download.
      expect(sendCommand).toHaveBeenCalledTimes(1);
    });
  });

  describe('GET /module-builds', () => {
    test('lists the caller-visible requests', async () => {
      const { app, deps } = register();
      const res = createRes();
      await app.gets['/module-builds']({ query: {}, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(200);
      expect(res.jsonBody.moduleBuilds).toHaveLength(1);
      expect(deps.db.listModuleBuildRequests).toHaveBeenCalledWith('alice', { mac: null });
    });

    test('accepts a mac filter and rejects a malformed one', async () => {
      const { app, deps } = register();
      let res = createRes();
      await app.gets['/module-builds']({ query: { mac: MAC }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(200);
      expect(deps.db.listModuleBuildRequests).toHaveBeenCalledWith('alice', { mac: MAC });

      res = createRes();
      await app.gets['/module-builds']({ query: { mac: 'zz' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /module-builds/:id', () => {
    test('returns one visible request', async () => {
      const { app, deps } = register();
      const res = createRes();
      await app.gets['/module-builds/:id']({ params: { id: '7' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(200);
      expect(res.jsonBody.moduleBuild).toEqual(expect.objectContaining({ id: 7 }));
      expect(deps.db.getModuleBuildRequest).toHaveBeenCalledWith('alice', 7);
    });

    test('404s an invisible or unknown request and 400s a bad id', async () => {
      const { app } = register({
        db: { getModuleBuildRequest: jest.fn().mockResolvedValue(null) },
      });
      let res = createRes();
      await app.gets['/module-builds/:id']({ params: { id: '999' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(404);

      res = createRes();
      await app.gets['/module-builds/:id']({ params: { id: 'abc' }, authUser: 'alice' }, res);
      expect(res.statusCode).toBe(400);
    });
  });
});
