'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function createFakeWs() {
  const handlers = new Map();
  return {
    handlers,
    on: jest.fn((event, handler) => {
      handlers.set(event, handler);
    }),
    close: jest.fn(),
  };
}

function flush() {
  // Yield to the event loop's I/O phase. A real (zero-delay) timer is used
  // rather than setImmediate so the poll reliably observes write-stream flush
  // callbacks (`stream.end(cb)`) even when the loop is busy after many prior
  // test files have run in-band.
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function loadPcapWebSocket(options = {}) {
  jest.resetModules();

  const WebSocketServer = jest.fn(function WebSocketServer(opts) {
    this.options = opts;
    this.handlers = new Map();
    this.on = jest.fn((event, handler) => {
      this.handlers.set(event, handler);
    });
  });
  const auth = {
    checkBearer: jest.fn(() => true),
  };
  const serverUtils = {
    isValidMacAddress: jest.fn(() => true),
    getClientIp: jest.fn((req) => req.socket?.remoteAddress || 'unknown'),
  };

  if (options.auth) Object.assign(auth, options.auth);

  jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  jest.doMock('fs', () => jest.requireActual('fs'));
  jest.doMock('ws', () => ({ WebSocketServer }), { virtual: true });
  jest.doMock('../../../../api/auth', () => auth);
  jest.doMock('../../../../api/agent/serverUtils', () => serverUtils);

  const mod = require('../../../../api/agent/pcapWebSocket');
  return { ...mod, WebSocketServer, auth, serverUtils };
}

describe('agent pcap websocket receiver', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('verifyClient enforces pcap path and bearer auth', () => {
    const { createPcapWebSocketServer, WebSocketServer, auth } = loadPcapWebSocket();
    createPcapWebSocketServer({
      server: {},
      dataDir: '/tmp/noop',
      persistUpload: jest.fn(),
    });
    const verifyClient = WebSocketServer.mock.instances[0].options.verifyClient;
    const done = jest.fn();

    verifyClient({ req: { url: '/upload/aa:bb', headers: {} } }, done);
    expect(done).toHaveBeenLastCalledWith(false, 404, 'Not Found');

    auth.checkBearer.mockReturnValueOnce(false);
    verifyClient({ req: { url: '/pcap/aa:bb:cc:dd:ee:ff', headers: {} } }, done);
    expect(done).toHaveBeenLastCalledWith(false, 401, 'Unauthorized');

    verifyClient({ req: { url: '/pcap/aa:bb:cc:dd:ee:ff', headers: { authorization: 'Bearer ok' } } }, done);
    expect(done).toHaveBeenLastCalledWith(true);
  });

  test('connection writes binary chunks and persists artifact path on close', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-pcap-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const { createPcapWebSocketServer, WebSocketServer } = loadPcapWebSocket();
    createPcapWebSocketServer({
      server: {},
      dataDir,
      persistUpload,
    });
    const onConnection = WebSocketServer.mock.instances[0].handlers.get('connection');
    const ws = createFakeWs();

    onConnection(ws, {
      url: '/pcap/aa:bb:cc:dd:ee:ff',
      socket: { remoteAddress: '127.0.0.1' },
      headers: {},
    });
    ws.handlers.get('message')(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]));
    ws.handlers.get('message')(Buffer.from([1, 2, 3]));
    ws.handlers.get('close')();

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }

    expect(persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      macAddress: 'aa:bb:cc:dd:ee:ff',
      uploadType: 'pcap',
      contentType: 'application/octet-stream',
      localArtifactPath: expect.stringMatching(/capture_.*\.pcap$/),
    }));
    const artifactPath = persistUpload.mock.calls[0][0].localArtifactPath;
    expect(fs.readFileSync(artifactPath)).toEqual(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 1, 2, 3]));

    fs.rmSync(dataDir, { recursive: true, force: true });
  });
});
