'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function createFakeWs() {
  const handlers = new Map();
  return {
    handlers,
    on: jest.fn((event, handler) => { handlers.set(event, handler); }),
    close: jest.fn(),
  };
}

function flush() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function loadWlanFuzzWebSocket(options = {}) {
  jest.resetModules();

  const WebSocketServer = jest.fn(function WebSocketServer(opts) {
    this.options = opts;
    this.handlers = new Map();
    this.on = jest.fn((event, handler) => { this.handlers.set(event, handler); });
  });
  const auth = { resolveBearer: jest.fn().mockResolvedValue(true) };
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

  const mod = require('../../../../api/agent/wlanFuzzWebSocket');
  return { ...mod, WebSocketServer, auth, serverUtils };
}

function connect(dataDir, persistUpload, opts = {}) {
  const seg = opts.pathSegment || 'wlan-fuzz';
  const { createWlanFuzzWebSocketServer, WebSocketServer } = loadWlanFuzzWebSocket();
  createWlanFuzzWebSocketServer({ server: {}, dataDir, persistUpload, ...opts });
  const onConnection = WebSocketServer.mock.instances[0].handlers.get('connection');
  const ws = createFakeWs();
  onConnection(ws, {
    url: `/${seg}/aa:bb:cc:dd:ee:ff`,
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
  });
  return ws;
}

describe('agent wlan-fuzz websocket receiver', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('buildCrashFile produces a replayable crash file, guarding the target', () => {
    const { buildCrashFile } = loadWlanFuzzWebSocket();
    expect(buildCrashFile('wext-generic', 'SIWESSID 4142 #buf=len:2'))
      .toBe('# target=wext-generic cases=1\nSIWESSID 4142 #buf=len:2\n');
    // a bogus target falls back rather than being injected into the header
    expect(buildCrashFile('evil target\ninject', 'X 00'))
      .toBe('# target=wext-generic cases=1\nX 00\n');
  });

  test('verifyClient enforces the wlan-fuzz path and bearer auth', async () => {
    const { createWlanFuzzWebSocketServer, WebSocketServer, auth } = loadWlanFuzzWebSocket();
    createWlanFuzzWebSocketServer({ server: {}, dataDir: '/tmp/noop', persistUpload: jest.fn() });
    const { verifyClient } = WebSocketServer.mock.instances[0].options;
    const done = jest.fn();

    verifyClient({ req: { url: '/pcap/aa:bb', headers: {} } }, done);
    expect(done).toHaveBeenLastCalledWith(false, 404, 'Not Found');

    auth.resolveBearer.mockResolvedValueOnce(false);
    verifyClient({ req: { url: '/wlan-fuzz/aa:bb:cc:dd:ee:ff', headers: {} } }, done);
    await flush();
    expect(done).toHaveBeenLastCalledWith(false, 401, 'Unauthorized');

    auth.resolveBearer.mockResolvedValueOnce(true);
    verifyClient({ req: { url: '/wlan-fuzz/aa:bb:cc:dd:ee:ff', headers: { authorization: 'Bearer ok' } } }, done);
    await flush();
    expect(done).toHaveBeenLastCalledWith(true);
  });

  test('ungraceful close saves the LAST held payload as a triage crash file', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload);

    ws.handlers.get('message')(Buffer.from('T wext-generic'));
    ws.handlers.get('message')(Buffer.from('C SIWESSID 4142 #first'));
    ws.handlers.get('message')(Buffer.from('C SIWENCODE deadbeef #second'));
    ws.handlers.get('close')(); // no 'D' -> host died mid-fuzz

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }

    expect(persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      macAddress: 'aa:bb:cc:dd:ee:ff',
      uploadType: 'wlan-fuzz',
      contentType: 'application/octet-stream',
      localArtifactPath: expect.stringMatching(/crash_.*\.txt$/),
    }));
    const artifactPath = persistUpload.mock.calls[0][0].localArtifactPath;
    // only the latest case is kept, and it's a replayable crash file
    expect(fs.readFileSync(artifactPath, 'utf8'))
      .toBe('# target=wext-generic cases=1\nSIWENCODE deadbeef #second\n');

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('a graceful "done" frame means a clean run: nothing is saved on close', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload);

    ws.handlers.get('message')(Buffer.from('T wext-generic'));
    ws.handlers.get('message')(Buffer.from('C SIWESSID 4142 #case'));
    ws.handlers.get('message')(Buffer.from('D')); // clean finish
    ws.handlers.get('close')();

    for (let i = 0; i < 10; i += 1) await flush();
    expect(persistUpload).not.toHaveBeenCalled();

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('pathSegment eth-fuzz serves the ethernet endpoint and tags its uploads', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-ethfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload, { pathSegment: 'eth-fuzz', uploadType: 'eth-fuzz' });

    ws.handlers.get('message')(Buffer.from('T ethtool-generic'));
    ws.handlers.get('message')(Buffer.from('C GEEPROM 0b00000000ffffff00 #len'));
    ws.handlers.get('close')();

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }
    expect(persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      uploadType: 'eth-fuzz',
      localArtifactPath: expect.stringMatching(/eth-fuzz\/crash_.*\.txt$/),
    }));
    expect(fs.readFileSync(persistUpload.mock.calls[0][0].localArtifactPath, 'utf8'))
      .toBe('# target=ethtool-generic cases=1\nGEEPROM 0b00000000ffffff00 #len\n');

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('close with no payloads at all saves nothing', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload);
    ws.handlers.get('close')();
    for (let i = 0; i < 10; i += 1) await flush();
    expect(persistUpload).not.toHaveBeenCalled();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
});
