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
  createWlanFuzzWebSocketServer({ dataDir, persistUpload, ...opts });
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

  test('buildCrashFile writes a whole ring, oldest first, with a matching count', () => {
    const { buildCrashFile } = loadWlanFuzzWebSocket();
    expect(buildCrashFile('ath10k', ['A 01 #one', 'B 02 #two', 'C 03 #three']))
      .toBe('# target=ath10k cases=3\nA 01 #one\nB 02 #two\nC 03 #three\n');
  });

  test('runs in noServer mode and exposes a per-segment pathRe', () => {
    const { createWlanFuzzWebSocketServer, WebSocketServer } = loadWlanFuzzWebSocket();
    const wlan = createWlanFuzzWebSocketServer({ dataDir: '/tmp/noop', persistUpload: jest.fn() });
    const eth = createWlanFuzzWebSocketServer({
      dataDir: '/tmp/noop', persistUpload: jest.fn(), pathSegment: 'eth-fuzz',
    });
    // noServer mode: routing/auth is the dispatcher's job, so each server only
    // exposes the pathRe that identifies its own path segment.
    expect(WebSocketServer.mock.instances[0].options).toEqual({ noServer: true });
    expect(wlan.pathRe.test('/wlan-fuzz/aa:bb:cc:dd:ee:ff')).toBe(true);
    expect(wlan.pathRe.test('/pcap/aa:bb')).toBe(false);
    expect(wlan.pathRe.test('/eth-fuzz/aa:bb:cc:dd:ee:ff')).toBe(false);
    expect(eth.pathRe.test('/eth-fuzz/aa:bb:cc:dd:ee:ff')).toBe(true);
    expect(eth.pathRe.test('/wlan-fuzz/aa:bb:cc:dd:ee:ff')).toBe(false);
  });

  test('ungraceful close saves the held ring as a triage crash file', async () => {
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
    // both cases are kept, oldest first, as one replayable crash file: under the
    // default ring of 10 nothing is evicted
    expect(fs.readFileSync(artifactPath, 'utf8'))
      .toBe('# target=wext-generic cases=2\nSIWESSID 4142 #first\nSIWENCODE deadbeef #second\n');

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('the ring defaults to the last 10 cases, evicting the oldest', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload);

    ws.handlers.get('message')(Buffer.from('T wext-generic'));
    for (let i = 0; i < 14; i += 1) {
      ws.handlers.get('message')(Buffer.from(`C SIWESSID 4142 #case${i}`));
    }
    ws.handlers.get('close')();

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }
    const text = fs.readFileSync(persistUpload.mock.calls[0][0].localArtifactPath, 'utf8');
    const lines = text.trim().split('\n');
    expect(lines[0]).toBe('# target=wext-generic cases=10');
    // cases 0-3 evicted; the newest case is last, where replay expects it
    expect(lines[1]).toBe('SIWESSID 4142 #case4');
    expect(lines[10]).toBe('SIWESSID 4142 #case13');

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('resolveRingSize sizes the ring, and is re-read per connection', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const resolveRingSize = jest.fn().mockResolvedValue(3);
    const ws = connect(dataDir, persistUpload, { resolveRingSize });

    ws.handlers.get('message')(Buffer.from('T wext-generic'));
    for (let i = 0; i < 5; i += 1) {
      ws.handlers.get('message')(Buffer.from(`C SIWESSID 4142 #case${i}`));
    }
    ws.handlers.get('close')();

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }
    expect(resolveRingSize).toHaveBeenCalledTimes(1);
    expect(fs.readFileSync(persistUpload.mock.calls[0][0].localArtifactPath, 'utf8')).toBe(
      '# target=wext-generic cases=3\n'
      + 'SIWESSID 4142 #case2\nSIWESSID 4142 #case3\nSIWESSID 4142 #case4\n',
    );

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('a failing ring-size lookup still captures the crash at the default size', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const resolveRingSize = jest.fn().mockRejectedValue(new Error('db down'));
    const ws = connect(dataDir, persistUpload, { resolveRingSize });

    ws.handlers.get('message')(Buffer.from('T wext-generic'));
    ws.handlers.get('message')(Buffer.from('C SIWESSID 4142 #only'));
    ws.handlers.get('close')();

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }
    // the settings store being down must not cost us the panic capture
    expect(fs.readFileSync(persistUpload.mock.calls[0][0].localArtifactPath, 'utf8'))
      .toBe('# target=wext-generic cases=1\nSIWESSID 4142 #only\n');

    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('an X frame persists a confirmed crash immediately, independent of close', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-wlanfuzz-ws-'));
    const persistUpload = jest.fn().mockResolvedValue({});
    const ws = connect(dataDir, persistUpload);

    ws.handlers.get('message')(Buffer.from('T ath10k'));
    const crashFile = '# target=ath10k cases=2\nVDEV_CREATE 0800 #a\nPEER_DELETE 01 #b\n';
    ws.handlers.get('message')(Buffer.from(`X ${crashFile}`));

    for (let i = 0; i < 20 && persistUpload.mock.calls.length === 0; i += 1) {
      await flush();
    }
    // saved on receipt of X -- before any close, and even though the agent
    // survives (a locally-detected, minimized crash uploaded live)
    expect(persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      uploadType: 'wlan-fuzz',
      localArtifactPath: expect.stringMatching(/crash_.*\.txt$/),
    }));
    expect(fs.readFileSync(persistUpload.mock.calls[0][0].localArtifactPath, 'utf8'))
      .toBe(crashFile);

    // a subsequent graceful close saves nothing more (no held C payload)
    ws.handlers.get('message')(Buffer.from('D'));
    ws.handlers.get('close')();
    for (let i = 0; i < 10; i += 1) await flush();
    expect(persistUpload).toHaveBeenCalledTimes(1);

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
