'use strict';

const os = require('os');
const path = require('path');
const fsp = require('fs/promises');

const {
  runGhidraAnalysis,
  fsRootFromArtifactPath,
  countAnalyzed,
} = require('../../../../api/ghidra/runGhidraAnalysis');

describe('fsRootFromArtifactPath', () => {
  const dataDir = '/data/agent';
  test('recovers <data>/<macDir>/fs from a file artifact path', () => {
    expect(fsRootFromArtifactPath(dataDir, '/data/agent/20:4c:03:32:75:5c/fs/usr/bin/foo'))
      .toBe('/data/agent/20:4c:03:32:75:5c/fs');
  });
  test('recovers the fs root when an extra grouping dir sits above the mac dir', () => {
    // Some agents nest an extra grouping dir (an instance/session id) above the
    // MAC dir, so `fs` is one level deeper. Its value is host-specific and must
    // not be assumed: the root is the path up to and including the `fs` wrapper,
    // not <data>/<firstSegment>/fs (which would be a non-existent directory).
    expect(fsRootFromArtifactPath(dataDir, '/data/agent/<group-id>/20:4c:03:32:75:5c/fs/sys/devices/soc.0/uevent'))
      .toBe('/data/agent/<group-id>/20:4c:03:32:75:5c/fs');
  });
  test('returns null when the artifact path has no fs wrapper segment', () => {
    expect(fsRootFromArtifactPath(dataDir, '/data/agent/20:4c:03:32:75:5c/module-buildinfo/x.log')).toBeNull();
  });
  test('rejects a path outside dataDir', () => {
    expect(fsRootFromArtifactPath(dataDir, '/etc/passwd')).toBeNull();
  });
});

describe('countAnalyzed', () => {
  let root;
  beforeEach(async () => { root = await fsp.mkdtemp(path.join(os.tmpdir(), 'ela-count-')); });
  afterEach(async () => { await fsp.rm(root, { recursive: true, force: true }); });

  test('counts program subdirs that contain at least one .c file', async () => {
    await fsp.mkdir(path.join(root, 'foo'), { recursive: true });
    await fsp.writeFile(path.join(root, 'foo', 'main@0x1000.c'), 'int main(){}');
    await fsp.mkdir(path.join(root, 'bar'), { recursive: true });
    await fsp.writeFile(path.join(root, 'bar', 'notes.txt'), 'no c here');
    await fsp.mkdir(path.join(root, 'baz'), { recursive: true });
    await fsp.writeFile(path.join(root, 'baz', 'f@0x1.c'), 'void f(){}');

    expect(await countAnalyzed(root)).toBe(2);
  });

  test('counts program dirs nested at any depth (structured output tree)', async () => {
    // Output now mirrors the fs layout, so program dirs are nested under their
    // path (e.g. lib/modules/.../foo.ko/) rather than sitting at the top level.
    const a = path.join(root, 'lib', 'modules', '4.4', 'cdc-acm.ko');
    const b = path.join(root, 'usr', 'sbin', 'swarm.cgi');
    await fsp.mkdir(a, { recursive: true });
    await fsp.writeFile(path.join(a, 'probe@0x100.c'), 'int probe(){}');
    await fsp.mkdir(b, { recursive: true });
    await fsp.writeFile(path.join(b, 'main@0x1.c'), 'int main(){}');
    // Intermediate dirs (lib, usr, ...) hold no .c files and must not be counted.
    expect(await countAnalyzed(root)).toBe(2);
  });
});

describe('runGhidraAnalysis orchestration', () => {
  function baseDeps(overrides = {}) {
    const calls = { markCopying: 0, markAnalyzing: null, markSucceeded: null, markFailed: null };
    const db = {
      markCopying: jest.fn(async () => { calls.markCopying += 1; }),
      markAnalyzing: jest.fn(async (_id, arg) => { calls.markAnalyzing = arg; }),
      markSucceeded: jest.fn(async (_id, arg) => { calls.markSucceeded = arg; }),
      markFailed: jest.fn(async (_id, msg) => { calls.markFailed = msg; }),
      updateAnalyzedCount: jest.fn(async () => {}),
      latestFilesystemUploadPath: jest.fn(async () => '/data/agent/de:ad:be:ef:00:01/fs/bin/sh'),
      ...overrides.db,
    };
    const sendCommand = overrides.sendCommand || jest.fn(async () => ({ status: 200 }));
    const analyze = overrides.analyze || jest.fn(async () => ({ code: 0, timedOut: false, argv: [] }));
    const scan = overrides.scan || jest.fn(async () => ({ files: [{ relPath: 'bin/sh' }, { relPath: 'lib/x.so' }], skippedLarge: 0, errors: 0 }));
    // In-memory fs stub sufficient for the orchestration path.
    const fs = {
      mkdir: jest.fn(async () => {}),
      mkdtemp: jest.fn(async (p) => `${p}XXX`),
      rm: jest.fn(async () => {}),
      readdir: jest.fn(async () => []),
      ...overrides.fs,
    };
    return { db, sendCommand, analyze, scan, fs, calls };
  }

  test('drives copying -> analyzing -> succeeded and invokes a recursive analyzeHeadless', async () => {
    const d = baseDeps();
    const result = await runGhidraAnalysis(
      { jobId: 9, deviceId: 42, mac: 'de:ad:be:ef:00:01' },
      { db: d.db, sendCommand: d.sendCommand, analyze: d.analyze, scan: d.scan, fsp: d.fs, dataDir: '/data/agent' },
    );

    // remote-copy was pushed to the agent.
    expect(d.sendCommand).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'exec', mode: 'ela', mac: 'de:ad:be:ef:00:01', command: 'linux remote-copy --analysis-only --recursive /' }),
      expect.any(Object),
    );
    // Analysis was scoped to the resolved fs root, recursively, into a parallel ghidra/ root.
    expect(d.analyze).toHaveBeenCalledWith(expect.objectContaining({
      importTarget: '/data/agent/de:ad:be:ef:00:01/fs',
      recursive: true,
      outputBase: '/data/agent/de:ad:be:ef:00:01/ghidra',
    }));
    expect(d.calls.markCopying).toBe(1);
    expect(d.calls.markAnalyzing).toEqual(expect.objectContaining({
      fsRoot: '/data/agent/de:ad:be:ef:00:01/fs',
      outputRoot: '/data/agent/de:ad:be:ef:00:01/ghidra',
      filesFound: 2,
    }));
    expect(result.outputRoot).toBe('/data/agent/de:ad:be:ef:00:01/ghidra');
    expect(d.db.markSucceeded).toHaveBeenCalled();
  });

  test('fails when remote-copy produced no filesystem uploads', async () => {
    const d = baseDeps({ db: { latestFilesystemUploadPath: jest.fn(async () => null) } });
    await expect(runGhidraAnalysis(
      { jobId: 9, deviceId: 42, mac: 'de:ad:be:ef:00:01' },
      { db: d.db, sendCommand: d.sendCommand, analyze: d.analyze, scan: d.scan, fsp: d.fs, dataDir: '/data/agent' },
    )).rejects.toThrow(/no filesystem uploads/);
    expect(d.analyze).not.toHaveBeenCalled();
  });

  test('proceeds to analysis even when the remote-copy exec throws (uploads are the real signal)', async () => {
    const d = baseDeps({ sendCommand: jest.fn(async () => { throw new Error('exec timed out'); }) });
    const result = await runGhidraAnalysis(
      { jobId: 9, deviceId: 42, mac: 'de:ad:be:ef:00:01' },
      { db: d.db, sendCommand: d.sendCommand, analyze: d.analyze, scan: d.scan, fsp: d.fs, dataDir: '/data/agent' },
    );
    expect(d.analyze).toHaveBeenCalled();
    expect(result.outputRoot).toBe('/data/agent/de:ad:be:ef:00:01/ghidra');
  });

  test('throws when analyzeHeadless exits non-zero', async () => {
    const d = baseDeps({ analyze: jest.fn(async () => ({ code: 1, timedOut: false, argv: [] })) });
    await expect(runGhidraAnalysis(
      { jobId: 9, deviceId: 42, mac: 'de:ad:be:ef:00:01' },
      { db: d.db, sendCommand: d.sendCommand, analyze: d.analyze, scan: d.scan, fsp: d.fs, dataDir: '/data/agent' },
    )).rejects.toThrow(/analyzeHeadless exited 1/);
  });
});
