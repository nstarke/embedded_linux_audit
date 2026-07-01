'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const {
  listGenericBinaries,
  assembleUserWrappers,
  readLauncherMetadata,
  rebuildAllLaunchers,
} = require('../../../../api/agent/provisionWrappers');
const { PAYLOAD_MARKER, parseLauncherHeader } = require('../../../../api/agent/selfExtract');

describe('provisionWrappers', () => {
  let root;
  let genericDir;
  let userDir;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-provision-'));
    genericDir = path.join(root, 'generic');
    userDir = path.join(root, 'users', 'deadbeef');
    fs.mkdirSync(genericDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  test('listGenericBinaries returns ela-<isa> files sorted by isa, ignoring others', async () => {
    fs.writeFileSync(path.join(genericDir, 'ela-x86_64'), 'bin');
    fs.writeFileSync(path.join(genericDir, 'ela-aarch64-le'), 'bin');
    fs.writeFileSync(path.join(genericDir, '.release_state.json'), '{}');
    fs.writeFileSync(path.join(genericDir, 'notes.txt'), 'x');

    await expect(listGenericBinaries(genericDir)).resolves.toEqual([
      { isa: 'aarch64-le', fileName: 'ela-aarch64-le' },
      { isa: 'x86_64', fileName: 'ela-x86_64' },
    ]);
  });

  test('listGenericBinaries returns [] for a missing directory', async () => {
    await expect(listGenericBinaries(path.join(root, 'nope'))).resolves.toEqual([]);
  });

  test('assembleUserWrappers throws when there are no generic binaries', async () => {
    await expect(
      assembleUserWrappers({ genericDir, userDir, token: 't' }),
    ).rejects.toThrow(/no generic binaries/);
  });

  test('assembleUserWrappers requires a token', async () => {
    await expect(
      assembleUserWrappers({ genericDir, userDir, token: '' }),
    ).rejects.toThrow(/token is required/);
  });

  test('writes one executable launcher per ISA, each wrapping its own binary', async () => {
    const x86 = Buffer.from('#!/bin/sh\necho x86 KEY=$ELA_API_KEY\n');
    const arm = Buffer.from('#!/bin/sh\necho arm KEY=$ELA_API_KEY\n');
    fs.writeFileSync(path.join(genericDir, 'ela-x86_64'), x86);
    fs.writeFileSync(path.join(genericDir, 'ela-arm32-le'), arm);

    const { written } = await assembleUserWrappers({
      genericDir,
      userDir,
      token: 'tok-abc',
      serverUrl: '',
    });

    expect(written.map((w) => w.isa).sort()).toEqual(['arm32-le', 'x86_64']);

    for (const isa of ['x86_64', 'arm32-le']) {
      const p = path.join(userDir, `ela-${isa}`);
      // Executable bit set.
      expect(fs.statSync(p).mode & 0o111).not.toBe(0);
      const content = fs.readFileSync(p);
      // Header carries the token and ends the text section with the marker.
      expect(content.toString('utf8')).toContain("ELA_TOKEN='tok-abc'");
      expect(content.includes(`${PAYLOAD_MARKER}\n`)).toBe(true);
    }

    // The x86 launcher actually runs its own payload with the token set.
    const out = execFileSync('sh', [path.join(userDir, 'ela-x86_64')], {
      env: { ...process.env, TMPDIR: root },
      encoding: 'utf8',
    });
    expect(out.trim()).toBe('x86 KEY=tok-abc');
  });

  describe('rebuildAllLaunchers', () => {
    let usersDir;

    // Seed the generic binaries and one user's launchers built with the OLD
    // (empty) server URL, as if provisioned before ELA_SERVER_URL was set.
    async function seedUser(keyHash, token) {
      fs.writeFileSync(path.join(genericDir, 'ela-x86_64'), Buffer.from('#!/bin/sh\necho v1\n'));
      fs.writeFileSync(path.join(genericDir, 'ela-arm32-le'), Buffer.from('#!/bin/sh\necho v1\n'));
      await assembleUserWrappers({
        genericDir,
        userDir: path.join(usersDir, keyHash),
        token,
        serverUrl: '',
      });
    }

    beforeEach(() => {
      usersDir = path.join(root, 'users');
      fs.mkdirSync(usersDir, { recursive: true });
    });

    test('readLauncherMetadata recovers the token from an assembled launcher', async () => {
      await seedUser('hashA', 'token-A');
      const meta = await readLauncherMetadata(path.join(usersDir, 'hashA', 'ela-x86_64'));
      expect(meta).toEqual({ token: 'token-A', serverUrl: '', insecure: false });
    });

    test('rebuilds every user with the new URL while preserving their token', async () => {
      await seedUser('hashA', 'token-A');
      await seedUser('hashB', 'token-B');

      const { rebuilt, skipped } = await rebuildAllLaunchers({
        genericDir,
        usersDir,
        serverUrl: 'wss://new.example.com',
      });

      expect(skipped).toEqual([]);
      expect(rebuilt.map((r) => r.keyHash).sort()).toEqual(['hashA', 'hashB']);

      for (const [hash, token] of [['hashA', 'token-A'], ['hashB', 'token-B']]) {
        const header = fs.readFileSync(path.join(usersDir, hash, 'ela-x86_64'), 'utf8');
        const meta = parseLauncherHeader(header);
        expect(meta.token).toBe(token);              // token preserved
        expect(meta.serverUrl).toBe('wss://new.example.com'); // URL updated
      }
    });

    test('--keyhash limits the rebuild to one user', async () => {
      await seedUser('hashA', 'token-A');
      await seedUser('hashB', 'token-B');

      const { rebuilt } = await rebuildAllLaunchers({
        genericDir, usersDir, serverUrl: 'wss://h', onlyKeyHash: 'hashA',
      });
      expect(rebuilt.map((r) => r.keyHash)).toEqual(['hashA']);

      // hashB still has the old (empty) URL.
      const bHeader = fs.readFileSync(path.join(usersDir, 'hashB', 'ela-x86_64'), 'utf8');
      expect(parseLauncherHeader(bHeader).serverUrl).toBe('');
    });

    test('insecureOverride forces the flag; null keeps the existing value', async () => {
      await seedUser('hashA', 'token-A'); // seeded with insecure:false

      await rebuildAllLaunchers({ genericDir, usersDir, serverUrl: 'wss://h', insecureOverride: true });
      let header = fs.readFileSync(path.join(usersDir, 'hashA', 'ela-x86_64'), 'utf8');
      expect(parseLauncherHeader(header).insecure).toBe(true);

      // null override keeps the just-written true value.
      await rebuildAllLaunchers({ genericDir, usersDir, serverUrl: 'wss://h', insecureOverride: null });
      header = fs.readFileSync(path.join(usersDir, 'hashA', 'ela-x86_64'), 'utf8');
      expect(parseLauncherHeader(header).insecure).toBe(true);
    });

    test('skips a user directory with no launcher to read the token from', async () => {
      // Generic binaries exist, but this user's dir is empty.
      fs.writeFileSync(path.join(genericDir, 'ela-x86_64'), Buffer.from('bin'));
      fs.mkdirSync(path.join(usersDir, 'emptyhash'), { recursive: true });

      const { rebuilt, skipped } = await rebuildAllLaunchers({ genericDir, usersDir, serverUrl: 'wss://h' });
      expect(rebuilt).toEqual([]);
      expect(skipped).toEqual([{ keyHash: 'emptyhash', reason: 'no existing launcher to read the token from' }]);
    });

    test('throws when there are no generic binaries to rebuild from', async () => {
      await expect(
        rebuildAllLaunchers({ genericDir, usersDir, serverUrl: 'wss://h' }),
      ).rejects.toThrow(/no generic binaries/);
    });
  });
});
