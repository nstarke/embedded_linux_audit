'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { listGenericBinaries, assembleUserWrappers } = require('../../../../api/agent/provisionWrappers');
const { PAYLOAD_MARKER } = require('../../../../api/agent/selfExtract');

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
});
