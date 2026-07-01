'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const {
  PAYLOAD_MARKER,
  shSingleQuote,
  buildWrapperHeader,
  assembleWrapper,
} = require('../../../../api/agent/selfExtract');

describe('selfExtract', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ela-selfextract-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('shSingleQuote', () => {
    test('escapes embedded single quotes for a single-quoted sh literal', () => {
      expect(shSingleQuote("a'b")).toBe("a'\\''b");
      expect(shSingleQuote('plain')).toBe('plain');
      expect(shSingleQuote(null)).toBe('');
    });
  });

  describe('buildWrapperHeader', () => {
    test('requires token and cacheKey', () => {
      expect(() => buildWrapperHeader({ cacheKey: 'x' })).toThrow(/token/);
      expect(() => buildWrapperHeader({ token: 't' })).toThrow(/cacheKey/);
    });

    test('embeds the token and ends with the payload marker line', () => {
      const header = buildWrapperHeader({ token: 'abc', cacheKey: 'x86_64-deadbeef' });
      expect(header).toMatch(/ELA_TOKEN='abc'/);
      expect(header).toMatch(/export ELA_API_KEY="\$ELA_TOKEN"/);
      expect(header.endsWith(`${PAYLOAD_MARKER}\n`)).toBe(true);
    });

    test('carries the URL/insecure vars and a bare-run --remote guard', () => {
      const withUrl = buildWrapperHeader({ token: 't', serverUrl: 'wss://h', insecure: true, cacheKey: 'k' });
      expect(withUrl).toMatch(/ELA_REMOTE='wss:\/\/h'/);
      expect(withUrl).toMatch(/ELA_INSECURE='true'/);
      // Bare run adds --remote (and --insecure) rather than seeding a conf file.
      expect(withUrl).toMatch(/\[ "\$#" -eq 0 \] && \[ -n "\$ELA_REMOTE" \]/);
      expect(withUrl).toMatch(/set -- --insecure --remote "\$ELA_REMOTE"/);
      expect(withUrl).not.toMatch(/\.ela\.conf/);

      const noUrl = buildWrapperHeader({ token: 't', cacheKey: 'k' });
      expect(noUrl).toMatch(/ELA_REMOTE=''/);
      expect(noUrl).toMatch(/ELA_INSECURE='false'/);
    });

    test('quotes a token containing a single quote safely', () => {
      const header = buildWrapperHeader({ token: "ab'cd", cacheKey: 'k' });
      expect(header).toContain("ELA_TOKEN='ab'\\''cd'");
    });
  });

  describe('assembleWrapper', () => {
    test('rejects a non-Buffer payload', () => {
      expect(() => assembleWrapper('not a buffer', { token: 't' })).toThrow(/Buffer/);
    });

    test('extracts the binary payload byte-for-byte under /bin/sh', () => {
      // A payload that deliberately contains newlines, a NUL byte, and a line
      // that looks like the marker — to prove first-match-wins and raw copying.
      const payload = Buffer.concat([
        Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x0a]),
        Buffer.from(`\n${PAYLOAD_MARKER}\n`, 'utf8'),
        Buffer.from([0x00, 0x01, 0x02, 0xff, 0x0a]),
      ]);
      const wrapper = assembleWrapper(payload, { token: 'tok', isa: 'x86_64' });
      const wrapperPath = path.join(tmpDir, 'launcher');
      fs.writeFileSync(wrapperPath, wrapper);

      // Reproduce the launcher's own extraction (awk marker + tail -n +N).
      const extract = `line=$(awk '/^${PAYLOAD_MARKER}$/ { print NR + 1; exit }' "$1"); tail -n +"$line" "$1"`;
      const extracted = execFileSync('sh', ['-c', extract, 'sh', wrapperPath], {
        maxBuffer: 64 * 1024 * 1024,
      });

      expect(Buffer.compare(extracted, payload)).toBe(0);
    });

    test('running the launcher sets ELA_API_KEY, forwards args, and execs the payload', () => {
      // Use an executable sh-script payload so exec succeeds; assert the launcher
      // exported the token and passed arguments through verbatim.
      const payload = Buffer.from('#!/bin/sh\necho "KEY=$ELA_API_KEY"\necho "ARGS=$*"\n', 'utf8');
      // serverUrl omitted so the launcher never writes the host's /tmp/.ela.conf.
      const wrapper = assembleWrapper(payload, { token: 'secret-tok-123', isa: 'test' });
      const wrapperPath = path.join(tmpDir, 'ela-test');
      fs.writeFileSync(wrapperPath, wrapper);

      const out = execFileSync('sh', [wrapperPath, 'hello', 'wide world'], {
        // Keep the extracted binary inside the test dir, not the real /tmp.
        env: { ...process.env, TMPDIR: tmpDir },
        encoding: 'utf8',
      });

      expect(out).toContain('KEY=secret-tok-123');
      expect(out).toContain('ARGS=hello wide world');
    });

    test('a bare run injects --remote (and --insecure) from the baked URL', () => {
      // Payload echoes its argv so we can see exactly what the launcher execs.
      const payload = Buffer.from('#!/bin/sh\nfor a in "$@"; do echo "ARG=$a"; done\n', 'utf8');
      const wrapper = assembleWrapper(payload, {
        token: 't', serverUrl: 'wss://ela.example.com', insecure: true, isa: 'remote',
      });
      const wrapperPath = path.join(tmpDir, 'ela-remote');
      fs.writeFileSync(wrapperPath, wrapper);

      const out = execFileSync('sh', [wrapperPath], { env: { ...process.env, TMPDIR: tmpDir }, encoding: 'utf8' });
      expect(out.split('\n').filter(Boolean)).toEqual([
        'ARG=--insecure',
        'ARG=--remote',
        'ARG=wss://ela.example.com',
      ]);
    });

    test('a run with arguments passes them through unchanged (no --remote)', () => {
      const payload = Buffer.from('#!/bin/sh\nfor a in "$@"; do echo "ARG=$a"; done\n', 'utf8');
      const wrapper = assembleWrapper(payload, { token: 't', serverUrl: 'wss://h', isa: 'passthru' });
      const wrapperPath = path.join(tmpDir, 'ela-passthru');
      fs.writeFileSync(wrapperPath, wrapper);

      const out = execFileSync('sh', [wrapperPath, 'linux', 'dmesg'], { env: { ...process.env, TMPDIR: tmpDir }, encoding: 'utf8' });
      expect(out.split('\n').filter(Boolean)).toEqual(['ARG=linux', 'ARG=dmesg']);
    });

    test('a bare run with no baked URL does not inject --remote', () => {
      const payload = Buffer.from('#!/bin/sh\necho "COUNT=$#"\n', 'utf8');
      const wrapper = assembleWrapper(payload, { token: 't', serverUrl: '', isa: 'nourl' });
      const wrapperPath = path.join(tmpDir, 'ela-nourl');
      fs.writeFileSync(wrapperPath, wrapper);

      const out = execFileSync('sh', [wrapperPath], { env: { ...process.env, TMPDIR: tmpDir }, encoding: 'utf8' });
      expect(out.trim()).toBe('COUNT=0');
    });

    test('reuses the cached extracted binary on a second run', () => {
      const payload = Buffer.from('#!/bin/sh\necho ran\n', 'utf8');
      const wrapper = assembleWrapper(payload, { token: 't', isa: 'cache' });
      const wrapperPath = path.join(tmpDir, 'ela-cache');
      fs.writeFileSync(wrapperPath, wrapper);

      const run = () => execFileSync('sh', [wrapperPath], { env: { ...process.env, TMPDIR: tmpDir }, encoding: 'utf8' });
      expect(run().trim()).toBe('ran');

      const cached = fs.readdirSync(tmpDir).filter((n) => n.startsWith('.ela-agent-cache-'));
      expect(cached).toHaveLength(1);
      // Second run should not create a second cache file.
      expect(run().trim()).toBe('ran');
      expect(fs.readdirSync(tmpDir).filter((n) => n.startsWith('.ela-agent-cache-'))).toHaveLength(1);
    });
  });
});
