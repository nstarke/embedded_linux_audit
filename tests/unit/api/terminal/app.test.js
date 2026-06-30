'use strict';

const http = require('http');
const { createTerminalApp } = require('../../../../api/terminal/app');

// Spin the Express app up on an ephemeral port and issue a single request,
// returning the parsed response.  This exercises the real middleware stack
// (routing, body parsing, error handling) without pulling in a test client.
function request(app, { method = 'GET', path = '/', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const payload = body === null
        ? null
        : (typeof body === 'string' ? body : JSON.stringify(body));
      const reqHeaders = { ...headers };
      if (payload !== null && reqHeaders['content-type'] === undefined) {
        reqHeaders['content-type'] = 'application/json';
      }
      const req = http.request({ host: '127.0.0.1', port, method, path, headers: reqHeaders }, (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => {
          server.close(() => {
            let parsed = raw;
            const type = res.headers['content-type'] || '';
            if (type.includes('application/json') && raw) {
              try {
                parsed = JSON.parse(raw);
              } catch {
                parsed = raw;
              }
            }
            resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed, raw });
          });
        });
      });
      req.on('error', (err) => server.close(() => reject(err)));
      if (payload !== null) {
        req.write(payload);
      }
      req.end();
    });
  });
}

function createRegistry(entries) {
  const map = new Map(entries);
  return {
    entries: () => [...map.entries()],
    getSession: (mac) => map.get(mac),
  };
}

const unauthorized = (req, res) => res.status(401).json({ error: 'Unauthorized' });

describe('terminal Express app', () => {
  test('returns ok for the healthcheck route without auth', async () => {
    const app = createTerminalApp({ sessionRegistry: createRegistry([]) });

    const res = await request(app, { path: '/terminal/healthcheck' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.raw).toBe('ok');
  });

  test('serves the healthcheck even for blocked remotes', async () => {
    const app = createTerminalApp({ sessionRegistry: createRegistry([]), isBlocked: () => true });

    const res = await request(app, { path: '/terminal/healthcheck' });

    expect(res.statusCode).toBe(200);
    expect(res.raw).toBe('ok');
  });

  test('returns 404 for unknown routes', async () => {
    const app = createTerminalApp({ sessionRegistry: createRegistry([]) });

    const res = await request(app, { path: '/terminal/unknown' });

    expect(res.statusCode).toBe(404);
    expect(res.raw).toBe('Not Found');
  });

  test('rejects blocked remotes with 403', async () => {
    const app = createTerminalApp({ sessionRegistry: createRegistry([]), isBlocked: () => true });

    const res = await request(app, { path: '/terminal/sessions' });

    expect(res.statusCode).toBe(403);
    expect(res.raw).toBe('Forbidden');
  });

  describe('GET /terminal/sessions', () => {
    test('returns the active sessions as JSON', async () => {
      const sessionRegistry = createRegistry([
        ['aa:bb:cc:dd:ee:ff', {
          alias: 'router',
          group: 'home',
          remoteAddress: '10.0.0.5',
          connectedAt: '2026-06-29T00:00:00.000Z',
          lastHeartbeat: '2026-06-29T00:01:00.000Z',
        }],
      ]);
      const app = createTerminalApp({ sessionRegistry });

      const res = await request(app, { path: '/terminal/sessions' });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.body).toEqual([
        {
          mac: 'aa:bb:cc:dd:ee:ff',
          alias: 'router',
          group: 'home',
          remoteAddress: '10.0.0.5',
          connectedAt: '2026-06-29T00:00:00.000Z',
          lastHeartbeat: '2026-06-29T00:01:00.000Z',
        },
      ]);
    });

    test('rejects unauthorized requests', async () => {
      const app = createTerminalApp({ sessionRegistry: createRegistry([]), authMiddleware: unauthorized });

      const res = await request(app, { path: '/terminal/sessions' });

      expect(res.statusCode).toBe(401);
      expect(res.body).toEqual({ error: 'Unauthorized' });
    });
  });

  describe('POST /terminal/:mac/exec', () => {
    const mac = 'aa:bb:cc:dd:ee:ff';

    test('runs the command and returns its output', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'hello\n', durationMs: 42 });
      const app = createTerminalApp({ sessionRegistry, runExecImpl });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'echo hello' } });

      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'echo hello', timeoutMs: undefined });
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ ok: true, output: 'hello\n', durationMs: 42 });
    });

    test('passes through a custom timeoutMs', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: '', durationMs: 1 });
      const app = createTerminalApp({ sessionRegistry, runExecImpl });

      await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'sleep 1', timeoutMs: 5000 } });

      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'sleep 1', timeoutMs: 5000 });
    });

    test('uppercase MAC in the URL is normalized to lower case', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: '', durationMs: 1 });
      const app = createTerminalApp({ sessionRegistry, runExecImpl });

      const res = await request(app, { method: 'POST', path: '/terminal/AA:BB:CC:DD:EE:FF/exec', body: { command: 'ls' } });

      expect(res.statusCode).toBe(200);
      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'ls', timeoutMs: undefined });
    });

    test('returns 404 when there is no session for the mac', async () => {
      const app = createTerminalApp({ sessionRegistry: createRegistry([]), runExecImpl: jest.fn() });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'ls' } });

      expect(res.statusCode).toBe(404);
      expect(res.body).toEqual({ error: 'no active session for mac' });
    });

    test('returns 504 when the exec times out', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockRejectedValue(
        Object.assign(new Error('exec timed out'), { code: 'TIMEOUT', output: 'partial', durationMs: 9000 }),
      );
      const app = createTerminalApp({ sessionRegistry, runExecImpl });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'sleep 99' } });

      expect(res.statusCode).toBe(504);
      expect(res.body).toEqual({
        ok: false,
        error: 'exec timed out',
        output: 'partial',
        durationMs: 9000,
      });
    });

    test('returns 500 when the exec fails for another reason', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockRejectedValue(new Error('boom'));
      const app = createTerminalApp({ sessionRegistry, runExecImpl });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'ls' } });

      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual({ error: 'exec failed' });
    });

    test('rejects a missing command with 400', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const app = createTerminalApp({ sessionRegistry, runExecImpl: jest.fn() });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: {} });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'command is required' });
    });

    test('rejects a non-positive timeoutMs with 400', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const app = createTerminalApp({ sessionRegistry, runExecImpl: jest.fn() });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'ls', timeoutMs: 0 } });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'timeoutMs must be a positive number' });
    });

    test('rejects an invalid mac with 400', async () => {
      const app = createTerminalApp({ sessionRegistry: createRegistry([]), runExecImpl: jest.fn() });

      const res = await request(app, { method: 'POST', path: '/terminal/not-a-mac/exec', body: { command: 'ls' } });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'invalid mac address' });
    });

    test('rejects an oversized body with 413', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const app = createTerminalApp({ sessionRegistry, runExecImpl: jest.fn() });
      const huge = 'x'.repeat(1024 * 1024 + 10);

      const res = await request(app, {
        method: 'POST',
        path: `/terminal/${mac}/exec`,
        body: JSON.stringify({ command: huge }),
      });

      expect(res.statusCode).toBe(413);
      expect(res.body).toEqual({ error: 'payload too large' });
    });

    test('rejects an invalid JSON body with 400', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const app = createTerminalApp({ sessionRegistry, runExecImpl: jest.fn() });

      const res = await request(app, {
        method: 'POST',
        path: `/terminal/${mac}/exec`,
        body: '{not valid json',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'invalid JSON body' });
    });

    test('rejects unauthorized exec requests', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const app = createTerminalApp({ sessionRegistry, authMiddleware: unauthorized, runExecImpl: jest.fn() });

      const res = await request(app, { method: 'POST', path: `/terminal/${mac}/exec`, body: { command: 'ls' } });

      expect(res.statusCode).toBe(401);
      expect(res.body).toEqual({ error: 'Unauthorized' });
    });
  });

  describe('spawn routes', () => {
    const mac = 'aa:bb:cc:dd:ee:ff';
    const now = () => '2026-06-29T12:00:00.000Z';

    describe('POST /terminal/:mac/spawn', () => {
      test('spawns a process and returns the pid and port', async () => {
        const entry = { ws: {} };
        const sessionRegistry = createRegistry([[mac, entry]]);
        const runSpawnImpl = jest.fn().mockResolvedValue({ pid: 4242, port: 5555 });
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl, now });

        const res = await request(app, {
          method: 'POST',
          path: `/terminal/${mac}/spawn`,
          body: { command: 'gdbserver', args: [':5555', 'a.out'], port: 5555 },
        });

        expect(runSpawnImpl).toHaveBeenCalledWith({
          entry, mac, command: 'gdbserver', args: [':5555', 'a.out'], port: 5555,
        });
        expect(res.statusCode).toBe(201);
        expect(res.body).toEqual({ pid: 4242, port: 5555 });
        // The spawn is now tracked on the entry.
        expect([...entry.spawns.values()]).toEqual([
          { pid: 4242, command: 'gdbserver', args: [':5555', 'a.out'], port: 5555, startedAt: now() },
        ]);
      });

      test('omits the port when none is reported', async () => {
        const entry = { ws: {} };
        const sessionRegistry = createRegistry([[mac, entry]]);
        const runSpawnImpl = jest.fn().mockResolvedValue({ pid: 99, port: undefined });
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl, now });

        const res = await request(app, {
          method: 'POST',
          path: `/terminal/${mac}/spawn`,
          body: { command: 'sleep', args: ['100'] },
        });

        expect(res.statusCode).toBe(201);
        expect(res.body).toEqual({ pid: 99 });
      });

      test('defaults args to an empty array', async () => {
        const entry = { ws: {} };
        const sessionRegistry = createRegistry([[mac, entry]]);
        const runSpawnImpl = jest.fn().mockResolvedValue({ pid: 1 });
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl, now });

        await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: { command: 'top' } });

        expect(runSpawnImpl).toHaveBeenCalledWith({ entry, mac, command: 'top', args: [], port: undefined });
      });

      test('rejects a missing command with 400', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl: jest.fn() });

        const res = await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: {} });

        expect(res.statusCode).toBe(400);
        expect(res.body).toEqual({ error: 'command is required' });
      });

      test('rejects non-string args with 400', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl: jest.fn() });

        const res = await request(app, {
          method: 'POST',
          path: `/terminal/${mac}/spawn`,
          body: { command: 'x', args: [1, 2] },
        });

        expect(res.statusCode).toBe(400);
        expect(res.body).toEqual({ error: 'args must be an array of strings' });
      });

      test('rejects an out-of-range port with 400', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl: jest.fn() });

        const res = await request(app, {
          method: 'POST',
          path: `/terminal/${mac}/spawn`,
          body: { command: 'x', port: 70000 },
        });

        expect(res.statusCode).toBe(400);
        expect(res.body).toEqual({ error: 'port must be an integer between 1 and 65535' });
      });

      test('returns 404 when there is no session', async () => {
        const app = createTerminalApp({ sessionRegistry: createRegistry([]), runSpawnImpl: jest.fn() });

        const res = await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: { command: 'x' } });

        expect(res.statusCode).toBe(404);
        expect(res.body).toEqual({ error: 'no active session for mac' });
      });

      test('returns 504 when the spawn times out', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const runSpawnImpl = jest.fn().mockRejectedValue(Object.assign(new Error('t'), { code: 'TIMEOUT' }));
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl });

        const res = await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: { command: 'x' } });

        expect(res.statusCode).toBe(504);
        expect(res.body).toEqual({ error: 'spawn timed out' });
      });

      test('returns 500 on an unexpected failure', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const runSpawnImpl = jest.fn().mockRejectedValue(new Error('boom'));
        const app = createTerminalApp({ sessionRegistry, runSpawnImpl });

        const res = await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: { command: 'x' } });

        expect(res.statusCode).toBe(500);
        expect(res.body).toEqual({ error: 'spawn failed' });
      });

      test('rejects unauthorized requests', async () => {
        const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
        const app = createTerminalApp({ sessionRegistry, authMiddleware: unauthorized, runSpawnImpl: jest.fn() });

        const res = await request(app, { method: 'POST', path: `/terminal/${mac}/spawn`, body: { command: 'x' } });

        expect(res.statusCode).toBe(401);
      });
    });

    describe('GET /terminal/:mac/spawn', () => {
      test('lists the tracked spawns', async () => {
        const entry = {
          ws: {},
          spawns: new Map([
            [7, { pid: 7, command: 'gdbserver', args: [':0'], port: 1234, startedAt: now() }],
            [8, { pid: 8, command: 'sleep', args: ['1'], port: undefined, startedAt: now() }],
          ]),
        };
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, entry]]) });

        const res = await request(app, { path: `/terminal/${mac}/spawn` });

        expect(res.statusCode).toBe(200);
        expect(res.body).toEqual([
          { pid: 7, command: 'gdbserver', args: [':0'], port: 1234, startedAt: now() },
          { pid: 8, command: 'sleep', args: ['1'], startedAt: now() },
        ]);
      });

      test('returns an empty array when nothing is tracked', async () => {
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, { ws: {} }]]) });

        const res = await request(app, { path: `/terminal/${mac}/spawn` });

        expect(res.statusCode).toBe(200);
        expect(res.body).toEqual([]);
      });

      test('returns 404 when there is no session', async () => {
        const app = createTerminalApp({ sessionRegistry: createRegistry([]) });

        const res = await request(app, { path: `/terminal/${mac}/spawn` });

        expect(res.statusCode).toBe(404);
        expect(res.body).toEqual({ error: 'no active session for mac' });
      });
    });

    describe('DELETE /terminal/:mac/spawn/:pid', () => {
      test('kills a tracked spawn and drops it from the registry', async () => {
        const entry = {
          ws: {},
          spawns: new Map([[7, { pid: 7, command: 'gdbserver', args: [], startedAt: now() }]]),
        };
        const runExecImpl = jest.fn().mockResolvedValue({ output: '', durationMs: 1 });
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, entry]]), runExecImpl });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/7` });

        expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'kill 7' });
        expect(res.statusCode).toBe(200);
        expect(res.body).toEqual({ ok: true });
        expect(entry.spawns.has(7)).toBe(false);
      });

      test('rejects an invalid pid with 400', async () => {
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, { ws: {} }]]), runExecImpl: jest.fn() });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/0` });

        expect(res.statusCode).toBe(400);
        expect(res.body).toEqual({ error: 'invalid pid' });
      });

      test('returns 404 for an untracked pid', async () => {
        const entry = { ws: {}, spawns: new Map() };
        const runExecImpl = jest.fn();
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, entry]]), runExecImpl });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/123` });

        expect(res.statusCode).toBe(404);
        expect(res.body).toEqual({ error: 'no such spawn' });
        expect(runExecImpl).not.toHaveBeenCalled();
      });

      test('returns 404 when there is no session', async () => {
        const app = createTerminalApp({ sessionRegistry: createRegistry([]), runExecImpl: jest.fn() });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/7` });

        expect(res.statusCode).toBe(404);
        expect(res.body).toEqual({ error: 'no active session for mac' });
      });

      test('returns 500 when the kill fails and keeps the spawn tracked', async () => {
        const entry = { ws: {}, spawns: new Map([[7, { pid: 7, command: 'x', args: [], startedAt: now() }]]) };
        const runExecImpl = jest.fn().mockRejectedValue(new Error('boom'));
        const app = createTerminalApp({ sessionRegistry: createRegistry([[mac, entry]]), runExecImpl });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/7` });

        expect(res.statusCode).toBe(500);
        expect(res.body).toEqual({ error: 'kill failed' });
        expect(entry.spawns.has(7)).toBe(true);
      });

      test('rejects unauthorized requests', async () => {
        const entry = { ws: {}, spawns: new Map([[7, { pid: 7 }]]) };
        const app = createTerminalApp({
          sessionRegistry: createRegistry([[mac, entry]]),
          authMiddleware: unauthorized,
          runExecImpl: jest.fn(),
        });

        const res = await request(app, { method: 'DELETE', path: `/terminal/${mac}/spawn/7` });

        expect(res.statusCode).toBe(401);
      });
    });
  });
});
