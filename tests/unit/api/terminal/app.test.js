'use strict';

const http = require('http');
const { createTerminalApp } = require('../../../../api/terminal/app');

// Spin the app up on an ephemeral port and issue a single request.
function request(app, { method = 'GET', path = '/', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { raw += c; });
        res.on('end', () => server.close(() => resolve({ statusCode: res.statusCode, raw })));
      });
      req.on('error', (err) => server.close(() => reject(err)));
      req.end();
    });
  });
}

// The terminal API is agent-only now: its HTTP surface is just a healthcheck.
// Operator control moved to the client API (which reaches agents over the
// command queue), so there are no sessions/exec/spawn routes here.
describe('terminal Express app (agent-only)', () => {
  test('healthcheck returns ok without auth', async () => {
    const res = await request(createTerminalApp(), { path: '/terminal/healthcheck' });
    expect(res.statusCode).toBe(200);
    expect(res.raw).toBe('ok');
  });

  test('healthcheck answers even for blocked remotes', async () => {
    const app = createTerminalApp({ isBlocked: () => true });
    const res = await request(app, { path: '/terminal/healthcheck' });
    expect(res.statusCode).toBe(200);
    expect(res.raw).toBe('ok');
  });

  test('blocked remotes are rejected with 403 on non-healthcheck paths', async () => {
    const app = createTerminalApp({ isBlocked: () => true });
    const res = await request(app, { path: '/terminal/anything' });
    expect(res.statusCode).toBe(403);
    expect(res.raw).toBe('Forbidden');
  });

  test('the removed operator routes now 404', async () => {
    const app = createTerminalApp();
    for (const path of ['/terminal/sessions', '/terminal/aa:bb:cc:dd:ee:ff/exec', '/terminal/aa:bb:cc:dd:ee:ff/spawn']) {
      const res = await request(app, { path });
      expect(res.statusCode).toBe(404);
      expect(res.raw).toBe('Not Found');
    }
  });

  test('unknown routes return 404 Not Found', async () => {
    const res = await request(createTerminalApp(), { path: '/nope' });
    expect(res.statusCode).toBe(404);
    expect(res.raw).toBe('Not Found');
  });
});
