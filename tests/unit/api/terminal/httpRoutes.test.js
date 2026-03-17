'use strict';

const { createTerminalHttpHandler } = require('../../../../api/terminal/httpRoutes');

function createMockResponse() {
  return {
    statusCode: null,
    headers: null,
    body: null,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
    },
  };
}

describe('terminal HTTP routes', () => {
  test('returns ok for the healthcheck route', () => {
    const handler = createTerminalHttpHandler();
    const res = createMockResponse();

    handler({ method: 'GET', url: '/terminal/healthcheck' }, res);

    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({ 'Content-Type': 'text/plain; charset=utf-8' });
    expect(res.body).toBe('ok');
  });

  test('returns 404 for unknown routes', () => {
    const handler = createTerminalHttpHandler();
    const res = createMockResponse();

    handler({ method: 'GET', url: '/terminal/unknown' }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('Not Found');
  });
});
