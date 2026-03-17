'use strict';

function createTerminalHttpHandler() {
  return function terminalHttpHandler(req, res) {
    const url = req.url || '';

    if (req.method === 'GET' && url === '/terminal/healthcheck') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('ok');
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  };
}

module.exports = {
  createTerminalHttpHandler,
};
