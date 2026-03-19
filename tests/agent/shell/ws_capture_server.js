#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      continue;
    }
    const key = arg.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      out[key] = '1';
      continue;
    }
    out[key] = value;
    i += 1;
  }
  return out;
}

function append(filePath, text) {
  fs.appendFileSync(filePath, text, 'utf8');
}

function requireWsModule(repoRoot) {
  const candidates = [
    process.env.WS_MODULE_DIR,
    path.join(repoRoot, 'api', 'terminal', 'node_modules', 'ws'),
    'ws',
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (_err) {
      continue;
    }
  }

  throw new Error('unable to load ws module');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const repoRoot = path.resolve(__dirname, '..', '..', '..');
  const eventsOut = args['events-out'];
  const messagesOut = args['messages-out'];
  const commandTextRaw = args['command-text'] || 'quit';
  const commandText = commandTextRaw.endsWith('\n') ? commandTextRaw : `${commandTextRaw}\n`;
  const expectText = args['expect-text'] || '';
  const autoQuit = args['auto-quit'] !== '0';

  if (!eventsOut || !messagesOut) {
    throw new Error('missing required --events-out or --messages-out');
  }

  fs.writeFileSync(eventsOut, '', 'utf8');
  fs.writeFileSync(messagesOut, '', 'utf8');

  const { WebSocketServer } = requireWsModule(repoRoot);
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  let closeScheduled = false;
  let shutdownTimer = null;

  function scheduleShutdown() {
    if (closeScheduled) {
      return;
    }
    closeScheduled = true;
    shutdownTimer = setTimeout(() => {
      wss.close(() => process.exit(0));
    }, 150);
  }

  wss.on('listening', () => {
    const address = wss.address();
    process.stdout.write(`ready:${address.port}\n`);
  });

  wss.on('connection', (ws, req) => {
    append(eventsOut, `connection:${req.url}\n`);

    const heartbeatTimer = setTimeout(() => {
      ws.send('{"_type":"heartbeat"}');
      append(eventsOut, 'heartbeat_sent\n');
    }, 40);

    const commandTimer = setTimeout(() => {
      ws.send(commandText);
      append(eventsOut, 'command_sent\n');
    }, 90);

    const quitTimer = setTimeout(() => {
      if (autoQuit) {
        ws.send('quit\n');
        append(eventsOut, 'quit_sent\n');
      }
    }, 180);

    ws.ping();
    append(eventsOut, 'ping_sent\n');

    ws.on('message', (data, isBinary) => {
      const text = isBinary ? Buffer.from(data).toString('hex') : data.toString();
      append(messagesOut, `${text}\n--frame--\n`);
      if (text.includes('"heartbeat_ack"')) {
        append(eventsOut, 'heartbeat_ack\n');
      }
      if (expectText && text.includes(expectText)) {
        append(eventsOut, 'expected_output_seen\n');
        if (autoQuit) {
          scheduleShutdown();
        }
      }
    });

    ws.on('pong', () => {
      append(eventsOut, 'pong\n');
    });

    ws.on('close', () => {
      clearTimeout(heartbeatTimer);
      clearTimeout(commandTimer);
      clearTimeout(quitTimer);
      append(eventsOut, 'close\n');
      scheduleShutdown();
    });

    ws.on('error', (err) => {
      append(eventsOut, `error:${err.message}\n`);
      scheduleShutdown();
    });
  });

  setTimeout(() => {
    append(eventsOut, 'timeout\n');
    wss.clients.forEach((ws) => {
      try {
        ws.close();
      } catch (_err) {
        // Ignore close races during forced shutdown.
      }
    });
    scheduleShutdown();
  }, 4000);
}

main();
