'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const auth = require('../auth');
const {
  isValidMacAddress,
  getClientIp,
} = require('./serverUtils');

function safeIpForPath(ip) {
  return String(ip || 'unknown').replace(/[^A-Za-z0-9_.-]/g, '_');
}

function createPcapWebSocketServer({
  server,
  dataDir,
  persistUpload,
  verbose = false,
}) {
  const wss = new WebSocketServer({
    server,
    verifyClient(info, done) {
      const url = info.req.url || '';
      if (!/^\/pcap\/[^/]+$/.test(url)) {
        done(false, 404, 'Not Found');
        return;
      }
      if (!auth.checkBearer(info.req.headers.authorization)) {
        done(false, 401, 'Unauthorized');
        return;
      }
      done(true);
    },
  });

  wss.on('connection', (ws, req) => {
    const parts = (req.url || '').split('/').filter(Boolean);
    const macAddress = String(parts[1] || '').toLowerCase();
    const srcIp = getClientIp(req);
    const timestamp = new Date().toISOString();
    const tsSafe = timestamp.replace(/[-:]/g, '').replace(/\..+/, 'Z');
    const safeIp = safeIpForPath(srcIp);
    const unique = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
    const targetDir = path.join(dataDir, macAddress, 'pcap');
    const localArtifactPath = path.join(targetDir, `capture_${tsSafe}_${safeIp}_${unique}.pcap`);
    let stream = null;
    let bytes = 0;
    let failed = false;

    if (!isValidMacAddress(macAddress)) {
      ws.close(1008, 'invalid mac address');
      return;
    }

    try {
      fs.mkdirSync(targetDir, { recursive: true });
      stream = fs.createWriteStream(localArtifactPath, { flags: 'wx' });
    } catch (err) {
      ws.close(1011, 'storage unavailable');
      process.stderr.write(`pcap websocket: failed to open ${localArtifactPath}: ${err.message}\n`);
      return;
    }

    if (verbose) {
      process.stdout.write(`[${timestamp}] ${srcIp} WS /pcap/${macAddress} -> ${localArtifactPath}\n`);
    }

    ws.on('message', (data) => {
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      bytes += chunk.length;
      if (!stream.write(chunk)) {
        ws.pause?.();
        stream.once('drain', () => ws.resume?.());
      }
    });

    ws.on('close', () => {
      if (!stream) {
        return;
      }
      stream.end(async () => {
        if (failed) {
          return;
        }
        try {
          const payload = Buffer.alloc(0);
          await persistUpload({
            macAddress,
            uploadType: 'pcap',
            contentType: 'application/octet-stream',
            srcIp,
            apiTimestamp: timestamp,
            requestFilePath: null,
            localArtifactPath,
            isSymlink: false,
            symlinkPath: null,
            payload,
            payloadToPersist: payload,
          });
          if (verbose) {
            process.stdout.write(`[${new Date().toISOString()}] WS /pcap/${macAddress} closed (${bytes} bytes)\n`);
          }
        } catch (err) {
          process.stderr.write(`pcap websocket: failed to persist ${localArtifactPath}: ${err.message}\n`);
        }
      });
    });

    stream.on('error', (err) => {
      failed = true;
      process.stderr.write(`pcap websocket: write failed for ${localArtifactPath}: ${err.message}\n`);
      try {
        ws.close(1011, 'storage unavailable');
      } catch {
        // ignore close races
      }
    });

    ws.on('error', () => {});
  });

  return wss;
}

module.exports = {
  createPcapWebSocketServer,
};
