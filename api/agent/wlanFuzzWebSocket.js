'use strict';

/*
 * WLAN-fuzz remote crash capture.
 *
 * The agent's `linux wlan fuzz --target wext-generic` streams each payload here
 * JUST BEFORE it drives the host kernel's WEXT ioctls. Because a WEXT bug can
 * PANIC the host, the agent process can die without a chance to save the
 * offending case locally. So this endpoint holds only the LATEST payload in
 * memory; if the socket closes without the agent's graceful "done" frame (the
 * signature of a panic/kill), that last payload is written out as a replayable
 * crash file for triage.
 *
 * Frame protocol (one text/binary frame each), from the agent:
 *   "T <target>"      once, up front  — names the fuzz target
 *   "C <MSGNAME> <hex> #<note>"        — the current case (overwrites the prior)
 *   "D"               on a clean run  — graceful done; nothing is saved
 */

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

// Keep the saved artifact a valid `wlan fuzz --replay`/`--show` crash file.
function buildCrashFile(target, caseLine) {
  const t = /^[A-Za-z0-9_-]+$/.test(target) ? target : 'wext-generic';
  return `# target=${t} cases=1\n${caseLine}\n`;
}

function createWlanFuzzWebSocketServer({
  server,
  dataDir,
  persistUpload,
  verbose = false,
  pathSegment = 'wlan-fuzz',	// 'wlan-fuzz' for WLAN, 'eth-fuzz' for ethernet
  uploadType = 'wlan-fuzz',
}) {
  const pathRe = new RegExp(`^/${pathSegment}/[^/]+$`);
  const wss = new WebSocketServer({
    server,
    verifyClient(info, done) {
      const url = info.req.url || '';
      if (!pathRe.test(url)) {
        done(false, 404, 'Not Found');
        return;
      }
      auth.resolveBearer(info.req.headers.authorization)
        .then((ok) => (ok ? done(true) : done(false, 401, 'Unauthorized')))
        .catch(() => done(false, 401, 'Unauthorized'));
    },
  });

  wss.on('connection', (ws, req) => {
    const parts = (req.url || '').split('/').filter(Boolean);
    const macAddress = String(parts[1] || '').toLowerCase();
    const srcIp = getClientIp(req);
    const timestamp = new Date().toISOString();

    if (!isValidMacAddress(macAddress)) {
      ws.close(1008, 'invalid mac address');
      return;
    }

    let target = 'wext-generic';
    let lastCase = null; // the current (latest) case line, or null
    let graceful = false;
    let cases = 0;

    if (verbose) {
      process.stdout.write(`[${timestamp}] ${srcIp} WS /${pathSegment}/${macAddress} open\n`);
    }

    ws.on('message', (data) => {
      const msg = (Buffer.isBuffer(data) ? data : Buffer.from(data)).toString('utf8');
      const kind = msg.charCodeAt(0);
      if (kind === 0x54 /* 'T' */) {
        target = msg.slice(2).trim() || target;
      } else if (kind === 0x43 /* 'C' */) {
        lastCase = msg.slice(2);
        cases += 1;
      } else if (kind === 0x44 /* 'D' */) {
        graceful = true; // clean finish: the held payload is not a crash
        lastCase = null;
      }
    });

    ws.on('close', async () => {
      // Only an ungraceful drop while holding a payload means a crash: the
      // agent stopped streaming without saying "done" (host panicked/killed).
      if (graceful || !lastCase) {
        if (verbose) {
          process.stdout.write(`[${new Date().toISOString()}] WS /${pathSegment}/${macAddress} closed cleanly (${cases} case(s))\n`);
        }
        return;
      }

      const tsSafe = timestamp.replace(/[-:]/g, '').replace(/\..+/, 'Z');
      const safeIp = safeIpForPath(srcIp);
      const unique = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const targetDir = path.join(dataDir, macAddress, pathSegment);
      const localArtifactPath = path.join(
        targetDir, `crash_${tsSafe}_${safeIp}_${unique}.txt`,
      );
      const payload = Buffer.from(buildCrashFile(target, lastCase), 'utf8');

      try {
        fs.mkdirSync(targetDir, { recursive: true });
        fs.writeFileSync(localArtifactPath, payload, { flag: 'wx' });
        await persistUpload({
          macAddress,
          uploadType,
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
        process.stdout.write(`[${new Date().toISOString()}] WS /${pathSegment}/${macAddress} DROPPED mid-fuzz -> saved crash ${localArtifactPath}\n`);
      } catch (err) {
        process.stderr.write(`wlan-fuzz websocket: failed to persist ${localArtifactPath}: ${err.message}\n`);
      }
    });

    ws.on('error', () => {});
  });

  return wss;
}

module.exports = {
  createWlanFuzzWebSocketServer,
  buildCrashFile,
};
