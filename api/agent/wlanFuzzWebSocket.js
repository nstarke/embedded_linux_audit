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
 *   "C <MSGNAME> <hex> #<note>"        — the current case (overwrites the prior;
 *                                        the host-panic dead-man's-switch)
 *   "X <crash-file text>"              — a confirmed crash the agent saved
 *                                        locally; persisted here immediately
 *   "D"               on a clean run  — graceful done; the held payload is not
 *                                        saved
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
    let lastCase = null; // latest streamed case (host-panic dead-man's-switch)
    let graceful = false;
    let cases = 0;
    let crashes = 0;

    const tsSafe = timestamp.replace(/[-:]/g, '').replace(/\..+/, 'Z');
    const safeIp = safeIpForPath(srcIp);
    const targetDir = path.join(dataDir, macAddress, pathSegment);

    // Persist one crash-file artifact (a full "# target=" crash file) to disk +
    // DB. `suffix` distinguishes a confirmed crash ('') from the last payload
    // captured on an ungraceful disconnect ('_panic').
    async function persistCrash(text, suffix, note) {
      const unique = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const localArtifactPath = path.join(
        targetDir, `crash_${tsSafe}_${safeIp}_${unique}${suffix}.txt`,
      );
      const payload = Buffer.from(text, 'utf8');
      try {
        fs.mkdirSync(targetDir, { recursive: true });
        fs.writeFileSync(localArtifactPath, payload, { flag: 'wx' });
        await persistUpload({
          macAddress,
          uploadType,
          contentType: 'application/octet-stream',
          srcIp,
          apiTimestamp: new Date().toISOString(),
          requestFilePath: null,
          localArtifactPath,
          isSymlink: false,
          symlinkPath: null,
          payload,
          payloadToPersist: payload,
        });
        process.stdout.write(`[${new Date().toISOString()}] WS /${pathSegment}/${macAddress} ${note} -> saved ${localArtifactPath}\n`);
      } catch (err) {
        process.stderr.write(`nic-fuzz websocket: failed to persist ${localArtifactPath}: ${err.message}\n`);
      }
    }

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
      } else if (kind === 0x58 /* 'X': a confirmed crash, saved immediately */) {
        const text = msg.slice(2);
        if (text) {
          crashes += 1;
          persistCrash(text, '', 'CONFIRMED crash');
        }
      } else if (kind === 0x44 /* 'D' */) {
        graceful = true; // clean finish: the held payload is not a crash
        lastCase = null;
      }
    });

    ws.on('close', async () => {
      // An ungraceful drop while still holding a payload means the agent died
      // (host panic/kill) mid-fuzz: save the last-streamed payload as a crash.
      if (graceful || !lastCase) {
        if (verbose) {
          process.stdout.write(`[${new Date().toISOString()}] WS /${pathSegment}/${macAddress} closed cleanly (${cases} case(s), ${crashes} crash(es))\n`);
        }
        return;
      }
      await persistCrash(buildCrashFile(target, lastCase), '_panic', 'DROPPED mid-fuzz');
    });

    ws.on('error', () => {});
  });

  return wss;
}

module.exports = {
  createWlanFuzzWebSocketServer,
  buildCrashFile,
};
