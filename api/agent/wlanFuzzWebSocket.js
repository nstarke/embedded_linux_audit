'use strict';

/*
 * WLAN-fuzz remote crash capture.
 *
 * The agent's `linux wlan fuzz --target wext-generic` streams each payload here
 * JUST BEFORE it drives the host kernel's WEXT ioctls. Because a WEXT bug can
 * PANIC the host, the agent process can die without a chance to save the
 * offending case locally. So this endpoint holds the last N payloads in an
 * in-memory ring (N is the DB-backed `fuzz_ring_size` setting, default 10); if
 * the socket closes without the agent's graceful "done" frame (the signature of
 * a panic/kill), the whole ring is written out as a replayable crash file for
 * triage. Keeping several cases matters because the case that panicked is often
 * not the last one streamed -- a bug can fire a few cases after the payload
 * that corrupted state, and the ring preserves that run-up.
 *
 * Frame protocol (one text/binary frame each), from the agent:
 *   "T <target>"      once, up front  — names the fuzz target
 *   "C <MSGNAME> <hex> #<note>"        — the current case (appended to the ring,
 *                                        evicting the oldest; the host-panic
 *                                        dead-man's-switch)
 *   "X <crash-file text>"              — a confirmed crash the agent saved
 *                                        locally; persisted here immediately
 *   "D"               on a clean run  — graceful done; the held payload is not
 *                                        saved
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const {
  isValidMacAddress,
  getClientIp,
} = require('./serverUtils');
const { DEFAULT_RING_SIZE, normalizeRingSize } = require('../lib/fuzzRing');

function safeIpForPath(ip) {
  return String(ip || 'unknown').replace(/[^A-Za-z0-9_.-]/g, '_');
}

// Keep the saved artifact a valid `wlan fuzz --replay`/`--show` crash file.
// `caseLines` may be a single line or the ring's worth of them, oldest first --
// so the LAST line is the case in flight when the host died, and the ones above
// it are the run-up that got it there. Replay walks them in that same order.
function buildCrashFile(target, caseLines) {
  const t = /^[A-Za-z0-9_-]+$/.test(target) ? target : 'wext-generic';
  const lines = Array.isArray(caseLines) ? caseLines : [caseLines];
  return `# target=${t} cases=${lines.length}\n${lines.map((l) => `${l}\n`).join('')}`;
}

function createWlanFuzzWebSocketServer({
  dataDir,
  persistUpload,
  verbose = false,
  pathSegment = 'wlan-fuzz',	// 'wlan-fuzz' for WLAN, 'eth-fuzz' for ethernet
  uploadType = 'wlan-fuzz',
  // Resolved once per connection so a client-API change to the setting takes
  // effect on the next fuzz run without restarting the agent API.
  resolveRingSize = null,
}) {
  // noServer mode: the caller's single upgrade dispatcher matches pathRe and
  // authenticates, then hands us the socket. Attaching with { server } here
  // instead would make this and every sibling WS server race on each upgrade --
  // a non-matching sibling's synchronous 404 would beat this one's async auth.
  const pathRe = new RegExp(`^/${pathSegment}/[^/]+$`);
  const wss = new WebSocketServer({ noServer: true });

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
    // The last `ringSize` streamed cases, oldest first (host-panic dead-man's
    // switch). Sized from the DB-backed setting, which resolves asynchronously
    // while frames may already be arriving -- so the ring is trimmed both on
    // push and once the real size lands.
    const ring = [];
    let ringSize = DEFAULT_RING_SIZE;
    let graceful = false;
    let cases = 0;
    let crashes = 0;

    function trimRing() {
      if (ring.length > ringSize) ring.splice(0, ring.length - ringSize);
    }

    const ringSizeReady = Promise.resolve()
      .then(() => (resolveRingSize ? resolveRingSize() : DEFAULT_RING_SIZE))
      .then((n) => { ringSize = normalizeRingSize(n); trimRing(); })
      .catch((err) => {
        // A settings-store hiccup must not cost us the crash capture itself.
        process.stderr.write(`nic-fuzz websocket: ring size lookup failed, using ${DEFAULT_RING_SIZE}: ${err.message}\n`);
      });

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
        ring.push(msg.slice(2));
        trimRing();
        cases += 1;
      } else if (kind === 0x58 /* 'X': a confirmed crash, saved immediately */) {
        const text = msg.slice(2);
        if (text) {
          crashes += 1;
          persistCrash(text, '', 'CONFIRMED crash');
        }
      } else if (kind === 0x44 /* 'D' */) {
        graceful = true; // clean finish: the held payloads are not a crash
        ring.length = 0;
      }
    });

    ws.on('close', async () => {
      // An ungraceful drop while still holding payloads means the agent died
      // (host panic/kill) mid-fuzz: save the held ring as a crash.
      await ringSizeReady; // may still be in flight on a very short run
      if (graceful || ring.length === 0) {
        if (verbose) {
          process.stdout.write(`[${new Date().toISOString()}] WS /${pathSegment}/${macAddress} closed cleanly (${cases} case(s), ${crashes} crash(es))\n`);
        }
        return;
      }
      await persistCrash(
        buildCrashFile(target, ring), '_panic',
        `DROPPED mid-fuzz (last ${ring.length} of ${cases} case(s))`,
      );
    });

    ws.on('error', () => {});
  });

  return { wss, pathRe };
}

module.exports = {
  createWlanFuzzWebSocketServer,
  buildCrashFile,
};
