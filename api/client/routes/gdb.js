'use strict';

// Reduce a MAC to its 12 lowercase hex digits for separator-insensitive
// comparison (`AA-BB-..`, `aa:bb:..`, and `aabb..` all compare equal), matching
// the terminal routes and the device DB layer.
function macKey(mac) {
  return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

const DEFAULT_WAIT_MS = 30000;

// Lazily resolve the DB/queue helpers so importing this module (e.g. in tests)
// does not pull in db/index or bullmq.
function deviceRegistry() {
  return require('../../lib/db/deviceRegistry');
}

function defaultSendGdbCommand(payload, opts) {
  return require('../../lib/queue').sendGdbCommand(payload, opts);
}

/**
 * Register the operator GDB routes on the client API. Every route is scoped to
 * the authenticated user AND ACL'd to devices that user is associated with
 * (`user_devices`): sessions on devices the caller is not associated with are
 * never revealed.
 *
 * Queries are not answered here — they are handed to the GDB bridge API over the
 * `ela-gdb-commands` queue and the result is awaited and relayed back.
 *
 * @param {object} app
 * @param {object} deps
 * @param {Function} [deps.sendCommand]  (payload, {waitMs}) => Promise<{status, body}>.
 * @param {Function} [deps.listUserDeviceMacs] (username) => Promise<string[]>.
 */
function registerGdbRoutes(app, deps = {}) {
  const {
    sendCommand = defaultSendGdbCommand,
    listUserDeviceMacs = (username) => deviceRegistry().listUserDeviceMacs(username),
  } = deps;

  // GET /gdb/sessions — active gdbserver sessions on the caller's associated
  // devices. A single device may have several concurrent gdbserver sessions;
  // each is listed separately with its attach handle (hexkey) and whether a gdb
  // client is currently attached (operatorConnected). Only the caller's
  // associated devices are shown (separator-insensitive MAC match); everything
  // else is filtered out with no enumeration.
  app.get('/gdb/sessions', async (req, res) => {
    let allowed;
    try {
      allowed = new Set((await listUserDeviceMacs(req.authUser)).map(macKey));
    } catch {
      res.status(500).json({ error: 'internal error' });
      return;
    }

    let result;
    try {
      result = await sendCommand({ type: 'sessions' }, { waitMs: DEFAULT_WAIT_MS });
    } catch {
      res.status(504).json({ error: 'gdb command timed out or gdb API unavailable' });
      return;
    }
    if (result.status !== 200) {
      res.status(result.status).json(result.body);
      return;
    }
    const sessions = (result.body.sessions || []).filter((s) => allowed.has(macKey(s.mac)));
    res.status(200).json({ sessions });
  });
}

module.exports = registerGdbRoutes;
