'use strict';

function createSessionRegistry({
  heartbeatIntervalMs,
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval,
} = {}) {
  const sessions = new Map();

  function addSession(mac, ws, { alias = null, connectionId = null } = {}) {
    const entry = {
      ws,
      mac,
      alias,
      connectionId,
      inputMode: 'line',
      lastHeartbeat: null,
      heartbeatTimer: null,
      outputBuffer: [],
    };

    if (heartbeatIntervalMs) {
      entry.heartbeatTimer = setIntervalImpl(() => {
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ _type: 'heartbeat' }));
        }
      }, heartbeatIntervalMs);
    }

    sessions.set(mac, entry);
    return entry;
  }

  function removeSession(mac) {
    const entry = sessions.get(mac);
    if (entry) {
      if (entry.heartbeatTimer) {
        clearIntervalImpl(entry.heartbeatTimer);
      }
      sessions.delete(mac);
    }
  }

  function getSession(mac) {
    return sessions.get(mac);
  }

  function listMacs() {
    return [...sessions.keys()];
  }

  function entries() {
    return [...sessions.entries()];
  }

  return {
    addSession,
    removeSession,
    getSession,
    listMacs,
    entries,
    get size() {
      return sessions.size;
    },
  };
}

module.exports = {
  createSessionRegistry,
};
