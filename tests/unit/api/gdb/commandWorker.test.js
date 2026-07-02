'use strict';

const { processGdbCommand, serializeSession, listSessions } = require('../../../../api/gdb/commandWorker');

// Minimal stand-ins for the live WebSocket handles held in a session.
const wsA = { label: 'in' };
const wsB = { label: 'out' };

function makeSessions(entries) {
  return new Map(entries);
}

describe('gdb commandWorker', () => {
  test('serializeSession exposes only the handle, mac, and operator state', () => {
    expect(serializeSession('abc', { in: wsA, out: wsB, deviceMac: 'aa-bb-cc-dd-ee-ff' })).toEqual({
      hexkey: 'abc',
      mac: 'aa-bb-cc-dd-ee-ff',
      operatorConnected: true,
    });
    expect(serializeSession('abc', { in: wsA, out: null, deviceMac: 'aa-bb-cc-dd-ee-ff' }).operatorConnected)
      .toBe(false);
  });

  test('listSessions returns active sessions and flags whether a gdb client is attached', () => {
    const sessions = makeSessions([
      // Active, no operator attached.
      ['key1', { in: wsA, out: null, deviceMac: '20-4c-03-32-75-5c' }],
      // Active, operator attached.
      ['key2', { in: wsA, out: wsB, deviceMac: '20-4c-03-32-75-5c' }],
      // Different device, active.
      ['key3', { in: wsA, out: null, deviceMac: 'aa-bb-cc-dd-ee-ff' }],
    ]);

    const { status, body } = listSessions(sessions);
    expect(status).toBe(200);
    expect(body.sessions).toEqual([
      { hexkey: 'key1', mac: '20-4c-03-32-75-5c', operatorConnected: false },
      { hexkey: 'key2', mac: '20-4c-03-32-75-5c', operatorConnected: true },
      { hexkey: 'key3', mac: 'aa-bb-cc-dd-ee-ff', operatorConnected: false },
    ]);
  });

  test('listSessions returns multiple concurrent sessions for one MAC', () => {
    const sessions = makeSessions([
      ['k1', { in: wsA, out: null, deviceMac: '20-4c-03-32-75-5c' }],
      ['k2', { in: wsA, out: wsB, deviceMac: '20-4c-03-32-75-5c' }],
    ]);
    const { body } = listSessions(sessions);
    expect(body.sessions.map((s) => s.hexkey)).toEqual(['k1', 'k2']);
    expect(body.sessions.every((s) => s.mac === '20-4c-03-32-75-5c')).toBe(true);
  });

  test('listSessions omits sessions with no connected agent or no declared MAC', () => {
    const sessions = makeSessions([
      // Agent gone (in null) — not active.
      ['k1', { in: null, out: wsB, deviceMac: '20-4c-03-32-75-5c' }],
      // No device MAC declared — cannot be attributed/ACL'd.
      ['k2', { in: wsA, out: null, deviceMac: null }],
    ]);
    expect(listSessions(sessions).body.sessions).toEqual([]);
  });

  test('processGdbCommand routes the sessions query', async () => {
    const sessions = makeSessions([['k1', { in: wsA, out: null, deviceMac: 'aa-bb-cc-dd-ee-ff' }]]);
    const result = await processGdbCommand({ job: { data: { type: 'sessions' } }, sessions });
    expect(result.status).toBe(200);
    expect(result.body.sessions).toHaveLength(1);
  });

  test('processGdbCommand rejects unknown command types', async () => {
    const result = await processGdbCommand({ job: { data: { type: 'nope' } }, sessions: makeSessions([]) });
    expect(result.status).toBe(400);
    expect(result.body.error).toMatch(/unknown command type/);
  });
});
