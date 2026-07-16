'use strict';

const { runConfigGet, deliverConfigValue } = require('../../../../api/terminal/configCommand');

function openWs() {
  const sent = [];
  return {
    OPEN: 1,
    readyState: 1,
    sent,
    send: (data) => sent.push(data),
  };
}

function entryWith(ws) {
  return { ws, mac: 'aa:bb:cc:dd:ee:ff' };
}

// Answer the request the entry most recently sent, as the agent would.
function replyTo(entry, values, { id } = {}) {
  const req = JSON.parse(entry.ws.sent[entry.ws.sent.length - 1]);
  deliverConfigValue(entry, { _type: 'config.value', id: id || req.id, values });
  return req;
}

describe('runConfigGet', () => {
  test('sends a config.get frame and resolves with the values', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_URL'] });

    const req = replyTo(entry, { ELA_API_URL: 'http://a.example/upload' });
    expect(req._type).toBe('config.get');
    expect(req.keys).toEqual(['ELA_API_URL']);
    expect(typeof req.id).toBe('string');

    await expect(promise).resolves.toEqual({ ELA_API_URL: 'http://a.example/upload' });
  });

  test('an unset value resolves as an empty string, not a failure', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_URL'] });
    replyTo(entry, { ELA_API_URL: '' });
    // "the device answered and has nothing set" must be distinguishable from
    // "the device never answered" — this is the resolve side of that.
    await expect(promise).resolves.toEqual({ ELA_API_URL: '' });
  });

  test('rejects with TIMEOUT when the device does not answer', async () => {
    const entry = entryWith(openWs());
    const timers = [];
    const promise = runConfigGet({
      entry,
      keys: ['ELA_API_URL'],
      timeoutMs: 50,
      setTimeoutImpl: (fn) => { timers.push(fn); return 1; },
      clearTimeoutImpl: () => {},
    });

    timers[0]();
    await expect(promise).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  test('rejects with NOT_CONNECTED when the socket is not open', async () => {
    const entry = entryWith({ OPEN: 1, readyState: 3, send: () => {} });
    await expect(runConfigGet({ entry, keys: ['ELA_API_URL'] }))
      .rejects.toMatchObject({ code: 'NOT_CONNECTED' });
  });

  test('rejects with SEND_FAILED when the socket write throws', async () => {
    const entry = entryWith({
      OPEN: 1,
      readyState: 1,
      send: () => { throw new Error('broken pipe'); },
    });
    await expect(runConfigGet({ entry, keys: ['ELA_API_URL'] }))
      .rejects.toMatchObject({ code: 'SEND_FAILED' });
  });

  test('never asks the device for ELA_API_KEY', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_KEY', 'ELA_API_URL', 'MADE_UP'] });

    const req = replyTo(entry, { ELA_API_URL: 'http://a.example/upload' });
    // The agent refuses it too, but the credential should not even be named on
    // the wire: /tmp/.ela.conf is inside the tree remote-copy uploads.
    expect(req.keys).toEqual(['ELA_API_URL']);

    await promise;
  });

  test('a late or unknown reply is ignored rather than crossing requests', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_URL'] });

    expect(deliverConfigValue(entry, { _type: 'config.value', id: 'not-mine', values: { ELA_API_URL: 'x' } }))
      .toBe(false);

    replyTo(entry, { ELA_API_URL: 'http://right.example/upload' });
    await expect(promise).resolves.toEqual({ ELA_API_URL: 'http://right.example/upload' });

    // The waiter is gone; a duplicate reply must not throw.
    expect(deliverConfigValue(entry, { _type: 'config.value', id: 'stale', values: {} })).toBe(false);
  });

  test('concurrent reads on one session resolve independently', async () => {
    const entry = entryWith(openWs());
    const first = runConfigGet({ entry, keys: ['ELA_API_URL'] });
    const second = runConfigGet({ entry, keys: ['ELA_OUTPUT_FORMAT'] });

    const [reqA, reqB] = entry.ws.sent.map((s) => JSON.parse(s));
    expect(reqA.id).not.toBe(reqB.id);

    // Answer out of order: correlation is by id, not arrival order.
    deliverConfigValue(entry, { _type: 'config.value', id: reqB.id, values: { ELA_OUTPUT_FORMAT: 'json' } });
    deliverConfigValue(entry, { _type: 'config.value', id: reqA.id, values: { ELA_API_URL: 'http://a.example' } });

    await expect(first).resolves.toEqual({ ELA_API_URL: 'http://a.example' });
    await expect(second).resolves.toEqual({ ELA_OUTPUT_FORMAT: 'json' });
  });

  test('waiters are cleaned up so a session does not leak state', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_URL'] });
    expect(entry.configWaiters.size).toBe(1);
    replyTo(entry, { ELA_API_URL: '' });
    await promise;
    expect(entry.configWaiters.size).toBe(0);
  });
});

describe('deliverConfigValue', () => {
  test('is a no-op for a session that has never read config', () => {
    expect(deliverConfigValue({ mac: 'a' }, { _type: 'config.value', id: 'x', values: {} })).toBe(false);
  });

  test('tolerates a malformed frame', () => {
    const entry = entryWith(openWs());
    entry.configWaiters = new Map([['x', { resolve: () => {} }]]);
    expect(deliverConfigValue(entry, null)).toBe(false);
    expect(deliverConfigValue(entry, { _type: 'config.value' })).toBe(false);
  });

  test('a reply with no values object resolves as empty', async () => {
    const entry = entryWith(openWs());
    const promise = runConfigGet({ entry, keys: ['ELA_API_URL'] });
    const req = JSON.parse(entry.ws.sent[0]);
    deliverConfigValue(entry, { _type: 'config.value', id: req.id });
    await expect(promise).resolves.toEqual({});
  });
});
