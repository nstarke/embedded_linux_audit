'use strict';

const { openapiSpec } = require('../../../../api/client/openapi');
const { VALID_UPLOAD_TYPES } = require('../../../../api/lib/uploadTypes');

describe('client OpenAPI spec', () => {
  test('is a serializable OpenAPI 3 document', () => {
    expect(openapiSpec.openapi).toMatch(/^3\./);
    expect(() => JSON.stringify(openapiSpec)).not.toThrow();
    expect(openapiSpec.info.title).toBe('ELA Client API');
  });

  test('documents every client API route', () => {
    expect(Object.keys(openapiSpec.paths).sort()).toEqual([
      '/gdb/sessions',
      '/terminal/sessions',
      '/terminal/sessions/{mac}',
      '/terminal/{mac}/ela/exec',
      '/terminal/{mac}/ela/spawn',
      '/terminal/{mac}/linux/exec',
      '/terminal/{mac}/linux/spawn',
      '/terminal/{mac}/spawn',
      '/terminal/{mac}/spawn/{pid}',
      '/uploads',
      '/uploads/{type}',
      '/uploads/{type}/{id}',
      '/uploads/{type}/{id}/raw',
    ]);
    // Every operation on every path requires auth (401 documented).
    for (const path of Object.values(openapiSpec.paths)) {
      const ops = ['get', 'post', 'delete'].map((m) => path[m]).filter(Boolean);
      expect(ops.length).toBeGreaterThan(0);
      for (const op of ops) {
        expect(op.responses['401']).toBeDefined();
      }
    }
  });

  test('ela/exec defaults to a valid ELA command, not a shell command', () => {
    // uname -a is a shell command (valid for linux/exec) but is not understood
    // by the agent as a raw ELA command, so ela/exec must default to a real one.
    const elaBody = openapiSpec.paths['/terminal/{mac}/ela/exec'].post
      .requestBody.content['application/json'];
    expect(elaBody.example).toEqual({ command: 'linux netstat' });

    // linux/exec still uses the shared shell-command example.
    const linuxBody = openapiSpec.paths['/terminal/{mac}/linux/exec'].post
      .requestBody.content['application/json'];
    expect(linuxBody.example).toBeUndefined();
    expect(openapiSpec.components.schemas.ExecRequest.properties.command.example).toBe('uname -a');
  });

  test('requires bearer auth globally', () => {
    expect(openapiSpec.security).toEqual([{ bearerAuth: [] }]);
    expect(openapiSpec.components.securitySchemes.bearerAuth).toMatchObject({
      type: 'http',
      scheme: 'bearer',
    });
  });

  test('the type enum stays in sync with VALID_UPLOAD_TYPES', () => {
    const enumValues = openapiSpec.components.parameters.UploadType.schema.enum;
    expect([...enumValues].sort()).toEqual([...VALID_UPLOAD_TYPES].sort());
  });

  test('offers both direct and reverse-proxy servers', () => {
    const urls = openapiSpec.servers.map((s) => s.url);
    expect(urls).toContain('/');
    expect(urls).toContain('/client');
  });
});
