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
      '/terminal/sessions',
      '/terminal/{mac}/exec',
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
