'use strict';

const { VALID_UPLOAD_TYPES } = require('../lib/uploadTypes');

const UPLOAD_TYPES = [...VALID_UPLOAD_TYPES].sort();

// OpenAPI 3 description of the client API. Built as a plain object so the upload
// type enum stays in sync with api/lib/uploadTypes.js. Served at GET /openapi.json
// and rendered by Swagger UI at GET /docs.
const openapiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'ELA Client API',
    version: '1.0.0',
    description:
      'Read-back API for artifacts uploaded by the embedded_linux_audit agent. '
      + 'Authenticate with your **client** bearer token (printed by '
      + '`tools/add-user-key.js`). Every route returns only the artifacts '
      + 'uploaded by your own agent.',
  },
  servers: [
    { url: '/', description: 'Direct to client-api (e.g. http://localhost:7000)' },
    { url: '/client', description: 'Through the nginx reverse proxy' },
  ],
  security: [{ bearerAuth: [] }],
  tags: [{ name: 'uploads', description: 'Uploaded artifacts' }],
  paths: {
    '/uploads': {
      get: {
        tags: ['uploads'],
        summary: 'List upload types and counts',
        operationId: 'listUploadTypes',
        responses: {
          200: {
            description: 'Upload types available to the authenticated user',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UploadTypesResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/uploads/{type}': {
      get: {
        tags: ['uploads'],
        summary: 'List artifacts of a given upload type',
        operationId: 'listUploads',
        parameters: [
          { $ref: '#/components/parameters/UploadType' },
          {
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer', minimum: 0, maximum: 1000, default: 100 },
            description: 'Maximum number of records to return (capped at 1000).',
          },
          {
            name: 'offset',
            in: 'query',
            required: false,
            schema: { type: 'integer', minimum: 0, default: 0 },
            description: 'Number of records to skip.',
          },
        ],
        responses: {
          200: {
            description: 'Artifact metadata (newest first)',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UploadListResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/uploads/{type}/{id}': {
      get: {
        tags: ['uploads'],
        summary: 'Fetch a single artifact (metadata + parsed payload)',
        operationId: 'getUpload',
        parameters: [
          { $ref: '#/components/parameters/UploadType' },
          { $ref: '#/components/parameters/UploadId' },
        ],
        responses: {
          200: {
            description: 'The artifact record',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UploadDetail' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/uploads/{type}/{id}/raw': {
      get: {
        tags: ['uploads'],
        summary: 'Download the original artifact bytes',
        operationId: 'getUploadRaw',
        parameters: [
          { $ref: '#/components/parameters/UploadType' },
          { $ref: '#/components/parameters/UploadId' },
        ],
        responses: {
          200: {
            description: 'Raw payload, with the artifact\'s stored content type',
            content: {
              'application/octet-stream': {
                schema: { type: 'string', format: 'binary' },
              },
              'text/plain': { schema: { type: 'string' } },
              'application/json': { schema: { type: 'object' } },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        description: 'The client-scoped API token for this user.',
      },
    },
    parameters: {
      UploadType: {
        name: 'type',
        in: 'path',
        required: true,
        description: 'Upload type.',
        schema: { type: 'string', enum: UPLOAD_TYPES },
      },
      UploadId: {
        name: 'id',
        in: 'path',
        required: true,
        description: 'Numeric upload id.',
        schema: { type: 'string', pattern: '^[0-9]+$' },
      },
    },
    responses: {
      Unauthorized: {
        description: 'Missing or invalid client token',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      NotFound: {
        description: 'Unknown upload type, or artifact not found / not owned',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: { error: { type: 'string' } },
        required: ['error'],
      },
      UploadTypeCount: {
        type: 'object',
        properties: {
          uploadType: { type: 'string', example: 'dmesg' },
          count: { type: 'integer', example: 3 },
        },
        required: ['uploadType', 'count'],
      },
      UploadTypesResponse: {
        type: 'object',
        properties: {
          uploadTypes: {
            type: 'array',
            items: { $ref: '#/components/schemas/UploadTypeCount' },
          },
        },
        required: ['uploadTypes'],
      },
      UploadMetadata: {
        type: 'object',
        properties: {
          id: { type: 'string', example: '42' },
          uploadType: { type: 'string', example: 'dmesg' },
          contentType: { type: 'string', example: 'text/plain' },
          macAddress: { type: 'string', nullable: true, example: 'aa:bb:cc:dd:ee:ff' },
          srcIp: { type: 'string', nullable: true },
          apiTimestamp: { type: 'string', format: 'date-time' },
          requestFilePath: { type: 'string', nullable: true },
          localArtifactPath: { type: 'string', nullable: true },
          isSymlink: { type: 'boolean' },
          symlinkPath: { type: 'string', nullable: true },
          payloadSha256: { type: 'string' },
          payloadBytes: { type: 'integer' },
        },
      },
      UploadListResponse: {
        type: 'object',
        properties: {
          uploadType: { type: 'string' },
          limit: { type: 'integer' },
          offset: { type: 'integer' },
          uploads: {
            type: 'array',
            items: { $ref: '#/components/schemas/UploadMetadata' },
          },
        },
        required: ['uploadType', 'limit', 'offset', 'uploads'],
      },
      UploadDetail: {
        allOf: [
          { $ref: '#/components/schemas/UploadMetadata' },
          {
            type: 'object',
            properties: {
              payloadText: { type: 'string', nullable: true },
              payloadJson: { type: 'object', nullable: true },
            },
          },
        ],
      },
    },
  },
};

module.exports = { openapiSpec };
