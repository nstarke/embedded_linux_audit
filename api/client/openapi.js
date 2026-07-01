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
      'Read-back API for artifacts uploaded by the embedded_linux_audit agent, '
      + 'plus live terminal control of connected devices. Authenticate with your '
      + '**client** bearer token (printed by `tools/add-user-key.js`). Every '
      + 'route is scoped to **devices you are associated with** (i.e. devices '
      + 'that have connected to the terminal API with your token); a device you '
      + 'are not associated with is treated as not connected (404). Terminal '
      + 'commands are relayed to the terminal API over an internal queue and the '
      + 'result is returned.',
  },
  servers: [
    { url: '/', description: 'Direct to client-api (e.g. http://localhost:7000)' },
    { url: '/client', description: 'Through the nginx reverse proxy' },
  ],
  security: [{ bearerAuth: [] }],
  tags: [
    { name: 'uploads', description: 'Uploaded artifacts' },
    { name: 'terminal', description: 'Live control of associated devices' },
    { name: 'gdb', description: 'Active gdbserver debug sessions on associated devices' },
  ],
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
    '/terminal/sessions': {
      get: {
        tags: ['terminal'],
        summary: 'List connected devices you are associated with',
        operationId: 'listTerminalSessions',
        responses: {
          200: {
            description: 'Live sessions for your associated devices',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SessionsResponse' } } },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/gdb/sessions': {
      get: {
        tags: ['gdb'],
        summary: 'List active gdbserver sessions on your associated devices',
        description: 'Lists every live gdbserver session on the devices you are associated with. A device may have multiple concurrent sessions; each is returned separately with its attach handle (`hexkey`) and whether a gdb client is currently attached (`operatorConnected`). Attach with `target remote wss://<host>/gdb/out/<hexkey>` using your client token.',
        operationId: 'listGdbSessions',
        responses: {
          200: {
            description: 'Active gdbserver sessions for your associated devices',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GdbSessionsResponse' } } },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          504: { $ref: '#/components/responses/GdbUnavailable' },
        },
      },
    },
    '/terminal/sessions/{mac}': {
      post: {
        tags: ['terminal'],
        summary: 'Set a device\'s alias and/or group',
        operationId: 'setTerminalSessionMeta',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/SetSessionMetaRequest' } } },
        },
        responses: {
          200: {
            description: 'The updated alias/group',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SessionMeta' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/linux/exec': {
      post: {
        tags: ['terminal'],
        summary: 'Run a Linux shell command and wait for its output',
        description: 'Runs the shell command via the agent\'s `linux execute-command` and returns the captured output.',
        operationId: 'terminalLinuxExec',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ExecRequest' } } },
        },
        responses: {
          200: {
            description: 'Captured command output',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ExecResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/ela/exec': {
      post: {
        tags: ['terminal'],
        summary: 'Run a raw ELA agent command and wait for its output',
        description: 'Sends the command verbatim to the ELA agent (e.g. `linux dmesg`, `linux gdbserver tunnel <pid> <url>`) and returns its output. Not wrapped in `execute-command`.',
        operationId: 'terminalElaExec',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: true,
          // Override the shared ExecRequest example: this endpoint runs a raw
          // ELA command (not a shell command), so the default must be a valid
          // ELA command like `linux netstat` — `uname -a` is a shell command and
          // is not understood by the agent here.
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ExecRequest' },
              example: { command: 'linux netstat' },
            },
          },
        },
        responses: {
          200: {
            description: 'Captured command output',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ExecResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/linux/spawn': {
      post: {
        tags: ['terminal'],
        summary: 'Launch a long-running background Linux process',
        description: 'Shell-backgrounds the command and returns the tracked PID (and port if detected). List with `GET /terminal/{mac}/spawn`, kill with `DELETE`.',
        operationId: 'terminalLinuxSpawn',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/SpawnRequest' } } },
        },
        responses: {
          201: {
            description: 'The spawned process',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SpawnResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/ela/spawn': {
      post: {
        tags: ['terminal'],
        summary: 'Start a self-daemonizing ELA agent command',
        description: 'Runs a raw ELA command that backgrounds itself (e.g. `linux gdbserver tunnel <pid> <url>`) and returns its output. ELA processes are self-managed, so no PID is tracked.',
        operationId: 'terminalElaSpawn',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/SpawnRequest' } } },
        },
        responses: {
          201: {
            description: 'Captured command output',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ExecResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/spawn': {
      get: {
        tags: ['terminal'],
        summary: 'List the processes spawned on a device',
        operationId: 'listTerminalSpawns',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        responses: {
          200: {
            description: 'Tracked spawns for the device',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SpawnListResponse' } } },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
        },
      },
    },
    '/terminal/{mac}/spawn/{pid}': {
      delete: {
        tags: ['terminal'],
        summary: 'Kill a spawned process on a device',
        operationId: 'killTerminalSpawn',
        parameters: [
          { $ref: '#/components/parameters/Mac' },
          { $ref: '#/components/parameters/Pid' },
        ],
        responses: {
          200: {
            description: 'The process was killed',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OkResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NoSession' },
          504: { $ref: '#/components/responses/TerminalUnavailable' },
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
      Mac: {
        name: 'mac',
        in: 'path',
        required: true,
        description: 'Device MAC address, either separator (aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff), any case. Must be a device you are associated with.',
        schema: { type: 'string', pattern: '^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$' },
      },
      Pid: {
        name: 'pid',
        in: 'path',
        required: true,
        description: 'PID of a tracked spawn.',
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
      BadRequest: {
        description: 'Invalid MAC, PID, or request body',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      NoSession: {
        description: 'No connected device for this MAC, or you are not associated with it',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      TerminalUnavailable: {
        description: 'The command timed out or the terminal API is unavailable',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      GdbUnavailable: {
        description: 'The query timed out or the GDB bridge API is unavailable',
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
      Session: {
        type: 'object',
        properties: {
          mac: { type: 'string', example: 'aa:bb:cc:dd:ee:ff' },
          alias: { type: 'string', nullable: true },
          group: { type: 'string', nullable: true },
          remoteAddress: { type: 'string', nullable: true },
          connectedAt: { type: 'string', format: 'date-time', nullable: true },
          lastHeartbeat: { type: 'string', format: 'date-time', nullable: true },
        },
        required: ['mac'],
      },
      SessionsResponse: {
        type: 'object',
        properties: {
          sessions: { type: 'array', items: { $ref: '#/components/schemas/Session' } },
        },
        required: ['sessions'],
      },
      GdbSession: {
        type: 'object',
        properties: {
          mac: { type: 'string', example: 'aa:bb:cc:dd:ee:ff' },
          hexkey: {
            type: 'string',
            example: '0123456789abcdef0123456789abcdef',
            description: 'Session handle. Attach with `target remote wss://<host>/gdb/out/<hexkey>`.',
          },
          operatorConnected: {
            type: 'boolean',
            example: false,
            description: 'Whether a gdb client is currently attached to this session.',
          },
        },
        required: ['mac', 'hexkey', 'operatorConnected'],
      },
      GdbSessionsResponse: {
        type: 'object',
        properties: {
          sessions: { type: 'array', items: { $ref: '#/components/schemas/GdbSession' } },
        },
        required: ['sessions'],
      },
      SetSessionMetaRequest: {
        type: 'object',
        description: 'Provide `alias`, `group`, or both. A string sets the value; null clears it. At least one is required.',
        properties: {
          alias: { type: 'string', nullable: true, example: 'lab-router' },
          group: { type: 'string', nullable: true, example: 'field-team' },
        },
      },
      SessionMeta: {
        type: 'object',
        properties: {
          mac: { type: 'string', example: 'aa:bb:cc:dd:ee:ff' },
          alias: { type: 'string', nullable: true },
          group: { type: 'string', nullable: true },
        },
        required: ['mac'],
      },
      ExecRequest: {
        type: 'object',
        properties: {
          command: { type: 'string', example: 'uname -a' },
          timeoutMs: {
            type: 'integer', minimum: 1, maximum: 60000, default: 15000,
            description: 'Per-command timeout in milliseconds (<= 60000).',
          },
        },
        required: ['command'],
      },
      ExecResponse: {
        type: 'object',
        properties: {
          ok: { type: 'boolean', example: true },
          output: { type: 'string' },
          durationMs: { type: 'integer' },
        },
        required: ['ok', 'output'],
      },
      SpawnRequest: {
        type: 'object',
        properties: {
          command: { type: 'string', example: 'gdbserver' },
          args: { type: 'array', items: { type: 'string' }, default: [] },
          port: { type: 'integer', minimum: 1, maximum: 65535, nullable: true },
        },
        required: ['command'],
      },
      SpawnResponse: {
        type: 'object',
        properties: {
          pid: { type: 'integer', example: 4242 },
          port: { type: 'integer', nullable: true },
        },
        required: ['pid'],
      },
      Spawn: {
        type: 'object',
        properties: {
          pid: { type: 'integer' },
          command: { type: 'string' },
          args: { type: 'array', items: { type: 'string' } },
          startedAt: { type: 'string', format: 'date-time' },
          port: { type: 'integer', nullable: true },
        },
        required: ['pid', 'command', 'args', 'startedAt'],
      },
      SpawnListResponse: {
        type: 'object',
        properties: {
          spawns: { type: 'array', items: { $ref: '#/components/schemas/Spawn' } },
        },
        required: ['spawns'],
      },
      OkResponse: {
        type: 'object',
        properties: { ok: { type: 'boolean', example: true } },
        required: ['ok'],
      },
    },
  },
};

module.exports = { openapiSpec };
