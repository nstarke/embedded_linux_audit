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
    { name: 'modules', description: 'Cross-compiled kernel-module builds for associated devices' },
    { name: 'ghidra', description: 'Ghidra decompilation of a device filesystem' },
  ],
  paths: {
    '/uploads': {
      get: {
        tags: ['uploads'],
        summary: 'List upload types and counts',
        operationId: 'listUploadTypes',
        parameters: [{ $ref: '#/components/parameters/MacFilter' }],
        responses: {
          200: {
            description: 'Upload types available to the authenticated user',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UploadTypesResponse' },
              },
            },
          },
          400: { $ref: '#/components/responses/BadRequest' },
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
          { $ref: '#/components/parameters/MacFilter' },
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
          400: { $ref: '#/components/responses/BadRequest' },
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
    '/devices/{mac}/module-builds': {
      post: {
        tags: ['modules'],
        summary: 'Request a cross-compiled kernel module for a device',
        description: 'Creates a build request from the device\'s latest `module-buildinfo` upload and enqueues it. If this exact target (same kernel release, ISA, endianness, and vermagic) was already compiled for the device and the artifact is still available, the existing build is returned instead of queueing a new one (200 with `reused: true`). Pass `autobuild: true` to first push `linux modules buildinfo` to the live agent and wait for a fresh upload, so the build uses current kernel facts (and works on devices that have never uploaded buildinfo).',
        operationId: 'createModuleBuild',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        requestBody: {
          required: false,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/CreateModuleBuildRequest' } } },
        },
        responses: {
          200: {
            description: 'An existing compilation for this target was reused; no new build was queued (`reused: true`)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ModuleBuildResponse' } } },
          },
          202: {
            description: 'A new build request was queued',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ModuleBuildResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/DeviceNotFound' },
          409: { $ref: '#/components/responses/ModuleBuildConflict' },
          422: { $ref: '#/components/responses/ModuleBuildUnprocessable' },
          503: { $ref: '#/components/responses/RegistryUnavailable' },
          504: { $ref: '#/components/responses/AutobuildUnavailable' },
        },
      },
    },
    '/module-builds': {
      get: {
        tags: ['modules'],
        summary: 'List your kernel-module build requests',
        operationId: 'listModuleBuilds',
        parameters: [{ $ref: '#/components/parameters/MacFilter' }],
        responses: {
          200: {
            description: 'Build requests for your associated devices (newest first)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ModuleBuildListResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/module-builds/{id}': {
      get: {
        tags: ['modules'],
        summary: 'Fetch one kernel-module build request',
        operationId: 'getModuleBuild',
        parameters: [{ $ref: '#/components/parameters/ModuleBuildId' }],
        responses: {
          200: {
            description: 'The build request status and result',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ModuleBuildResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/ModuleBuildNotFound' },
        },
      },
    },
    '/module-builds/{id}/deliver': {
      post: {
        tags: ['modules'],
        summary: 'Deliver a succeeded build to its device',
        description: 'Mints a one-time download token and pushes `linux download-file` (then, unless `load: false`, `linux modules load`) to the device\'s live agent session. Only `succeeded` builds with an artifact are deliverable.',
        operationId: 'deliverModuleBuild',
        parameters: [{ $ref: '#/components/parameters/ModuleBuildId' }],
        requestBody: {
          required: false,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/DeliverModuleBuildRequest' } } },
        },
        responses: {
          200: {
            description: 'Delivery attempt completed (`delivered: true` on full success)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/DeliverModuleBuildResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/ModuleBuildNotFound' },
          409: { $ref: '#/components/responses/ModuleBuildConflict' },
          502: {
            description: 'A download/load command failed on the device (body has the same shape with `delivered: false`)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/DeliverModuleBuildResponse' } } },
          },
        },
      },
    },
    '/devices/{mac}/ghidra-analysis': {
      post: {
        tags: ['ghidra'],
        summary: 'Decompile a device\'s filesystem with Ghidra',
        description: 'Pushes `linux remote-copy --recursive /` to the device\'s live agent session to upload its filesystem (the agent refuses /dev, /proc and /sys by default), then queues a background job that hands the uploaded tree to Ghidra\'s `analyzeHeadless -recursive`. Ghidra discovers every loadable binary (ELF executables, shared objects and kernel modules) and the Haruspex post-script writes decompiled C into a parallel `ghidra/` directory tree, kept separate from the uploaded binaries. Returns 202 immediately; poll `GET /ghidra-analysis/{id}` for progress.',
        operationId: 'createGhidraAnalysis',
        parameters: [{ $ref: '#/components/parameters/Mac' }],
        responses: {
          202: {
            description: 'A ghidra-analysis job was queued',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GhidraAnalysisResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/DeviceNotFound' },
          503: { $ref: '#/components/responses/RegistryUnavailable' },
        },
      },
    },
    '/ghidra-analysis': {
      get: {
        tags: ['ghidra'],
        summary: 'List your ghidra-analysis jobs',
        operationId: 'listGhidraAnalyses',
        parameters: [{ $ref: '#/components/parameters/MacFilter' }],
        responses: {
          200: {
            description: 'Ghidra-analysis jobs for your associated devices (newest first)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GhidraAnalysisListResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/ghidra-analysis/{id}': {
      get: {
        tags: ['ghidra'],
        summary: 'Fetch one ghidra-analysis job',
        operationId: 'getGhidraAnalysis',
        parameters: [{ $ref: '#/components/parameters/GhidraAnalysisId' }],
        responses: {
          200: {
            description: 'The job status and progress',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GhidraAnalysisResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/GhidraAnalysisNotFound' },
        },
      },
    },
    '/ghidra-analysis/{id}/outputs': {
      get: {
        tags: ['ghidra'],
        summary: 'List the downloadable decompiler outputs for a job',
        description: 'Returns one entry per binary that Ghidra produced decompiled C for — the relative directory (the value `output.zip?binary=` accepts) and its `.c` file count. Only available for `succeeded` jobs.',
        operationId: 'listGhidraAnalysisOutputs',
        parameters: [{ $ref: '#/components/parameters/GhidraAnalysisId' }],
        responses: {
          200: {
            description: 'The binaries with decompiler output',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GhidraAnalysisOutputsResponse' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/GhidraAnalysisNotFound' },
          409: {
            description: 'The job has no downloadable output yet (not succeeded)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },
    '/ghidra-analysis/{id}/output.zip': {
      get: {
        tags: ['ghidra'],
        summary: 'Download the decompiler output as a zip',
        description: 'Streams a zip archive of the Haruspex decompiler output for a `succeeded` job: one `<programName>/<func@addr>.c` subdirectory per binary, in the source filesystem hierarchy. Pass `?binary=<relative-dir>` (e.g. `usr/bin/busybox`) to download just one binary\'s decompiled C.',
        operationId: 'downloadGhidraAnalysisOutput',
        parameters: [
          { $ref: '#/components/parameters/GhidraAnalysisId' },
          {
            name: 'binary',
            in: 'query',
            required: false,
            description: 'Optional relative directory under the output root to scope the archive to one binary.',
            schema: { type: 'string', example: 'usr/bin/busybox' },
          },
        ],
        responses: {
          200: {
            description: 'A zip archive of the decompiled C files',
            content: { 'application/zip': { schema: { type: 'string', format: 'binary' } } },
          },
          400: { $ref: '#/components/responses/BadRequest' },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/GhidraAnalysisNotFound' },
          409: {
            description: 'The job has no downloadable output yet (not succeeded)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
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
      MacFilter: {
        name: 'mac',
        in: 'query',
        required: false,
        description: 'Optional device MAC filter (any separator or none, any case). Restricts results to that device; unknown or unassociated MACs return no results.',
        schema: { type: 'string', example: 'aa:bb:cc:dd:ee:ff' },
      },
      Pid: {
        name: 'pid',
        in: 'path',
        required: true,
        description: 'PID of a tracked spawn.',
        schema: { type: 'string', pattern: '^[0-9]+$' },
      },
      ModuleBuildId: {
        name: 'id',
        in: 'path',
        required: true,
        description: 'Numeric module-build request id.',
        schema: { type: 'string', pattern: '^[0-9]+$' },
      },
      GhidraAnalysisId: {
        name: 'id',
        in: 'path',
        required: true,
        description: 'Numeric ghidra-analysis job id.',
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
      DeviceNotFound: {
        description: 'No such device, or you are not associated with it',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      ModuleBuildNotFound: {
        description: 'Module build not found or not owned',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      GhidraAnalysisNotFound: {
        description: 'Ghidra-analysis job not found or not owned',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      ModuleBuildConflict: {
        description: 'No buildinfo upload to build from, or the build is not in a deliverable state',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      ModuleBuildUnprocessable: {
        description: 'The device kernel release is unusable, or no cross toolchain matches its isa/endianness',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      RegistryUnavailable: {
        description: 'The device registry is unavailable',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      AutobuildUnavailable: {
        description: 'Autobuild requested but the agent produced no module-buildinfo upload (device offline?)',
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
          output: {
            description: 'Command output. Agents emit JSON (ELA_OUTPUT_FORMAT=json), '
              + 'so this is the parsed JSON object/array when the output is valid JSON; '
              + 'otherwise the raw text string.',
            oneOf: [{ type: 'string' }, { type: 'object' }, { type: 'array' }],
          },
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
      ModuleBuild: {
        type: 'object',
        properties: {
          id: { type: 'integer', example: 12 },
          status: {
            type: 'string',
            enum: ['queued', 'building', 'succeeded', 'failed'],
            description: 'Lifecycle state; transitions are driven by the builder worker.',
          },
          kernelRelease: { type: 'string', example: '5.15.0-113-generic' },
          isa: { type: 'string', nullable: true, example: 'arm' },
          endianness: { type: 'string', nullable: true, enum: ['little', 'big'], example: 'little' },
          deviceVermagic: {
            type: 'string', nullable: true,
            description: 'Vermagic reported by the device\'s modules.',
            example: '5.15.0-113-generic SMP mod_unload modversions ARMv7',
          },
          builtVermagic: {
            type: 'string', nullable: true,
            description: 'Vermagic of the module this build produced (null until it succeeds).',
          },
          vermagicResult: {
            type: 'string', nullable: true,
            enum: ['match', 'release-match', 'mismatch', 'unverified'],
            description: 'How the built vermagic compares to the device\'s.',
          },
          source: {
            type: 'string', nullable: true,
            enum: ['upstream-exact', 'upstream-nearest'],
            description: 'Which upstream kernel source the module was compiled against.',
          },
          errorMessage: { type: 'string', nullable: true },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
        required: ['id', 'status', 'kernelRelease'],
      },
      ModuleBuildResponse: {
        type: 'object',
        properties: {
          moduleBuild: { $ref: '#/components/schemas/ModuleBuild' },
          reused: {
            type: 'boolean',
            description: 'Present and true when an existing compilation was returned instead of queueing a new build.',
          },
        },
        required: ['moduleBuild'],
      },
      ModuleBuildListResponse: {
        type: 'object',
        properties: {
          moduleBuilds: { type: 'array', items: { $ref: '#/components/schemas/ModuleBuild' } },
        },
        required: ['moduleBuilds'],
      },
      CreateModuleBuildRequest: {
        type: 'object',
        properties: {
          autobuild: {
            type: 'boolean',
            default: false,
            description: 'Push `linux modules buildinfo` to the live agent and wait for a fresh upload before building, instead of using the last stored one.',
          },
        },
      },
      DeliverModuleBuildRequest: {
        type: 'object',
        properties: {
          baseUrl: {
            type: 'string',
            description: 'agent-api origin as reachable FROM THE DEVICE, used to build the module download URL. Falls back to ELA_MODULE_DOWNLOAD_BASE_URL; required one way or the other.',
            example: 'https://agent.example.com',
          },
          load: {
            type: 'boolean',
            default: true,
            description: 'Run `linux modules load` after downloading. Set false to only download the artifact.',
          },
          force: {
            type: 'boolean',
            description: 'Load with --force (vermagic override). Defaults to true when the build\'s vermagicResult was not an exact `match`.',
          },
          destPath: {
            type: 'string',
            default: '/tmp/ela_kmod.ko',
            description: 'Absolute path where the .ko lands on the device.',
          },
        },
      },
      DeliverCommandResult: {
        type: 'object',
        description: 'Outcome of one command pushed to the device (download token redacted).',
        properties: {
          command: { type: 'string', example: 'linux download-file https://agent.example.com/module/<token> /tmp/ela_kmod.ko' },
          status: { type: 'integer', example: 200 },
        },
        required: ['command'],
        additionalProperties: true,
      },
      DeliverModuleBuildResponse: {
        type: 'object',
        properties: {
          delivered: { type: 'boolean', example: true },
          force: { type: 'boolean' },
          destPath: { type: 'string', example: '/tmp/ela_kmod.ko' },
          tokenExpiresAt: { type: 'string', format: 'date-time', nullable: true },
          results: { type: 'array', items: { $ref: '#/components/schemas/DeliverCommandResult' } },
        },
        required: ['delivered', 'results'],
      },
      GhidraAnalysis: {
        type: 'object',
        properties: {
          id: { type: 'integer', example: 7 },
          status: {
            type: 'string',
            enum: ['queued', 'copying', 'analyzing', 'succeeded', 'failed'],
            description: 'Lifecycle state driven by the ghidra-analysis worker: queued -> copying (uploading the rootfs) -> analyzing (running Ghidra) -> succeeded | failed.',
          },
          filesFound: {
            type: 'integer',
            description: 'ELF files found in the uploaded filesystem (known once analysis starts).',
            example: 214,
          },
          filesAnalyzed: {
            type: 'integer',
            description: 'Binaries Ghidra produced decompiler output for so far.',
            example: 214,
          },
          outputRoot: {
            type: 'string', nullable: true,
            description: 'Server-side directory holding the decompiled C tree (parallel to the uploaded filesystem).',
          },
          errorMessage: { type: 'string', nullable: true },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
        required: ['id', 'status'],
      },
      GhidraAnalysisResponse: {
        type: 'object',
        properties: {
          ghidraAnalysis: { $ref: '#/components/schemas/GhidraAnalysis' },
        },
        required: ['ghidraAnalysis'],
      },
      GhidraAnalysisListResponse: {
        type: 'object',
        properties: {
          ghidraAnalyses: { type: 'array', items: { $ref: '#/components/schemas/GhidraAnalysis' } },
        },
        required: ['ghidraAnalyses'],
      },
      GhidraAnalysisOutput: {
        type: 'object',
        properties: {
          binary: {
            type: 'string',
            description: 'Relative directory under the output root (pass to output.zip?binary=).',
            example: 'usr/bin/busybox',
          },
          files: { type: 'integer', description: 'Number of decompiled .c files.', example: 312 },
        },
        required: ['binary', 'files'],
      },
      GhidraAnalysisOutputsResponse: {
        type: 'object',
        properties: {
          outputs: { type: 'array', items: { $ref: '#/components/schemas/GhidraAnalysisOutput' } },
        },
        required: ['outputs'],
      },
    },
  },
};

module.exports = { openapiSpec };
