'use strict';

const {
  uploadDirectoryForType,
  logFilePrefixForUploadType,
  sanitizeFileListPath,
  fileListNameForPath,
} = require('./uploadHelpers');

function createResponseHelpers(res, req, verboseResponseLog) {
  return {
    send(status, body) {
      res.status(status).type('text').send(body);
      verboseResponseLog(req, status, Buffer.byteLength(body));
    },
  };
}

function createUploadHandler(deps) {
  const {
    dataDir,
    path,
    fsp,
    crypto,
    validUploadTypes,
    validContentTypes,
    normalizeContentType,
    sanitizeUploadPath,
    writeUploadFile,
    augmentJsonPayload,
    logPathForContentType,
    persistUpload,
    isValidMacAddress,
    verboseRequestLog,
    verboseResponseLog,
    getClientIp,
    isWithinRoot,
  } = deps;

  async function writeSymlink(baseDir, relativePath, symlinkTarget) {
    const dest = path.resolve(baseDir, relativePath);
    if (!isWithinRoot(dest, baseDir)) {
      throw new Error('invalid path');
    }
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    try {
      await fsp.unlink(dest);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw err;
      }
    }
    await fsp.symlink(symlinkTarget, dest);
  }

  return async function uploadHandler(req, res) {
    verboseRequestLog(req);
    const reply = createResponseHelpers(res, req, verboseResponseLog);
    const macAddress = String(req.params.mac || '').toLowerCase();
    const uploadType = req.params.type;
    const contentTypeHeader = req.get('Content-Type') || '';
    const normalizedContentType = normalizeContentType(contentTypeHeader);
    const payload = Buffer.isBuffer(req.body) ? req.body : Buffer.from([]);
    const timestamp = new Date().toISOString();
    const srcIp = getClientIp(req);
    const macDataDir = path.join(dataDir, macAddress);
    const requestedFilePath = sanitizeUploadPath(req.query.filePath);
    const symlink = req.query.symlink;
    const symlinkPath = req.query.symlinkPath;
    const wantsSymlink = symlink === 'true';

    if (!isValidMacAddress(macAddress)) {
      reply.send(400, 'invalid mac address\n');
      return;
    }

    if (uploadType !== 'file' && (symlink !== undefined || symlinkPath !== undefined)) {
      reply.send(400, 'symlink arguments only allowed for /upload/file\n');
      return;
    }

    if (symlink !== undefined && symlink !== 'true' && symlink !== 'false') {
      reply.send(400, 'invalid symlink value\n');
      return;
    }

    if (wantsSymlink && (!requestedFilePath || typeof symlinkPath !== 'string' || !symlinkPath.length)) {
      reply.send(400, 'symlink uploads require filePath and symlinkPath\n');
      return;
    }

    if (!wantsSymlink && symlinkPath !== undefined) {
      reply.send(400, 'symlinkPath requires symlink=true\n');
      return;
    }

    if (!validUploadTypes.has(uploadType)) {
      reply.send(404, 'invalid upload type\n');
      return;
    }

    if (!Object.prototype.hasOwnProperty.call(validContentTypes, normalizedContentType)) {
      const allowed = Object.keys(validContentTypes).sort().join(', ');
      reply.send(415, `unsupported content type; expected one of: ${allowed}\n`);
      return;
    }

    if (normalizedContentType === 'application/json' && !['arch', 'cmd'].includes(uploadType)) {
      const allowed = Object.keys(validContentTypes)
        .filter((type) => type !== 'application/json')
        .sort()
        .join(', ');
      reply.send(415, `unsupported content type; expected one of: ${allowed}\n`);
      return;
    }

    let payloadToLog = payload;
    let shouldTryJson = normalizedContentType.includes('json');

    if (!shouldTryJson) {
      try {
        payload.toString('utf8');
        shouldTryJson = true;
      } catch {
        shouldTryJson = false;
      }
    }

    if (shouldTryJson) {
      try {
        payloadToLog = augmentJsonPayload(payload, timestamp, srcIp);
      } catch {
        payloadToLog = payload;
      }
    }

    if (uploadType === 'file' && wantsSymlink) {
      try {
        await writeSymlink(path.join(macDataDir, 'fs'), requestedFilePath, symlinkPath);
      } catch {
        reply.send(400, 'invalid symlink upload\n');
        return;
      }
    } else if (uploadType === 'file' && requestedFilePath) {
      try {
        await writeUploadFile(path.join(macDataDir, 'fs'), requestedFilePath, payload);
      } catch {
        reply.send(400, 'invalid filePath\n');
        return;
      }
    } else {
      const targetDir = uploadDirectoryForType(path, macDataDir, uploadType);
      await fsp.mkdir(targetDir, { recursive: true });

      if (uploadType === 'file-list' || uploadType === 'symlink-list' || uploadType === 'grep') {
        const requestedListPath = sanitizeFileListPath(path, req.query.filePath);
        if (!requestedListPath) {
          reply.send(400, `${uploadType} uploads require absolute filePath\n`);
          return;
        }

        const targetListPath = path.join(targetDir, fileListNameForPath(requestedListPath));
        await fsp.writeFile(
          targetListPath,
          payloadToLog[payloadToLog.length - 1] === 0x0a ? payloadToLog : Buffer.concat([payloadToLog, Buffer.from('\n')]),
        );
      } else if (normalizedContentType === 'application/octet-stream') {
        const tsSafe = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z').replace(/:/g, '');
        const unique = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
        const safeIp = srcIp.replace(/:/g, '_');
        const binaryPath = path.join(targetDir, `upload_${tsSafe}_${safeIp}_${unique}.bin`);
        await fsp.writeFile(binaryPath, payload);
      } else {
        const logPrefix = logFilePrefixForUploadType(path, targetDir, uploadType);
        const targetLogPath = logPathForContentType(logPrefix, contentTypeHeader);
        await fsp.mkdir(path.dirname(targetLogPath), { recursive: true });
        await fsp.appendFile(
          targetLogPath,
          payloadToLog[payloadToLog.length - 1] === 0x0a ? payloadToLog : Buffer.concat([payloadToLog, Buffer.from('\n')]),
        );
      }
    }

    await persistUpload({
      macAddress,
      uploadType,
      contentType: normalizedContentType,
      srcIp,
      apiTimestamp: timestamp,
      requestFilePath: requestedFilePath,
      isSymlink: wantsSymlink,
      symlinkPath: wantsSymlink ? symlinkPath : null,
      payload,
      payloadToPersist: normalizedContentType === 'application/octet-stream' ? payload : payloadToLog,
    });

    res.type('text').send('ok\n');
    verboseResponseLog(req, 200, 3);
  };
}

module.exports = {
  createUploadHandler,
};
