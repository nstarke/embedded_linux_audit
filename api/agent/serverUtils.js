'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

function findProjectRoot(startDir) {
  const markers = [
    ['tests', 'agent', 'shell', 'download_tests.sh'],
    ['api', 'agent', 'package.json'],
    ['Makefile'],
  ];

  let current = path.resolve(startDir);
  while (true) {
    const hasAllMarkers = markers.every((segments) => fs.existsSync(path.join(current, ...segments)));
    if (hasAllMarkers) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }

  return path.resolve(startDir, '..', '..');
}

function isValidMacAddress(value) {
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(String(value || ''));
}

function normalizeContentType(contentTypeHeader = '') {
  return contentTypeHeader.split(';', 1)[0].trim().toLowerCase();
}

function logPathForContentType(logPrefix, contentTypeHeader, validContentTypes) {
  const contentType = normalizeContentType(contentTypeHeader);
  const suffix = validContentTypes[contentType];
  const dir = path.dirname(logPrefix);
  const base = path.basename(logPrefix);
  return path.join(dir, `${base}.${suffix || 'unknown'}.log`);
}

function augmentJsonPayload(payloadBuffer, timestamp, srcIp) {
  const text = payloadBuffer.toString('utf8');
  const stripped = text.trim();
  if (!stripped) {
    return payloadBuffer;
  }

  const lines = text.split(/\r?\n/);
  if (lines.filter((line) => line.trim()).length > 1) {
    const outLines = [];
    let changed = false;
    for (const line of lines) {
      if (!line.trim()) {
        continue;
      }
      const obj = JSON.parse(line);
      if (obj === null || Array.isArray(obj) || typeof obj !== 'object') {
        return payloadBuffer;
      }
      obj.api_timestamp = timestamp;
      obj.src_ip = srcIp;
      outLines.push(JSON.stringify(obj));
      changed = true;
    }
    if (changed) {
      return Buffer.from(`${outLines.join('\n')}\n`, 'utf8');
    }
    return payloadBuffer;
  }

  const obj = JSON.parse(stripped);
  if (obj === null || Array.isArray(obj) || typeof obj !== 'object') {
    return payloadBuffer;
  }
  obj.api_timestamp = timestamp;
  obj.src_ip = srcIp;
  return Buffer.from(`${JSON.stringify(obj)}\n`, 'utf8');
}

function resolveProjectPath(projectRoot, targetPath) {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(projectRoot, targetPath);
}

function isWithinRoot(candidatePath, rootPath) {
  const resolvedCandidate = path.resolve(candidatePath);
  const resolvedRoot = path.resolve(rootPath);
  return resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(`${resolvedRoot}${path.sep}`);
}

function getClientIp(req) {
  return (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
}

function sanitizeUploadPath(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    return null;
  }

  const normalized = path.posix.normalize(filePath.replace(/\\/g, '/'));
  const trimmed = normalized.replace(/^\/+/, '');
  if (!trimmed || trimmed === '.' || trimmed.startsWith('../') || trimmed.includes('/../')) {
    return null;
  }
  return trimmed;
}

async function writeUploadFile(baseDir, relativePath, payload) {
  const dest = path.resolve(baseDir, relativePath);
  if (!isWithinRoot(dest, baseDir)) {
    throw new Error('invalid path');
  }
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  await fsp.writeFile(dest, payload);
  return dest;
}

module.exports = {
  findProjectRoot,
  isValidMacAddress,
  normalizeContentType,
  logPathForContentType,
  augmentJsonPayload,
  resolveProjectPath,
  isWithinRoot,
  getClientIp,
  sanitizeUploadPath,
  writeUploadFile,
};
