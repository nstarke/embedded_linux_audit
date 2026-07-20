'use strict';

const { isSafeSinglePathSegment } = require('../../agent/routes/shared');
const { VALID_UPLOAD_TYPES } = require('../../lib/uploadTypes');
const {
  listUploadTypesForUser,
  listUploadsForUser,
  getUploadForUser,
} = require('../../lib/db/clientUploads');

function parseNonNegativeInt(value, fallback) {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(String(value), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function isValidUploadType(type) {
  return isSafeSinglePathSegment(type) && VALID_UPLOAD_TYPES.has(type);
}

function isValidId(id) {
  return typeof id === 'string' && /^[0-9]+$/.test(id);
}

// Optional `?mac=<addr>` filter. Accepts any separator style (`:`/`-`/none);
// the query layer canonicalizes it. Returns { valid, mac }: `mac` is the raw
// caller value (or null when absent), `valid` is false only when a value is
// present but is not a 12-hex-digit MAC.
function parseMacFilter(value) {
  if (value === undefined) {
    return { valid: true, mac: null };
  }
  const hex = String(value).toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) {
    return { valid: false, mac: null };
  }
  return { valid: true, mac: value };
}

module.exports = function registerUploadsRoutes(app, deps = {}) {
  const queries = {
    listUploadTypesForUser,
    listUploadsForUser,
    getUploadForUser,
    ...deps.queries,
  };

  // Without `?type=` this lists the upload types (with counts) visible to the
  // caller; with `?type=` it lists that type's uploads.
  app.get('/uploads', async (req, res) => {
    const { valid, mac } = parseMacFilter(req.query.mac);
    if (!valid) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }

    if (req.query.type === undefined) {
      const types = await queries.listUploadTypesForUser(req.authUser, { mac });
      res.json({ uploadTypes: types });
      return;
    }

    const type = String(req.query.type);
    if (!isValidUploadType(type)) {
      res.status(400).json({ error: 'unknown upload type' });
      return;
    }
    const limit = Math.min(parseNonNegativeInt(req.query.limit, 100), 1000);
    const offset = parseNonNegativeInt(req.query.offset, 0);
    const uploads = await queries.listUploadsForUser(type, req.authUser, { limit, offset, mac });
    const body = { uploadType: type, limit, offset, uploads };
    if (mac) {
      body.mac = mac;
    }
    res.json(body);
  });

  app.get('/uploads/:id', async (req, res) => {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const upload = await queries.getUploadForUser(id, req.authUser);
    if (!upload) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    res.json(upload);
  });

  app.get('/uploads/:id/raw', async (req, res) => {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const upload = await queries.getUploadForUser(id, req.authUser, { includeBinary: true });
    if (!upload) {
      res.status(404).json({ error: 'not found' });
      return;
    }

    if (upload.contentType === 'application/octet-stream') {
      const buffer = upload.payloadBinary ? Buffer.from(upload.payloadBinary) : Buffer.alloc(0);
      res.type('application/octet-stream').send(buffer);
      return;
    }

    if (upload.payloadText != null) {
      res.type(upload.contentType || 'text/plain').send(upload.payloadText);
      return;
    }

    if (upload.payloadJson != null) {
      res.type(upload.contentType || 'application/json').send(JSON.stringify(upload.payloadJson));
      return;
    }

    res.status(404).json({ error: 'no raw payload stored for this upload' });
  });
};
