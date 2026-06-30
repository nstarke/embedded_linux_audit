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

module.exports = function registerUploadsRoutes(app, deps = {}) {
  const queries = {
    listUploadTypesForUser,
    listUploadsForUser,
    getUploadForUser,
    ...deps.queries,
  };

  app.get('/uploads', async (req, res) => {
    const types = await queries.listUploadTypesForUser(req.authUser);
    res.json({ uploadTypes: types });
  });

  app.get('/uploads/:type', async (req, res) => {
    const { type } = req.params;
    if (!isValidUploadType(type)) {
      res.status(404).json({ error: 'unknown upload type' });
      return;
    }
    const limit = Math.min(parseNonNegativeInt(req.query.limit, 100), 1000);
    const offset = parseNonNegativeInt(req.query.offset, 0);
    const uploads = await queries.listUploadsForUser(type, req.authUser, { limit, offset });
    res.json({ uploadType: type, limit, offset, uploads });
  });

  app.get('/uploads/:type/:id', async (req, res) => {
    const { type, id } = req.params;
    if (!isValidUploadType(type) || !isValidId(id)) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const upload = await queries.getUploadForUser(type, id, req.authUser);
    if (!upload) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    res.json(upload);
  });

  app.get('/uploads/:type/:id/raw', async (req, res) => {
    const { type, id } = req.params;
    if (!isValidUploadType(type) || !isValidId(id)) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const upload = await queries.getUploadForUser(type, id, req.authUser, { includeBinary: true });
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
