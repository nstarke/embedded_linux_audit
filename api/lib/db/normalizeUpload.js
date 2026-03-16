'use strict';

function parseJsonValue(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseNdjson(text) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const objects = [];

  for (const line of lines) {
    const parsed = parseJsonValue(line);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return [];
    }
    objects.push(parsed);
  }

  return objects;
}

function splitLines(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseSimpleCsvLine(line) {
  const values = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      values.push(current);
      current = '';
      continue;
    }
    current += ch;
  }

  values.push(current);
  return values;
}

function parseCommandUpload(contentType, payloadText) {
  if (contentType === 'application/json') {
    const parsed = parseJsonValue(payloadText);
    if (parsed && typeof parsed.command === 'string') {
      return {
        commandText: parsed.command,
        commandOutput: typeof parsed.output === 'string' ? parsed.output : null,
        commandFormat: 'json',
      };
    }
    return null;
  }

  if (contentType === 'text/csv') {
    const firstLine = splitLines(payloadText)[0];
    if (!firstLine) {
      return null;
    }
    const fields = parseSimpleCsvLine(firstLine);
    if (fields.length >= 2) {
      return {
        commandText: fields[0],
        commandOutput: fields.slice(1).join(','),
        commandFormat: 'csv',
      };
    }
    return null;
  }

  const lines = String(payloadText || '').split(/\r?\n/);
  const commandText = lines.shift();
  if (!commandText) {
    return null;
  }
  return {
    commandText,
    commandOutput: lines.join('\n').trim() || null,
    commandFormat: 'txt',
  };
}

function parseFileListEntries(payloadText, rootPath) {
  return splitLines(payloadText).map((entryPath, index) => ({
    recordIndex: index,
    rootPath: rootPath || null,
    entryPath,
  }));
}

function parseSymlinkListEntries(contentType, payloadText, rootPath) {
  if (contentType === 'application/x-ndjson') {
    return parseNdjson(payloadText)
      .map((row, index) => {
        if (typeof row.link_path !== 'string') {
          return null;
        }
        return {
          recordIndex: index,
          rootPath: rootPath || null,
          linkPath: row.link_path,
          targetPath: typeof row.location_path === 'string' ? row.location_path : null,
        };
      })
      .filter(Boolean);
  }

  return splitLines(payloadText)
    .map((line, index) => {
      const match = /^(.*?)\s+->\s+(.*)$/.exec(line);
      if (!match) {
        return null;
      }
      return {
        recordIndex: index,
        rootPath: rootPath || null,
        linkPath: match[1],
        targetPath: match[2],
      };
    })
    .filter(Boolean);
}

function parseEfiVariables(contentType, payloadText) {
  if (contentType === 'application/x-ndjson') {
    return parseNdjson(payloadText)
      .map((row, index) => {
        if (row.record !== 'efi_var' || typeof row.guid !== 'string' || typeof row.name !== 'string') {
          return null;
        }
        return {
          recordIndex: index,
          guid: row.guid,
          name: row.name,
          attributes: row.attributes ?? null,
          sizeBytes: row.size ?? null,
          dataHex: row.data_hex ?? null,
        };
      })
      .filter(Boolean);
  }

  if (contentType === 'text/csv') {
    return splitLines(payloadText)
      .map((line, index) => {
        const fields = parseSimpleCsvLine(line);
        if (fields.length < 5) {
          return null;
        }
        return {
          recordIndex: index,
          guid: fields[0],
          name: fields[1],
          attributes: fields[2] ? Number.parseInt(fields[2], 0) : null,
          sizeBytes: fields[3] ? Number.parseInt(fields[3], 10) : null,
          dataHex: fields[4] || null,
        };
      })
      .filter(Boolean);
  }

  return splitLines(payloadText)
    .map((line, index) => {
      const match = /guid=(.*?)\s+name=(.*?)\s+attributes=(.*?)\s+size=(.*?)\s+data_hex=(.*)$/.exec(line);
      if (!match) {
        return null;
      }
      return {
        recordIndex: index,
        guid: match[1],
        name: match[2],
        attributes: Number.parseInt(match[3], 0),
        sizeBytes: Number.parseInt(match[4], 10),
        dataHex: match[5] || null,
      };
    })
    .filter(Boolean);
}

function extractRawJson(contentType, payloadText) {
  if (contentType === 'application/json') {
    return parseJsonValue(payloadText);
  }
  if (contentType === 'application/x-ndjson') {
    const rows = parseNdjson(payloadText);
    return rows.length ? rows : null;
  }
  return null;
}

function normalizeStructuredLogRows(rows) {
  const events = [];
  const ubootEnvCandidates = [];
  const ubootEnvVariables = [];

  rows.forEach((row, index) => {
    const recordType = typeof row.record === 'string' ? row.record : 'log';

    if (recordType === 'env_candidate' || recordType === 'redundant_pair') {
      ubootEnvCandidates.push({
        recordIndex: index,
        recordType,
        device: row.device || null,
        offset: row.offset ?? null,
        crcEndian: row.crc_endian || null,
        mode: row.mode || null,
        hasKnownVars: row.has_known_vars ?? null,
        cfgOffset: row.cfg_offset ?? null,
        envSize: row.env_size ?? null,
        eraseSize: row.erase_size ?? null,
        sectorCount: row.sector_count ?? null,
        pairOffset: row.pair_offset ?? row.cfg_offset ?? null,
      });
      return;
    }

    if (recordType === 'env_vars' && Array.isArray(row.vars)) {
      row.vars.forEach((entry, envIndex) => {
        if (!entry || typeof entry.key !== 'string') {
          return;
        }
        ubootEnvVariables.push({
          recordIndex: (index * 1000) + envIndex,
          device: row.device || null,
          offset: row.offset ?? null,
          key: entry.key,
          value: entry.value ?? null,
        });
      });
      return;
    }

    events.push({
      recordIndex: index,
      eventType: recordType,
      message: row.message ?? row.value ?? null,
      phase: row.phase ?? null,
      command: row.command ?? null,
      rc: Number.isInteger(row.rc) ? row.rc : null,
      mode: row.mode ?? null,
      romPath: row.rom_path ?? null,
      sizeBytes: row.size ?? null,
      metadata: row,
    });
  });

  return { events, ubootEnvCandidates, ubootEnvVariables };
}

function normalizeUpload(input) {
  const payloadText = input.payloadText || null;
  const rawJson = payloadText ? extractRawJson(input.contentType, payloadText) : null;
  const result = {
    upload: {
      payloadText,
      payloadJson: rawJson,
    },
    commandUpload: null,
    fileListEntries: [],
    symlinkListEntries: [],
    efiVariables: [],
    ubootEnvCandidates: [],
    ubootEnvVariables: [],
    logEvents: [],
  };

  if (!payloadText) {
    return result;
  }

  if (input.uploadType === 'cmd') {
    result.commandUpload = parseCommandUpload(input.contentType, payloadText);
  }

  if (input.uploadType === 'file-list') {
    result.fileListEntries = parseFileListEntries(payloadText, input.requestFilePath);
  }

  if (input.uploadType === 'symlink-list') {
    result.symlinkListEntries = parseSymlinkListEntries(input.contentType, payloadText, input.requestFilePath);
  }

  if (input.uploadType === 'efi-vars') {
    result.efiVariables = parseEfiVariables(input.contentType, payloadText);
  }

  if (input.contentType === 'application/x-ndjson') {
    const rows = parseNdjson(payloadText);
    const structured = normalizeStructuredLogRows(rows);
    result.logEvents = structured.events;
    result.ubootEnvCandidates = structured.ubootEnvCandidates;
    result.ubootEnvVariables = structured.ubootEnvVariables;

    if (input.uploadType === 'dmesg' && result.logEvents.length === 0) {
      result.logEvents = rows.map((row, index) => ({
        recordIndex: index,
        eventType: row.record || 'dmesg',
        message: row.message || null,
        metadata: row,
      }));
    }
  } else if (['log', 'logs', 'dmesg', 'orom', 'uboot-image', 'uboot-environment'].includes(input.uploadType)) {
    result.logEvents = splitLines(payloadText).map((line, index) => ({
      recordIndex: index,
      eventType: input.uploadType,
      message: line,
      metadata: null,
    }));
  }

  return result;
}

module.exports = {
  normalizeUpload,
};
