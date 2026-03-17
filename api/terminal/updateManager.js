'use strict';

function buildIsaString(isa, endianness) {
  if (isa === 'x86_64' || isa === 'x86' || isa === 'riscv32' || isa === 'riscv64') {
    return isa;
  }
  return `${isa}-${endianness === 'big' ? 'be' : 'le'}`;
}

function deriveUpdateBaseUrl(apiUrl) {
  const trimmed = String(apiUrl || '').trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }

  if (trimmed.endsWith('/upload')) {
    return trimmed.slice(0, -'/upload'.length) || null;
  }

  return trimmed;
}

function startSessionUpdate(entry) {
  if (entry.updateCtx) {
    return false;
  }

  entry.updateCtx = {
    state: 'await-api-url',
    apiUrl: null,
    updateBaseUrl: null,
    isa: null,
    buffer: '',
  };
  entry.updateStatus = 'updating';
  if (entry.ws.readyState === entry.ws.OPEN) {
    entry.ws.send('\x15');
    entry.ws.send('linux execute-command "echo \\"[ELA_API_URL_BEGIN]$ELA_API_URL[ELA_API_URL_END]\\""\n');
  }
  return true;
}

function handleUpdateMessage(entry, text, {
  onUpdateComplete = () => {},
  onUpdateFailed = () => {},
} = {}) {
  const ctx = entry.updateCtx;
  if (!ctx) {
    return;
  }

  ctx.buffer += text;

  if (ctx.state === 'await-api-url') {
    const start = ctx.buffer.indexOf('[ELA_API_URL_BEGIN]');
    const end = ctx.buffer.indexOf('[ELA_API_URL_END]');
    if (start < 0 || end < 0 || end <= start) {
      return;
    }

    ctx.apiUrl = ctx.buffer.slice(start + '[ELA_API_URL_BEGIN]'.length, end).trim();
    ctx.updateBaseUrl = deriveUpdateBaseUrl(ctx.apiUrl);
    if (!ctx.updateBaseUrl) {
      entry.updateCtx = null;
      entry.updateStatus = 'failed';
      onUpdateFailed(entry);
      return;
    }

    ctx.buffer = '';
    ctx.state = 'await-isa';
    if (entry.ws.readyState === entry.ws.OPEN) {
      entry.ws.send('--output-format json arch isa\n');
    }
    return;
  }

  if (ctx.state === 'await-isa') {
    const match = ctx.buffer.match(/\{"record":"arch"[^}]+\}/);
    if (!match) {
      return;
    }

    try {
      const obj = JSON.parse(match[0]);
      if (obj.subcommand !== 'isa' || !obj.value) {
        return;
      }
      ctx.isa = obj.value;
    } catch {
      return;
    }

    ctx.buffer = '';
    ctx.state = 'await-endianness';
    if (entry.ws.readyState === entry.ws.OPEN) {
      entry.ws.send('--output-format json arch endianness\n');
    }
    return;
  }

  if (ctx.state === 'await-endianness') {
    const match = ctx.buffer.match(/\{"record":"arch"[^}]+\}/);
    if (!match) {
      return;
    }

    let endianness;
    try {
      const obj = JSON.parse(match[0]);
      if (obj.subcommand !== 'endianness' || !obj.value) {
        return;
      }
      endianness = obj.value;
    } catch {
      return;
    }

    const isaString = buildIsaString(ctx.isa, endianness);
    ctx.buffer = '';
    ctx.state = 'in-progress';
    if (entry.ws.readyState === entry.ws.OPEN) {
      const downloadCommand = `linux download-file ${ctx.updateBaseUrl}/isa/${isaString} /tmp/ela.new\n`;
      const moveCommand = 'linux execute-command ' +
        '"chmod +x /tmp/ela.new && ' +
        'mv /tmp/ela.new $(readlink -f /proc/self/exe) && ' +
        'echo [UPDATE OK] || echo [UPDATE FAILED]"\n';
      entry.ws.send(downloadCommand + moveCommand);
    }
    return;
  }

  if (ctx.state === 'in-progress') {
    if (text.includes('[UPDATE OK]')) {
      entry.updateCtx = null;
      entry.updateStatus = 'ok';
      onUpdateComplete(entry);
      return;
    }

    if (text.includes('[UPDATE FAILED]')) {
      entry.updateCtx = null;
      entry.updateStatus = 'failed';
      onUpdateFailed(entry);
    }
  }
}

module.exports = {
  buildIsaString,
  deriveUpdateBaseUrl,
  startSessionUpdate,
  handleUpdateMessage,
};
