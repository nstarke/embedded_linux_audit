'use strict';

function buildIsaString(isa, endianness) {
  if (isa === 'x86_64' || isa === 'x86' || isa === 'riscv32' || isa === 'riscv64') {
    return isa;
  }
  return `${isa}-${endianness === 'big' ? 'be' : 'le'}`;
}

function startSessionUpdate(entry, updateUrl) {
  if (!updateUrl || entry.updateCtx) {
    return false;
  }

  entry.updateCtx = { state: 'await-isa', isa: null, buffer: '' };
  entry.updateStatus = 'updating';
  if (entry.ws.readyState === entry.ws.OPEN) {
    entry.ws.send('\x15');
    entry.ws.send('--output-format json arch isa\n');
  }
  return true;
}

function handleUpdateMessage(entry, text, {
  updateUrl,
  onUpdateComplete = () => {},
  onUpdateFailed = () => {},
} = {}) {
  const ctx = entry.updateCtx;
  if (!ctx) {
    return;
  }

  ctx.buffer += text;

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
      const downloadCommand = `linux download-file ${updateUrl}/isa/${isaString} /tmp/ela.new\n`;
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
  startSessionUpdate,
  handleUpdateMessage,
};
