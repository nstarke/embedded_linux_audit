'use strict';

const { normalizeUpload } = require('../../../../api/lib/db/normalizeUpload');

describe('normalizeUpload', () => {
  // ── normalizeUpload top-level ────────────────────────────────────────────

  test('returns empty result when payloadText is absent', () => {
    const result = normalizeUpload({ uploadType: 'cmd', contentType: 'text/plain' });
    expect(result.commandUpload).toBeNull();
    expect(result.archReport).toBeNull();
    expect(result.fileListEntries).toEqual([]);
    expect(result.grepMatches).toEqual([]);
    expect(result.symlinkListEntries).toEqual([]);
    expect(result.efiVariables).toEqual([]);
    expect(result.logEvents).toEqual([]);
    expect(result.upload.payloadText).toBeNull();
  });

  test('sets payloadText and payloadJson on the upload object', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'application/json',
      payloadText: '{"record":"arch","subcommand":"isa","value":"x86_64"}',
    });
    expect(result.upload.payloadText).toContain('arch');
    expect(result.upload.payloadJson).toMatchObject({ record: 'arch' });
  });

  test('sets payloadJson to null for non-JSON content types', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'text/plain',
      payloadText: 'line one\n',
    });
    expect(result.upload.payloadJson).toBeNull();
  });

  // ── parseCommandUpload ───────────────────────────────────────────────────

  test('normalizes cmd text/plain payloads with output', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/plain',
      payloadText: 'uname -a\nLinux hostname 5.15.0\n',
    });
    expect(result.commandUpload).toEqual({
      commandText: 'uname -a',
      commandOutput: 'Linux hostname 5.15.0',
      commandFormat: 'txt',
    });
  });

  test('normalizes cmd text/plain payload with no output lines', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/plain',
      payloadText: 'uname -a',
    });
    expect(result.commandUpload).toEqual({
      commandText: 'uname -a',
      commandOutput: null,
      commandFormat: 'txt',
    });
  });

  test('returns null commandUpload for an empty text/plain cmd payload', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/plain',
      payloadText: '\n\n',
    });
    expect(result.commandUpload).toBeNull();
  });

  test('normalizes cmd application/json payloads', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'application/json',
      payloadText: '{"command":"uname -a","output":"Linux hostname"}',
    });
    expect(result.commandUpload).toEqual({
      commandText: 'uname -a',
      commandOutput: 'Linux hostname',
      commandFormat: 'json',
    });
  });

  test('normalizes cmd json payload with no output field', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'application/json',
      payloadText: '{"command":"uname -a"}',
    });
    expect(result.commandUpload).toEqual({
      commandText: 'uname -a',
      commandOutput: null,
      commandFormat: 'json',
    });
  });

  test('returns null commandUpload for json cmd missing the command field', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'application/json',
      payloadText: '{"output":"something"}',
    });
    expect(result.commandUpload).toBeNull();
  });

  test('returns null commandUpload for invalid json cmd payload', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'application/json',
      payloadText: 'not-json',
    });
    expect(result.commandUpload).toBeNull();
  });

  test('normalizes cmd text/csv payloads', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/csv',
      payloadText: 'uname -a,Linux hostname\n',
    });
    expect(result.commandUpload).toEqual({
      commandText: 'uname -a',
      commandOutput: 'Linux hostname',
      commandFormat: 'csv',
    });
  });

  test('returns null commandUpload for csv cmd with only one field', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/csv',
      payloadText: 'uname -a',
    });
    expect(result.commandUpload).toBeNull();
  });

  test('returns null commandUpload for empty csv cmd payload', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/csv',
      payloadText: '\n\n',
    });
    expect(result.commandUpload).toBeNull();
  });

  // ── parseSimpleCsvLine (via cmd/arch/efi-vars text/csv) ─────────────────

  test('handles quoted fields in csv cmd payloads', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/csv',
      payloadText: '"uname,-a","Linux hostname"\n',
    });
    expect(result.commandUpload).toMatchObject({
      commandText: 'uname,-a',
      commandOutput: 'Linux hostname',
    });
  });

  test('handles escaped double-quotes in csv fields', () => {
    const result = normalizeUpload({
      uploadType: 'cmd',
      contentType: 'text/csv',
      payloadText: '"say ""hello""",output\n',
    });
    expect(result.commandUpload.commandText).toBe('say "hello"');
  });

  // ── parseArchReport ──────────────────────────────────────────────────────

  test('normalizes arch json payloads', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'application/json',
      payloadText: '{"record":"arch","subcommand":"isa","value":"x86_64"}',
    });
    expect(result.archReport).toEqual({ subcommand: 'isa', value: 'x86_64' });
  });

  test('normalizes arch text/plain payloads', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'text/plain',
      payloadText: 'x86_64\n',
    });
    expect(result.archReport).toEqual({ subcommand: null, value: 'x86_64' });
  });

  test('normalizes arch text/csv payloads', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'text/csv',
      payloadText: 'x86_64\n',
    });
    expect(result.archReport).toEqual({ subcommand: null, value: 'x86_64' });
  });

  test('returns null archReport for an empty arch payload', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'text/plain',
      payloadText: '\n\n',
    });
    expect(result.archReport).toBeNull();
  });

  test('returns null archReport for json with wrong record type', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'application/json',
      payloadText: '{"record":"other","value":"x86_64"}',
    });
    expect(result.archReport).toBeNull();
  });

  test('returns null for arch json subcommand/value when they are not strings', () => {
    const result = normalizeUpload({
      uploadType: 'arch',
      contentType: 'application/json',
      payloadText: '{"record":"arch","subcommand":42,"value":null}',
    });
    expect(result.archReport).toEqual({ subcommand: null, value: null });
  });

  // ── parseFileListEntries ─────────────────────────────────────────────────

  test('normalizes file-list payloads with a rootPath', () => {
    const result = normalizeUpload({
      uploadType: 'file-list',
      contentType: 'text/plain',
      payloadText: '/etc/passwd\n/etc/group\n',
      requestFilePath: '/etc',
    });
    expect(result.fileListEntries).toEqual([
      { recordIndex: 0, rootPath: '/etc', entryPath: '/etc/passwd' },
      { recordIndex: 1, rootPath: '/etc', entryPath: '/etc/group' },
    ]);
  });

  test('sets rootPath to null when requestFilePath is absent', () => {
    const result = normalizeUpload({
      uploadType: 'file-list',
      contentType: 'text/plain',
      payloadText: '/etc/passwd\n',
    });
    expect(result.fileListEntries[0].rootPath).toBeNull();
  });

  test('returns empty fileListEntries for an empty payload', () => {
    const result = normalizeUpload({
      uploadType: 'file-list',
      contentType: 'text/plain',
      payloadText: '\n',
    });
    expect(result.fileListEntries).toEqual([]);
  });

  // ── parseGrepMatches ─────────────────────────────────────────────────────

  test('normalizes grep text payloads', () => {
    const result = normalizeUpload({
      uploadType: 'grep',
      contentType: 'text/plain',
      requestFilePath: '/etc',
      payloadText: '/etc/passwd:1:root\n/etc/group:2:daemon',
    });
    expect(result.grepMatches).toHaveLength(2);
    expect(result.grepMatches[0]).toEqual({
      recordIndex: 0,
      rootPath: '/etc',
      filePath: '/etc/passwd',
      lineNumber: 1,
      lineText: 'root',
    });
  });

  test('filters out grep lines that do not match the expected format', () => {
    const result = normalizeUpload({
      uploadType: 'grep',
      contentType: 'text/plain',
      payloadText: '/etc/passwd:1:root\nnot-a-match-line\n',
      requestFilePath: '/etc',
    });
    expect(result.grepMatches).toHaveLength(1);
  });

  test('sets rootPath to null when requestFilePath is absent for grep', () => {
    const result = normalizeUpload({
      uploadType: 'grep',
      contentType: 'text/plain',
      payloadText: '/etc/passwd:1:root\n',
    });
    expect(result.grepMatches[0].rootPath).toBeNull();
  });

  // ── parseSymlinkListEntries ──────────────────────────────────────────────

  test('normalizes symlink-list ndjson payloads', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'application/x-ndjson',
      payloadText: '{"link_path":"/usr/bin/python","location_path":"/usr/bin/python3"}\n',
      requestFilePath: '/',
    });
    expect(result.symlinkListEntries).toEqual([{
      recordIndex: 0,
      rootPath: '/',
      linkPath: '/usr/bin/python',
      targetPath: '/usr/bin/python3',
    }]);
  });

  test('filters out ndjson symlink entries without link_path', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'application/x-ndjson',
      payloadText: '{"location_path":"/target"}\n',
    });
    expect(result.symlinkListEntries).toEqual([]);
  });

  test('sets targetPath to null when location_path is absent in ndjson symlink', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'application/x-ndjson',
      payloadText: '{"link_path":"/usr/bin/python"}\n',
    });
    expect(result.symlinkListEntries[0].targetPath).toBeNull();
  });

  test('returns empty symlinkListEntries when ndjson contains a non-object line', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'application/x-ndjson',
      payloadText: '{"link_path":"a"}\n[1,2,3]\n',
    });
    expect(result.symlinkListEntries).toEqual([]);
  });

  test('normalizes symlink-list text/plain payloads', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'text/plain',
      payloadText: '/usr/bin/python -> /usr/bin/python3\n',
      requestFilePath: '/',
    });
    expect(result.symlinkListEntries).toEqual([{
      recordIndex: 0,
      rootPath: '/',
      linkPath: '/usr/bin/python',
      targetPath: '/usr/bin/python3',
    }]);
  });

  test('filters out symlink-list text/plain lines not matching the arrow format', () => {
    const result = normalizeUpload({
      uploadType: 'symlink-list',
      contentType: 'text/plain',
      payloadText: 'not-a-symlink\n/usr/bin/python -> /usr/bin/python3\n',
    });
    expect(result.symlinkListEntries).toHaveLength(1);
  });

  // ── parseEfiVariables ────────────────────────────────────────────────────

  test('normalizes efi-vars ndjson payloads', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"efi_var","guid":"8be4df61","name":"BootOrder","attributes":7,"size":4,"data_hex":"0100"}\n',
    });
    expect(result.efiVariables).toHaveLength(1);
    expect(result.efiVariables[0]).toMatchObject({
      recordIndex: 0,
      guid: '8be4df61',
      name: 'BootOrder',
      attributes: 7,
      sizeBytes: 4,
      dataHex: '0100',
    });
  });

  test('filters out efi-vars ndjson entries with the wrong record type', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"other","guid":"g","name":"n"}\n',
    });
    expect(result.efiVariables).toEqual([]);
  });

  test('filters out efi-vars ndjson entries missing guid or name', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"efi_var","name":"n"}\n',
    });
    expect(result.efiVariables).toEqual([]);
  });

  test('sets optional efi-vars ndjson fields to null when absent', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"efi_var","guid":"g","name":"n"}\n',
    });
    expect(result.efiVariables[0]).toMatchObject({
      attributes: null,
      sizeBytes: null,
      dataHex: null,
    });
  });

  test('normalizes efi-vars text/csv payloads', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/csv',
      payloadText: '8be4df61,BootOrder,7,4,0100\n',
    });
    expect(result.efiVariables).toHaveLength(1);
    expect(result.efiVariables[0]).toMatchObject({
      guid: '8be4df61',
      name: 'BootOrder',
      attributes: 7,
      sizeBytes: 4,
      dataHex: '0100',
    });
  });

  test('filters out efi-vars csv lines with fewer than 5 fields', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/csv',
      payloadText: 'g,n,7,4\n',
    });
    expect(result.efiVariables).toEqual([]);
  });

  test('sets efi-vars csv optional fields to null when empty', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/csv',
      payloadText: 'g,n,,,\n',
    });
    expect(result.efiVariables[0]).toMatchObject({
      attributes: null,
      sizeBytes: null,
      dataHex: null,
    });
  });

  test('normalizes efi-vars text/plain payloads', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/plain',
      payloadText: 'guid=8be4df61 name=BootOrder attributes=0x7 size=4 data_hex=0100\n',
    });
    expect(result.efiVariables).toHaveLength(1);
    expect(result.efiVariables[0]).toMatchObject({
      guid: '8be4df61',
      name: 'BootOrder',
    });
  });

  test('filters out efi-vars text/plain lines that do not match the expected format', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/plain',
      payloadText: 'not-a-valid-efi-line\n',
    });
    expect(result.efiVariables).toEqual([]);
  });

  test('sets efi-vars text/plain data_hex to null when absent', () => {
    const result = normalizeUpload({
      uploadType: 'efi-vars',
      contentType: 'text/plain',
      payloadText: 'guid=g name=n attributes=0x7 size=4 data_hex=\n',
    });
    expect(result.efiVariables[0].dataHex).toBeNull();
  });

  // ── application/x-ndjson → normalizeStructuredLogRows ───────────────────

  test('parses ndjson and produces log events for generic records', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"log","message":"booting","phase":"init","command":"cmd","rc":0,"mode":"normal","rom_path":"/rom","size":1024}\n',
    });
    expect(result.logEvents).toHaveLength(1);
    expect(result.logEvents[0]).toMatchObject({
      recordIndex: 0,
      eventType: 'log',
      message: 'booting',
      phase: 'init',
      command: 'cmd',
      rc: 0,
      mode: 'normal',
      romPath: '/rom',
      sizeBytes: 1024,
    });
  });

  test('uses value as message when message field is absent', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"log","value":"fallback"}\n',
    });
    expect(result.logEvents[0].message).toBe('fallback');
  });

  test('sets rc to null when it is not an integer', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"log","rc":"oops"}\n',
    });
    expect(result.logEvents[0].rc).toBeNull();
  });

  test('defaults record type to "log" when the record field is absent', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '{"message":"no record field"}\n',
    });
    expect(result.logEvents[0].eventType).toBe('log');
  });

  test('extracts env_candidate records into ubootEnvCandidates', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_candidate","device":"/dev/mtd0","offset":0,"crc_endian":"little","mode":"raw","has_known_vars":true,"cfg_offset":4096,"env_size":8192,"erase_size":65536,"sector_count":2,"pair_offset":131072}\n',
    });
    expect(result.ubootEnvCandidates).toHaveLength(1);
    expect(result.ubootEnvCandidates[0]).toMatchObject({
      recordIndex: 0,
      recordType: 'env_candidate',
      device: '/dev/mtd0',
      offset: 0,
      crcEndian: 'little',
      mode: 'raw',
      hasKnownVars: true,
      cfgOffset: 4096,
      envSize: 8192,
      eraseSize: 65536,
      sectorCount: 2,
      pairOffset: 131072,
    });
  });

  test('falls back to cfg_offset for pairOffset when pair_offset is absent', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_candidate","cfg_offset":4096}\n',
    });
    expect(result.ubootEnvCandidates[0].pairOffset).toBe(4096);
  });

  test('sets pairOffset to null when both pair_offset and cfg_offset are absent', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_candidate"}\n',
    });
    expect(result.ubootEnvCandidates[0].pairOffset).toBeNull();
  });

  test('extracts redundant_pair records into ubootEnvCandidates', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"redundant_pair","device":"/dev/mtd1"}\n',
    });
    expect(result.ubootEnvCandidates[0].recordType).toBe('redundant_pair');
  });

  test('extracts env_vars records into ubootEnvVariables', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_vars","device":"/dev/mtd0","offset":0,"vars":[{"key":"bootcmd","value":"run dist_boot"},{"key":"baudrate","value":"115200"}]}\n',
    });
    expect(result.ubootEnvVariables).toHaveLength(2);
    expect(result.ubootEnvVariables[0]).toMatchObject({
      key: 'bootcmd',
      value: 'run dist_boot',
      device: '/dev/mtd0',
      offset: 0,
    });
  });

  test('filters out env_vars entries without a string key', () => {
    const result = normalizeUpload({
      uploadType: 'uboot-environment',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_vars","vars":[{"value":"no-key"},{"key":"valid","value":"ok"}]}\n',
    });
    expect(result.ubootEnvVariables).toHaveLength(1);
    expect(result.ubootEnvVariables[0].key).toBe('valid');
  });

  test('sets payloadJson for application/x-ndjson uploads', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"log","message":"boot"}\n',
    });
    expect(Array.isArray(result.upload.payloadJson)).toBe(true);
  });

  test('sets payloadJson to null when ndjson produces no rows', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'application/x-ndjson',
      payloadText: '\n',
    });
    expect(result.upload.payloadJson).toBeNull();
  });

  // ── dmesg fallback (logEvents empty after structured parsing) ────────────

  test('falls back to row-level dmesg events when structured log produces no events', () => {
    const result = normalizeUpload({
      uploadType: 'dmesg',
      contentType: 'application/x-ndjson',
      // env_candidate goes to ubootEnvCandidates, leaving logEvents empty
      payloadText: '{"record":"env_candidate","device":"/dev/mtd0"}\n',
    });
    expect(result.logEvents).toHaveLength(1);
    expect(result.logEvents[0]).toMatchObject({
      recordIndex: 0,
      eventType: 'env_candidate',
      message: null,
    });
  });

  test('uses dmesg row message field in fallback events', () => {
    const result = normalizeUpload({
      uploadType: 'dmesg',
      contentType: 'application/x-ndjson',
      payloadText: '{"record":"env_candidate","message":"something"}\n',
    });
    expect(result.logEvents[0].message).toBe('something');
  });

  // ── plain-text log upload types ──────────────────────────────────────────

  test('normalizes log upload as plain text lines', () => {
    const result = normalizeUpload({
      uploadType: 'log',
      contentType: 'text/plain',
      payloadText: 'line one\nline two\n',
    });
    expect(result.logEvents).toEqual([
      { recordIndex: 0, eventType: 'log', message: 'line one', metadata: null },
      { recordIndex: 1, eventType: 'log', message: 'line two', metadata: null },
    ]);
  });

  test('normalizes dmesg upload as plain text lines', () => {
    const result = normalizeUpload({
      uploadType: 'dmesg',
      contentType: 'text/plain',
      payloadText: '[0.000000] Booting Linux\n',
    });
    expect(result.logEvents[0]).toMatchObject({
      eventType: 'dmesg',
      message: '[0.000000] Booting Linux',
      metadata: null,
    });
  });

  test('normalizes orom upload as plain text lines', () => {
    const result = normalizeUpload({
      uploadType: 'orom',
      contentType: 'text/plain',
      payloadText: 'Option ROM v1.0\n',
    });
    expect(result.logEvents[0].eventType).toBe('orom');
  });

  test('normalizes tpm2-getcap upload as plain text lines', () => {
    const result = normalizeUpload({
      uploadType: 'tpm2-getcap',
      contentType: 'text/plain',
      payloadText: 'cap output\n',
    });
    expect(result.logEvents[0].eventType).toBe('tpm2-getcap');
  });
});
