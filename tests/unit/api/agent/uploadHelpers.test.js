'use strict';

const path = require('path');
const {
  uploadDirectoryForType,
  logFilePrefixForUploadType,
  sanitizeFileListPath,
  fileListNameForPath,
} = require('../../../../api/agent/routes/uploadHelpers');

describe('upload helpers', () => {
  const now = new Date('2026-03-17T12:34:56.000Z');

  test('maps upload types to expected directories', () => {
    expect(uploadDirectoryForType(path, '/base', 'logs')).toBe('/base/logs');
    expect(uploadDirectoryForType(path, '/base', 'uboot-image')).toBe('/base/uboot/image');
    expect(uploadDirectoryForType(path, '/base', 'arch')).toBe('/base/arch');
  });

  test('creates timestamped log prefixes', () => {
    expect(logFilePrefixForUploadType(path, '/base/logs', 'cmd', now)).toBe('/base/logs/cmd.20260317T123456Z');
  });

  test('validates absolute list paths', () => {
    expect(sanitizeFileListPath(path, '/var/log')).toBe('/var/log');
    expect(sanitizeFileListPath(path, 'relative')).toBeNull();
  });

  test('generates stable file list names', () => {
    expect(fileListNameForPath('/', now)).toBe('root-fs_20260317T123456Z');
    expect(fileListNameForPath('/var/log/messages', now)).toBe('var-log-messages_20260317T123456Z');
  });
});
