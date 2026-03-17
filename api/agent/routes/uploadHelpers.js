'use strict';

function uploadDirectoryForType(path, baseDir, uploadType) {
  switch (uploadType) {
    case 'log':
    case 'logs':
      return path.join(baseDir, 'logs');
    case 'dmesg':
      return path.join(baseDir, 'dmesg');
    case 'cmd':
      return path.join(baseDir, 'cmd');
    case 'efi-vars':
      return path.join(baseDir, 'efi-vars');
    case 'file-list':
      return path.join(baseDir, 'file-list');
    case 'symlink-list':
      return path.join(baseDir, 'symlink-list');
    case 'orom':
      return path.join(baseDir, 'orom');
    case 'uboot-image':
      return path.join(baseDir, 'uboot', 'image');
    case 'uboot-environment':
      return path.join(baseDir, 'uboot', 'env');
    default:
      return path.join(baseDir, uploadType);
  }
}

function logFilePrefixForUploadType(path, targetDir, uploadType, now = new Date()) {
  const timestamp = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z');
  switch (uploadType) {
    case 'log':
    case 'logs':
      return path.join(targetDir, `log.${timestamp}`);
    case 'dmesg':
      return path.join(targetDir, `dmesg.${timestamp}`);
    case 'cmd':
      return path.join(targetDir, `cmd.${timestamp}`);
    case 'efi-vars':
      return path.join(targetDir, `efi-vars.${timestamp}`);
    default:
      return path.join(targetDir, uploadType);
  }
}

function sanitizeFileListPath(path, filePath) {
  if (!filePath || typeof filePath !== 'string') {
    return null;
  }

  const normalized = path.posix.normalize(filePath.replace(/\\/g, '/'));
  if (!normalized.startsWith('/')) {
    return null;
  }

  if (normalized === '/..' || normalized.startsWith('/../') || normalized.includes('/../')) {
    return null;
  }

  return normalized;
}

function fileListNameForPath(filePath, now = new Date()) {
  const timestamp = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z');
  if (filePath === '/') {
    return `root-fs_${timestamp}`;
  }

  const stripped = filePath.replace(/^\/+/, '');
  return (stripped ? stripped.replace(/\//g, '-') : 'root') + `_${timestamp}`;
}

module.exports = {
  uploadDirectoryForType,
  logFilePrefixForUploadType,
  sanitizeFileListPath,
  fileListNameForPath,
};
