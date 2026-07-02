function listBinaryEntries(assetsDir, fsp, releaseStateFile) {
  return fsp.readdir(assetsDir, { withFileTypes: true }).catch(() => []).then((entries) => entries
    .filter((entry) => entry.isFile()
      && entry.name !== releaseStateFile
      && entry.name !== '.release_state.json'
      && !entry.name.startsWith('.release_state'))
    .map((entry) => {
      const isa = entry.name.startsWith('ela-')
        ? entry.name.slice('ela-'.length)
        : entry.name.startsWith('embedded_linux_audit-')
        ? entry.name.slice('embedded_linux_audit-'.length)
        : entry.name;
      // No `url` here: the download route is /isa/<token>/<isa>, and the token
      // is not known to the server (only its hash), so a working link cannot be
      // generated. Callers render the usage pattern instead.
      return {
        isa,
        fileName: entry.name
      };
    })
    .sort((a, b) => a.isa.localeCompare(b.isa)));
}

function isSafeSinglePathSegment(value) {
  if (typeof value !== 'string' || !value) {
    return false;
  }

  if (value.includes('/') || value.includes('\\')) {
    return false;
  }

  if (value === '.' || value === '..' || value.includes('..')) {
    return false;
  }

  return true;
}

function isSafeRelativePath(value) {
  if (typeof value !== 'string' || !value) {
    return false;
  }

  if (value.includes('\\')) {
    return false;
  }

  const normalized = value.split('/');
  if (normalized.some((segment) => !isSafeSinglePathSegment(segment))) {
    return false;
  }

  return true;
}

module.exports = {
  listBinaryEntries,
  isSafeSinglePathSegment,
  isSafeRelativePath
};