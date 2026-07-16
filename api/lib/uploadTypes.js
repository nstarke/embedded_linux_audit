'use strict';

// Canonical set of accepted upload types, shared by the agent API (ingest
// validation) and the client API (read-back route validation).
const VALID_UPLOAD_TYPES = new Set([
  'arch',
  'cmd',
  'coredump',
  'dmesg',
  'efi-vars',
  'file',
  'file-list',
  'grep',
  'kernel-config',
  'linux-audit',
  'log',
  'logs',
  'module-buildinfo',
  'module-vermagic',
  'netstat',
  'orom',
  'pcap',
  'physmem',
  'symlink-list',
  'tpm2-createprimary',
  'tpm2-getcap',
  'tpm2-nvreadpublic',
  'tpm2-pcrread',
  'uboot-image',
  'uboot-environment',
  'wlan-fuzz',
  'eth-fuzz',
  'bt-fuzz',
  'cpu-fuzz',
]);

module.exports = {
  VALID_UPLOAD_TYPES,
};
