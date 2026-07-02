'use strict';

const { getModels, getSequelize } = require('./index');

// Canonicalize a MAC to lowercase dash-separated form (`20-4c-03-32-75-5c`).
// The agent identifies itself with `:` on the upload path but `-` on the
// terminal/WebSocket path, and Device rows are keyed by this exact string.
// Without canonicalization those two spellings create two separate Device rows,
// so an upload (colon) and the user↔device association made on phone-home (dash)
// never line up and the artifact is invisible in /uploads. Dash form is chosen
// because the terminal session registry, client routing, and existing
// associations already use it, so uploads converge onto the associated device.
function normalizeMac(macAddress) {
  if (macAddress == null) return macAddress;
  const hex = String(macAddress).toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return String(macAddress).toLowerCase();
  return hex.match(/.{2}/g).join('-');
}

async function ensureDevice(macAddress, transaction, seenAt = new Date()) {
  const { Device } = getModels();
  const mac = normalizeMac(macAddress);
  const [device] = await Device.findOrCreate({
    where: { macAddress: mac },
    defaults: {
      macAddress: mac,
      firstSeenAt: seenAt,
      lastSeenAt: seenAt,
    },
    transaction,
  });

  if (device.lastSeenAt < seenAt) {
    device.lastSeenAt = seenAt;
    await device.save({ transaction });
  }

  return device;
}

async function getDeviceAlias(macAddress) {
  const { Device, DeviceAlias } = getModels();
  const device = await Device.findOne({
    where: { macAddress: normalizeMac(macAddress) },
    include: [{ model: DeviceAlias }],
  });

  if (!device || !device.DeviceAlias) {
    return null;
  }

  return device.DeviceAlias.alias;
}

async function setDeviceAlias(macAddress, alias, source = 'terminal_api') {
  const sequelize = getSequelize();
  const { DeviceAlias } = getModels();

  return sequelize.transaction(async (transaction) => {
    const device = await ensureDevice(macAddress, transaction, new Date());
    const existing = await DeviceAlias.findOne({
      where: { deviceId: device.id },
      transaction,
    });

    if (!alias) {
      if (existing) {
        if (existing.group != null) {
          existing.alias = null;
          existing.source = source;
          await existing.save({ transaction });
        } else {
          await existing.destroy({ transaction });
        }
      }
      return null;
    }

    if (existing) {
      existing.alias = alias;
      existing.source = source;
      await existing.save({ transaction });
      return existing.alias;
    }

    const created = await DeviceAlias.create({
      deviceId: device.id,
      alias,
      source,
    }, { transaction });
    return created.alias;
  });
}

async function setDeviceGroup(macAddress, group) {
  const sequelize = getSequelize();
  const { DeviceAlias } = getModels();

  return sequelize.transaction(async (transaction) => {
    const device = await ensureDevice(macAddress, transaction, new Date());
    const existing = await DeviceAlias.findOne({
      where: { deviceId: device.id },
      transaction,
    });

    if (group == null) {
      if (existing) {
        if (existing.alias != null) {
          existing.group = null;
          await existing.save({ transaction });
        } else {
          await existing.destroy({ transaction });
        }
      }
      return null;
    }

    if (existing) {
      existing.group = group;
      await existing.save({ transaction });
      return existing.group;
    }

    const created = await DeviceAlias.create({
      deviceId: device.id,
      group,
    }, { transaction });
    return created.group;
  });
}

async function addBlockedRemote(cidr) {
  const { BlockedRemote } = getModels();
  const [, created] = await BlockedRemote.findOrCreate({
    where: { cidr },
    defaults: { cidr },
  });
  return created;
}

async function getBlockedRemotes() {
  const { BlockedRemote } = getModels();
  return BlockedRemote.findAll();
}

async function deleteDeviceAliasByGroupAndName(group, name) {
  const { DeviceAlias } = getModels();
  const record = await DeviceAlias.findOne({
    where: { alias: name, group },
  });
  if (!record) return false;
  record.alias = null;
  await record.save();
  return true;
}

// Link a user to a device (idempotent). The client API uses these associations
// to decide which devices' artifacts a user may see.
async function associateUserDevice(userId, deviceId, transaction = undefined) {
  const { UserDevice } = getModels();
  const [link, created] = await UserDevice.findOrCreate({
    where: { userId, deviceId },
    defaults: { userId, deviceId },
    transaction,
  });
  if (!created) {
    link.changed('updatedAt', true); // touch last-associated time
    await link.save({ transaction });
  }
  return { link, created };
}

// Return true iff `username` resolves to a user associated (via user_devices)
// with the device identified by `macAddress`. Used by the gdb bridge to gate
// the operator (out) side to users associated with the device on the agent
// (in) side. Returns false for missing/unknown inputs rather than throwing.
async function isUserAssociatedWithDevice(username, macAddress) {
  if (!username || !macAddress) return false;
  const { User, Device, UserDevice } = getModels();
  const user = await User.findOne({ where: { username } });
  if (!user) return false;
  const device = await Device.findOne({ where: { macAddress: normalizeMac(macAddress) } });
  if (!device) return false;
  const link = await UserDevice.findOne({
    where: { userId: user.id, deviceId: device.id },
  });
  return link !== null;
}

// Return the MAC addresses of every device `username` is associated with (via
// user_devices). Used by the terminal API to expose only a user's own devices.
// Returns [] for a missing/unknown user.
async function listUserDeviceMacs(username) {
  if (!username) return [];
  const { User, Device, UserDevice } = getModels();
  const user = await User.findOne({ where: { username } });
  if (!user) return [];
  const links = await UserDevice.findAll({
    where: { userId: user.id },
    include: [{ model: Device, attributes: ['macAddress'] }],
  });
  return links
    .map((link) => link.Device && link.Device.macAddress)
    .filter((mac) => typeof mac === 'string' && mac.length > 0);
}

// Audit-log one operator command issued through the client API. Resolves the
// username → user and the MAC → device (best effort; both may be null) and
// inserts a command_logs row. Never throws to the caller — logging failures must
// not fail the command.
async function recordCommandLog({ username, macAddress, commandType, command, status = null }) {
  const { User, Device, CommandLog } = getModels();
  const mac = macAddress ? normalizeMac(macAddress) : null;
  const user = username ? await User.findOne({ where: { username } }) : null;
  const device = mac ? await Device.findOne({ where: { macAddress: mac } }) : null;
  await CommandLog.create({
    userId: user ? user.id : null,
    deviceId: device ? device.id : null,
    macAddress: mac || null,
    commandType,
    command,
    status,
  });
}

async function recordTerminalConnection(macAddress, remoteAddress, authenticatedUser = null) {
  const sequelize = getSequelize();
  const { DeviceAlias, TerminalConnection, User } = getModels();

  return sequelize.transaction(async (transaction) => {
    const device = await ensureDevice(macAddress, transaction, new Date());
    let aliasRecord = await DeviceAlias.findOne({
      where: { deviceId: device.id },
      transaction,
    });

    // Initialize group on first connection. Prefer the authenticated username
    // (derived from the API key) so that devices are grouped under their owner;
    // fall back to the source IP when auth is not enforced.
    const initialGroup = authenticatedUser || remoteAddress;
    if (initialGroup && (!aliasRecord || aliasRecord.group == null)) {
      if (aliasRecord) {
        aliasRecord.group = initialGroup;
        await aliasRecord.save({ transaction });
      } else {
        aliasRecord = await DeviceAlias.create({
          deviceId: device.id,
          group: initialGroup,
        }, { transaction });
      }
    }

    // Associate the authenticated user (from the agent's API key) with this
    // device, so the user's client token can later read its artifacts. Skipped
    // when auth is open (no resolved user) or the username is unknown.
    if (authenticatedUser) {
      const user = await User.findOne({ where: { username: authenticatedUser }, transaction });
      if (user) {
        await associateUserDevice(user.id, device.id, transaction);
      }
    }

    const connection = await TerminalConnection.create({
      deviceId: device.id,
      remoteAddress: remoteAddress || null,
      connectedAt: new Date(),
    }, { transaction });

    return {
      connectionId: connection.id,
      alias: aliasRecord ? aliasRecord.alias : null,
      group: aliasRecord ? aliasRecord.group : null,
    };
  });
}

async function touchTerminalHeartbeat(connectionId, heartbeatAt = new Date()) {
  const { TerminalConnection } = getModels();
  await TerminalConnection.update({
    lastHeartbeatAt: heartbeatAt,
  }, {
    where: { id: connectionId },
  });
}

async function closeTerminalConnection(connectionId, disconnectedAt = new Date()) {
  const { TerminalConnection } = getModels();
  await TerminalConnection.update({
    disconnectedAt,
  }, {
    where: { id: connectionId },
  });
}

async function loadApiKeyHashes(scope) {
  const { ApiKey, User } = getModels();
  const where = scope ? { scope } : {};
  const keys = await ApiKey.findAll({ where, include: [{ model: User }] });
  return keys.map((k) => ({ keyHash: k.keyHash, username: k.User.username }));
}

async function createUser(username) {
  const { User } = getModels();
  const [user, created] = await User.findOrCreate({
    where: { username },
    defaults: { username },
  });
  return { user, created };
}

async function getUserWithKeys(username) {
  const { User, ApiKey } = getModels();
  const user = await User.findOne({
    where: { username },
    include: [{ model: ApiKey }],
  });
  if (!user) {
    return null;
  }
  return {
    id: user.id,
    username: user.username,
    keys: (user.ApiKeys || []).map((k) => ({ keyHash: k.keyHash, scope: k.scope, label: k.label })),
  };
}

async function deleteUserByUsername(username) {
  const { User } = getModels();
  // The api_keys FK is ON DELETE CASCADE and uploads.user_id is ON DELETE SET
  // NULL, so removing the user row drops its keys and orphans (keeps) its
  // uploads at the database level.
  return User.destroy({ where: { username } });
}

async function createApiKey(username, keyHash, label = null, scope = 'agent') {
  const sequelize = getSequelize();
  const { User, ApiKey } = getModels();
  return sequelize.transaction(async (transaction) => {
    const [user] = await User.findOrCreate({
      where: { username },
      defaults: { username },
      transaction,
    });
    const [key, created] = await ApiKey.findOrCreate({
      where: { keyHash },
      defaults: { userId: user.id, keyHash, label, scope },
      transaction,
    });
    return { key, created };
  });
}

module.exports = {
  normalizeMac,
  ensureDevice,
  getDeviceAlias,
  setDeviceAlias,
  setDeviceGroup,
  deleteDeviceAliasByGroupAndName,
  addBlockedRemote,
  getBlockedRemotes,
  loadApiKeyHashes,
  createUser,
  createApiKey,
  getUserWithKeys,
  deleteUserByUsername,
  associateUserDevice,
  isUserAssociatedWithDevice,
  listUserDeviceMacs,
  recordCommandLog,
  recordTerminalConnection,
  touchTerminalHeartbeat,
  closeTerminalConnection,
};
