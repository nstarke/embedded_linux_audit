'use strict';

const { getModels, getSequelize } = require('./index');

async function ensureDevice(macAddress, transaction, seenAt = new Date()) {
  const { Device } = getModels();
  const [device] = await Device.findOrCreate({
    where: { macAddress },
    defaults: {
      macAddress,
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
    where: { macAddress },
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

async function recordTerminalConnection(macAddress, remoteAddress, authenticatedUser = null) {
  const sequelize = getSequelize();
  const { DeviceAlias, TerminalConnection } = getModels();

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
  recordTerminalConnection,
  touchTerminalHeartbeat,
  closeTerminalConnection,
};
