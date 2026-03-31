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

async function recordTerminalConnection(macAddress, remoteAddress) {
  const sequelize = getSequelize();
  const { DeviceAlias, TerminalConnection } = getModels();

  return sequelize.transaction(async (transaction) => {
    const device = await ensureDevice(macAddress, transaction, new Date());
    let aliasRecord = await DeviceAlias.findOne({
      where: { deviceId: device.id },
      transaction,
    });

    // Initialize group to remoteAddress on first connection if not already set
    if (remoteAddress && (!aliasRecord || aliasRecord.group == null)) {
      if (aliasRecord) {
        aliasRecord.group = remoteAddress;
        await aliasRecord.save({ transaction });
      } else {
        aliasRecord = await DeviceAlias.create({
          deviceId: device.id,
          group: remoteAddress,
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

module.exports = {
  ensureDevice,
  getDeviceAlias,
  setDeviceAlias,
  setDeviceGroup,
  deleteDeviceAliasByGroupAndName,
  recordTerminalConnection,
  touchTerminalHeartbeat,
  closeTerminalConnection,
};
