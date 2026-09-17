// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// CI installs the root test dependencies without the API's Sequelize package.
jest.mock('sequelize', () => ({
  Op: { ne: Symbol('ne') },
}), { virtual: true });

// Exercise each public read path so moving its ACL cannot accidentally turn a
// missing user or an unrelated device into an unrestricted job/upload query.
describe.each([
  ['clientUploads', 'listUploadsForUser', 'Upload', (list, mac) => list('file', 'alice', { mac })],
  ['moduleBuilds', 'listModuleBuildRequests', 'ModuleBuildRequest', (list, mac) => list('alice', { mac })],
  ['ghidraJobs', 'listGhidraJobs', 'GhidraAnalysisJob', (list, mac) => list('alice', { mac })],
])('%s device visibility', (moduleName, method, modelName, invoke) => {
  let models;
  let list;

  beforeEach(() => {
    jest.resetModules();
    models = {
      User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
      UserDevice: { findAll: jest.fn().mockResolvedValue([{ deviceId: 3 }]) },
      Device: {},
      [modelName]: { findAll: jest.fn().mockResolvedValue([]) },
    };
    jest.doMock('../../../../api/lib/db/index', () => ({ getModels: () => models }));
    list = require(`../../../../api/lib/db/${moduleName}`)[method];
  });

  afterEach(() => jest.resetModules());

  test('canonicalizes the MAC inside the user association query', async () => {
    await invoke(list, 'AA:BB:CC:DD:EE:FF');
    expect(models.UserDevice.findAll).toHaveBeenCalledWith({
      where: { userId: 7 },
      attributes: ['deviceId'],
      include: [{
        model: models.Device,
        attributes: [],
        where: { macAddress: 'aa-bb-cc-dd-ee-ff' },
        required: true,
      }],
    });
    expect(models[modelName].findAll).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ deviceId: [3] }),
    }));
  });

  test('unknown user cannot query artifacts or jobs', async () => {
    models.User.findOne.mockResolvedValue(null);
    await expect(invoke(list, null)).resolves.toEqual([]);
    expect(models.UserDevice.findAll).not.toHaveBeenCalled();
    expect(models[modelName].findAll).not.toHaveBeenCalled();
  });

  test('unassociated MAC cannot query artifacts or jobs', async () => {
    models.UserDevice.findAll.mockResolvedValue([]);
    await expect(invoke(list, '11:22:33:44:55:66')).resolves.toEqual([]);
    expect(models[modelName].findAll).not.toHaveBeenCalled();
  });
});
