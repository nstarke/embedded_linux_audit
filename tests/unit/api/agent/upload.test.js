'use strict';

function loadRegisterUploadRoute() {
  jest.resetModules();
  const createUploadHandler = jest.fn(() => 'upload-handler');

  jest.doMock('../../../../api/agent/routes/uploadHandler', () => ({
    createUploadHandler,
  }));

  const registerUploadRoute = require('../../../../api/agent/routes/upload');
  return { registerUploadRoute, createUploadHandler };
}

describe('upload route', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('registers the upload handler on the expected route', () => {
    const { registerUploadRoute, createUploadHandler } = loadRegisterUploadRoute();
    const app = { post: jest.fn() };
    const deps = { persistUpload: jest.fn() };

    registerUploadRoute(app, deps);

    expect(createUploadHandler).toHaveBeenCalledWith(deps);
    expect(app.post).toHaveBeenCalledWith('/:mac/upload/:type', 'upload-handler');
  });
});
