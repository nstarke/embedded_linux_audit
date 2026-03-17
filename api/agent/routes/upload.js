const { createUploadHandler } = require('./uploadHandler');

module.exports = function registerUploadRoute(app, deps) {
  app.post('/:mac/upload/:type', createUploadHandler(deps));
};
