const express = require("express");
const v1 = express.Router();

const { agentRouter } = require('../../../routes/agent.route');
v1.use('/auth', agentRouter);

module.exports = {
  v1
};
