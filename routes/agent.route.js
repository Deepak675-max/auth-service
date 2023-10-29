const express = require('express');
const agentRouter = express.Router();
const agentController = require('../controllers/agent.controller');
const jwtModule = require("../middlewares/jwt/jwt.middleware");

agentRouter.post('/create-user', agentController.createUser);
agentRouter.post('/create-vendor', agentController.createVendor);
agentRouter.post('/login-user', agentController.loginUser);
agentRouter.post('/authorize-user', agentController.verifyUser);
agentRouter.post('/authorize-vendor', agentController.verifyVendor);
agentRouter.post('/login-vendor', agentController.loginVendor);
agentRouter.get('/logout-user', jwtModule.verifyUserAccessToken, agentController.logoutUser);
agentRouter.get('/logout-vendor', jwtModule.verifyVendorAccessToken, agentController.logoutVendor);
agentRouter.get('/get-user-from-token', jwtModule.verifyUserAccessToken, agentController.getUserFromToken);
agentRouter.get('/get-vendor-from-token', jwtModule.verifyVendorAccessToken, agentController.getVendorFromToken);


module.exports = { agentRouter };