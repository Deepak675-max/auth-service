const express = require("express");
const JWT = require("jsonwebtoken");
const authServiceApp = express();
const httpErrors = require("http-errors");
const httpServer = require("http").createServer(authServiceApp);
const socketio = require("socket.io")(httpServer);

socketio.on('connection', (socket) => {
  console.log('A user connected');
  // Handle events here
  // For example, listen for a task update event and broadcast it to connected clients
});


module.exports = {
  authServiceApp,
  httpServer,
  socketio,
};
