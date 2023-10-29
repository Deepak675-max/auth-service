// Import Packages
const mongoose = require("mongoose");

const mongodbURI = 'mongodb://127.0.0.1:27017'
// Establish Connection to MongoDB Server
mongoose.set("strictQuery", false);
mongoose
  .connect(mongodbURI, {
    useNewUrlParser: true,
    useUnifiedtopology: true,
  })
  .catch((error) => {
    console.log(error);
    process.exit(0);
  });

// Create connection Object & Listen for Events
const mongoConnection = mongoose.connection;

mongoConnection.on("connected", () => {
  console.log(`Application Connected to MongoDB Server.`);
});

mongoConnection.on("disconnected", () => {
  console.error(`Application Disconnected from MongoDB Server.`);
});

// Disconnect MongoDB Server before quitting Application
process.on("SIGINT", async () => {
  await mongoConnection.close().catch((error) => {
    console.log(error);
  });
});

// Export Connection
module.exports = mongoConnection;
