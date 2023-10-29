// Import Packages
const redis = require("redis");
const moment = require("moment");

// Establish Connection to Redis Server
const redisClient = redis.createClient({
  port: process.env.REDIS_PORT,
  host: process.env.REDIS_HOST,
  password: process.env.REDIS_PASS,
  no_ready_check: true,
});

redisClient.connect().catch((error) => {
  console.error(`Error Connecting Redis Server.\n${error?.message}`);
  process.exit(0);
});

// Listen for Events
redisClient.on("connect", () => {
  console.log(`Application Connected to Redis Server.`);
  (async () => {
    try {
      await redisClient.SET("socketData", JSON.stringify({}));
    } catch (error) {
      console.error(error?.message);
      process.exit(0);
    }
  })();
});

redisClient.on("end", () => {
  console.error(`\nApplication Disconnected from Redis Server.`);
});

// Disconnect Redis Server before quitting Application
process.on("SIGINT", async () => {
  await redisClient.quit().catch((error) => {
    console.log(error);
  });
});

// Export Connection
module.exports = redisClient;
