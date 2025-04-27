const mongoose = require("mongoose");
require("dotenv").config();

const MONGOURI = process.env.MONGODB;

async function connectToDB() {
  mongoose
    .connect(MONGOURI)
    .then(() => {
      console.log("Connected to DB");
    })
    .catch((e) => {
      "Error occured while connecting to DB", e;
    });
}

module.exports = { connectToDB };
