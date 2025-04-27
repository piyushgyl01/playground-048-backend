const mongoose = require("mongoose");

const pcSchema = new mongoose.Schema(
  {
    buildName: {
      type: String,
      required: true,
    },
    price: {
      type: String,
      required: true,
    },
    buidler: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("pg48pc", pcSchema);
