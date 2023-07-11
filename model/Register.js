const mongoose = require("mongoose");

const RegisterUser = mongoose.Schema(
  {
    name: {
      type: String,
      require: [true, "No Name provided"],
    },

    email: {
      type: String,
      require: [true, "No Email provided"],
    },

    password: {
      type: String,
      require: [true, "No Password provided"],
    },

    verified: {
      type: Boolean,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Register", RegisterUser);
