const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const Register = require("../model/Register");

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  //  **Checking if user already register with the same email or not
  const userExist = await Register.findOne({ email });

  //  **Sending response back to user including JSON_WEB_TOKEN
  if (userExist && (await bcrypt.compare(password, userExist.password))) {
    res.status(200).json({
      _id: userExist.id,
      name: userExist.name,
      email: userExist.email,
      token: generateToken(userExist._id, userExist.name, userExist.email),
    });
  } else {
    res.status(400);
    throw new Error("Invalid Credientals");
  }
});

//  **Generating a Token Function
const generateToken = (id, name, email) => {
  return jwt.sign({ id, name, email }, process.env.jwt_secret, {
    expiresIn: "30d",
  });
};

module.exports = {
  loginUser,
};
