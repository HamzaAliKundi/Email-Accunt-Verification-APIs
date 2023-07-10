const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const Register = require("../model/Register");

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const userExist = await Register.findOne({ email });

  if (userExist) {
    res.status(400);
    throw new Error("User alredy register with this Email address");
  }

  const salt = await bcrypt.genSalt(10);
  const encryptedPassword = await bcrypt.hash(password, salt);

  const newUser = await Register.create({
    name: name,
    email: email,
    password: encryptedPassword,
  });

  if (newUser) {
    res.status(201).json({
      _id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      token: generateToken(newUser._id, newUser.name, newUser.email),
    });
  } else {
    res.status(400);
    throw new Error("Invalid Admin Data");
  }
});

//  **Generating a Token Function
const generateToken = (id, name, email) => {
  return jwt.sign({ id, name, email }, process.env.jwt_secret, {
    expiresIn: "30d",
  });
};

module.exports = {
  registerUser,
};
