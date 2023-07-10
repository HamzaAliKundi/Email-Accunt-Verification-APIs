const express = require("express");
const router = express.Router();

const { registerUser } = require("../controllers/Register");
const { loginUser } = require("../controllers/Login");

router.post("/register", registerUser);
router.post("/login", loginUser);

module.exports = router;
