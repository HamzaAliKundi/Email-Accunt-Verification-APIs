const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const Register = require("../model/Register");
const UserVerification = require("../model/UserVerification");
const nodemailer = require("nodemailer");
// const { v9: uuidv9 } = require("uuid");
require("dotenv").config();
const router = express.Router();
const path = require("path");

let transpoter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

transpoter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for message : ", success);
  }
});

const sendVerificationEmail = ({ _id, email }, res) => {
  const currentUrl = "http://localhost:5000/";
  // const uniqueString = uuidv9() + _id;
  const uniqueString = _id.toString();

  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify Your Email",
    html: `<p>Verify your email address to complete Signup and login into your account.</p><p>This link <b>expires in 6 hours</b>.</p><p>Press <a href=${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
    }>here</a> to proceed.</p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      const newuserVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newuserVerification
        .save()
        .then(() => {
          transpoter
            .sendMail(mailOptions)
            .then(() => {
              res.json({
                status: "PENDING",
                message: "Verify Email Sent!",
              });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "FAILED",
                message: "Verification Email Failed",
              });
            });
        })
        .catch((err) => {
          console.log(err);
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email data!",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occurred while hashing email data!",
      });
    });
};

router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;
  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        if (expiresAt < Date.now()) {
          UserVerification.deleteOne({ userId })
            .then((result) => {
              Register.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired please sign up again";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                })
                .catch((error) => {
                  let message =
                    "Clearing user with expired unique string failed";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                });
            })
            .catch((err) => {
              console.log(err);
              let message =
                "An error occurred while clearing expired user verification record";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        } else {
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                Register.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "../views/verified.html")
                        );
                      })
                      .catch((err) => {
                        console.log(err);
                        let message =
                          "An error occurred while finalizing successfull verification";
                        res.redirect(
                          `/user/verified/error=true&message=${message}`
                        );
                      });
                  })
                  .catch((err) => {
                    console.log(err);
                    let message =
                      "An error occurred while updating user record to show verified.";
                    res.redirect(
                      `/user/verified/error=true&message=${message}`
                    );
                  });
              } else {
                let message =
                  "An error Invalid verification detail passed. Check your inbox.";
                res.redirect(`/user/verified/error=true&message=${message}`);
              }
            })
            .catch((error) => {
              console.log(error);
              let message = "An error occurred while comparing unique string";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        }
      } else {
        let message =
          "Account record doesn't exists  or has been verified  already. Please signup or login";
        res.redirect(`/user/verified/error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An error occurred while checking for existing users verification record";
      res.redirect(`/user/verified/error=true&message=${message}`);
    });
});

router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/verified.html"));
});

router.post("/signup", (req, res) => {
  let { name, email, password } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();

  if (name === "" || email === "" || password === "") {
    res.json({
      status: "FAILED",
      message: "Empty Input Fields",
    });
  } else {
    Register.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "FAILED",
            message: "User with provided email already exists",
          });
        } else {
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new Register({
                name,
                email,
                password: hashedPassword,
              });

              newUser.save().then((result) => {
                sendVerificationEmail(newUser, res);
              });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "En error accured while checking for existing user!",
        });
      });
  }
});

router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email === "" || password === "") {
    res.json({
      status: "FAILED",
      message: "Expty Credientals supplied",
    });
  } else {
    Register.find({ email: email })
      .then((data) => {
        if (data.length) {
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email hans't been verified. Check your Inbox",
            });
          } else {
            const hasheedPassword = data[0].password;
            bcrypt
              .compare(password, hasheedPassword)
              .then((result) => {
                if (result) {
                  res.json({
                    status: "Success",
                    message: "Sign In successful",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "Failed",
                    message: "Invalied password entered",
                  });
                }
              })
              .catch((err) => {
                status: "FAILED";
                message: "An error occurred while comparing the password";
              });
          }
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid Credientals",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking  for existing user",
        });
      });
  }
});

//  **Generating a Token Function
const generateToken = (id, name, email) => {
  return jwt.sign({ id, name, email }, process.env.jwt_secret, {
    expiresIn: "30d",
  });
};

module.exports = router;
