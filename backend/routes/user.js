const zod = require("zod");
const express = require("express");
const router = express.Router();
const User = require("../db");
const jwt = require("jsonwebtoken");
const JWT_SECRET = require("../config");
const { authMiddleware } = require("../middleware");

const signupBody = zod.object({
  email: zod.string().email(),
  firstName: zod.string(),
  lastName: zod.string(),
  password: zod.string(),
});

const signinBody = zod.object({
  email: zod.string().email(),
  password: zod.string(),
});

const updateBody = zod.object({
  firstName: zod.string(),
  lastName: zod.string(),
  password: zod.string(),
});

router.post("/signup", async (req, res) => {
  try {
    const { success } = signupBody.safeParse(req.body);
    if (!success) {
      res.status(411).json({ error: "Email already taken!" });
    }

    const existingUser = await User.findOne({
      email: req.body.username,
    });

    if (existingUser) {
      res.status(411).json({ error: "Email already taken!" });
    }

    const user = new User({
      username: req.body.username,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: req.body.password,
    });

    const userId = user._id;

    const token = jwt.sign(
      {
        userId,
      },
      JWT_SECRET
    );

    res.status(200).json({
      message: "User created successfully",
      token: token,
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/signin", async (req, res) => {
  try {
    const { success } = signinBody.safeParse(req.body);

    if (!success) {
      res.status(411).json({
        error: "Error while logging in",
      });
    }

    const user = await User.findOne({
      email: req.body.email,
      password: req.body.password,
    });

    if (user) {
      const token = jwt.sign(
        {
          userId: user._id,
        },
        JWT_SECRET
      );

      res.status(200).json({
        message: "User logged in successfully",
        token: token,
      });
    }
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

router.put("/update", authMiddleware, async (req, res) => {
  try {
    const { success } = updateBody.safeParse(req.body);

    if (!success) {
      res.status(411).json({
        error: "Error while updating information",
      });
    }

    await User.updateOne({ _id: req.userId }, req.body);

    res.status(200).json({
      message: "User updated successfully",
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
