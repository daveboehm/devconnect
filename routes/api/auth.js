const express = require("express")
const router = express.Router()
const auth = require("../../middleware/auth")
const user = require("../../models/User")

const bcrypt = require("bcryptjs")
const config = require("config")
const jwt = require("jsonwebtoken")
const { check, validationResult } = require("express-validator/check")

// @route GET api/auth
// @desc Test route
// @access Public
router.get("/", auth, async (req, res) => {
  try {
    const user = await user.findById(req.user.id).select("-password")
    res.json(user)
  } catch (err) {
    console.error(err.message)
    res.status(500).send("Error finding user id from token")
  }
})

// @route GET api/auth
// @desc Authenticate user and get token
// @access Public
router.post(
  "/",
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists()
  ],
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array()
      })
    }

    const { email, password } = req.body

    try {
      // See if user exists
      let user = await User.findOne({ email })
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid credentials" }] })
      }

      // Compare entered password and encrypted pw from token
      const isMatch = await bcrypt.compare(password, user.password)

      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid credentials" }] })
      }

      // Return json web token (required to log in user on registration)
      const payload = {
        user: {
          id: user.id
        }
      }

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 36000 },
        (err, token) => {
          if (err) throw err
          res.json({ token })
        }
      )
    } catch (err) {
      console.error(err.message)
      res.status(500).send("Server error")
    }

    res.send("User route")
  }
)

module.exports = router
