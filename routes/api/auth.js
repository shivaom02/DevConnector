const express = require('express');
const router = express.Router();

const jwt = require('jsonwebtoken');
const config = require('config');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const User = require('../../models/User');
const auth = require('./../../middleware/auth');

// @route GET api/auth
// @desc Test Route
// @access Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error!!!');
  }
});

// @route POST api/auth
// @desc Authenticate user and get token
// @access Public
router.post(
  '/',
  // validation check
  body('email', 'Please enter valid email').isEmail(),
  body('password', 'Password is required!').exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Destructuring req to get data
    const { email, password } = req.body;

    try {
      // See if user exist
      let user = await User.findOne({ email });

      if (!user) {
        return res.status(400).json({
          errors: [
            {
              msg: 'Invalid Credentials!'
            }
          ]
        });
      }

      // matching entered password with original one
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({
          errors: [
            {
              msg: 'Invalid Credentials!'
            }
          ]
        });
      }

      // Return jsonwebtoken to login
      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtToken'),
        // optional params below
        { expiresIn: 36000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error!!!');
    }
  }
);

module.exports = router;
