const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { body, validationResult } = require('express-validator');

const User = require('./../../models/User');

// @route GET api/users
// @desc Get all users
// @access Public
router.get('/', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    console.error(err.message);
    res.status(400).send('Server Error!');
  }
});

// @route POST api/users
// @desc Register a User
// @access Public
router.post(
  '/',
  // validation check
  body('name', 'Name is required!').not().isEmpty(),
  body('email', 'Please include a valid email').isEmail(),
  body(
    'password',
    'Please enter a password with 6 or more characters!'
  ).isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Destructuring req to get data
    const { name, email, password } = req.body;

    try {
      // See if user exist
      let user = await User.findOne({ email });

      if (user) {
        return res.status(400).json({
          errors: [
            {
              msg: 'User already exists!!!'
            }
          ]
        });
      }

      // Get User Gravatar (image asso with email)
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });

      // updating the user with the gravatar and storing in the same previous let user variable
      user = new User({
        name,
        email,
        avatar,
        password
      });

      // Encrypt password using bcryptjs
      // Create a salt to do the hashing with (10 recmed, more = secure = slow; so 10)
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      // Now, the user is stored in the mongodb
      await user.save();

      // Return jsonwebtoken to login immediately
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
