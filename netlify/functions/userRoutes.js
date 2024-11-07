// userRoutes.js
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('./models');
const { sendVerificationEmail } = require('./email');
const jwt = require('jsonwebtoken');
const router = express.Router();

router.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({});
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error });
  }
});

router.post('/api/users', async (req, res) => {
  const saltRounds = 10;
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    await sendVerificationEmail(email, token);

    res.status(201).json({ message: 'User created successfully. Please check your email to verify your account.' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

module.exports = router;
