// authRoutes.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models');
const router = express.Router();

router.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.verified) return res.status(403).json({ message: 'Account not verified' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    if (user.isFirstLogin) {
      user.isFirstLogin = false;
      await user.save();
    }

    res.json({
      message: 'Login successful',
      token,
      isFirstLogin: user.isFirstLogin,
      isArtisan: user.isArtisan,
      isClient: user.isClient,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
