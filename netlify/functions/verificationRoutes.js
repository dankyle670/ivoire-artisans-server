//// verificationRoutes.js
//const express = require('express');
//const jwt = require('jsonwebtoken');
//const User = require('./models');
//const router = express.Router();
//
//router.get('/api/verify-email', async (req, res) => {
//  const { token } = req.query;
//  if (!token) return res.status(400).json({ message: 'No token provided' });
//
//  try {
//    const decoded = jwt.verify(token, process.env.JWT_SECRET);
//    const user = await User.findById(decoded.userId);
//    if (!user) return res.status(400).json({ message: 'Invalid token' });
//
//    if (user.verified) return res.status(400).json({ message: 'User already verified' });
//
//    user.verified = true;
//    await user.save();
//
//    res.status(200).json({ message: 'User verified successfully' });
//  } catch (error) {
//    res.status(500).json({ message: 'Error verifying token' });
//  }
//});
//
//module.exports = router;
