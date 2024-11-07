// roleRoutes.js
//const express = require('express');
//const User = require('./models');
//const router = express.Router();
//
//router.post('/api/updateRole', async (req, res) => {
//  const { userId, role } = req.body;
//
//  try {
//    const user = await User.findById(userId);
//    if (!user) return res.status(404).json({ message: 'User not found' });
//
//    if (role === 'artisan') {
//      user.isArtisan = true;
//      user.isClient = false;
//    } else if (role === 'client') {
//      user.isArtisan = false;
//      user.isClient = true;
//    } else {
//      return res.status(400).json({ message: 'Invalid role' });
//    }
//
//    await user.save();
//    res.json({ message: 'User role updated successfully' });
//  } catch (error) {
//    res.status(500).json({ message: 'Server error' });
//  }
//});
//
//module.exports = router;
