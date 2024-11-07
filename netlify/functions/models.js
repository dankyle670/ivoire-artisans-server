// models.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  isFirstLogin: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  isArtisan: { type: Boolean, default: false },
  isClient: { type: Boolean, default: false },
  countryCode: { type: String },
  phoneNumber: { type: String },
  artisanType: { type: String },
});

const User = mongoose.model('User', UserSchema);

module.exports = User;
