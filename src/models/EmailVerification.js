// models/EmailVerification.js
const mongoose = require('mongoose');

const emailVerificationSchema = new mongoose.Schema({
  email: { type: String, required: true },
  verificationCode: { type: String, required: true },
  verificationExpires: { type: Date, required: true }
});

module.exports = mongoose.model('EmailVerification', emailVerificationSchema);