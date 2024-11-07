//// email.js
//const nodemailer = require('nodemailer');
//const jwt = require('jsonwebtoken');
//
//const transporter = nodemailer.createTransport({
//  service: 'gmail',
//  auth: {
//    user: process.env.GMAIL_USER,
//    pass: process.env.GMAIL_PASS,
//  },
//});
//
//const sendVerificationEmail = async (email, token) => {
//  const verificationUrl = `https://ivoire-artisans-verif.netlify.app?token=${encodeURIComponent(token)}`;
//
//  const mailOptions = {
//    from: process.env.GMAIL_USER,
//    to: email,
//    subject: 'Verify your email',
//    html: `<p>Please verify your email by clicking <a href="${verificationUrl}">here</a>.</p>`,
//  };
//
//  return transporter.sendMail(mailOptions);
//};
//
//module.exports = { sendVerificationEmail };
