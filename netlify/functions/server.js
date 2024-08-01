//const nodemailer = require('nodemailer');
//require('dotenv').config();
//
//const OUTLOOK_USER = process.env.OUTLOOK_USER;
//const OUTLOOK_PASS = process.env.OUTLOOK_PASS;
//
//console.log('OUTLOOK_USER:', OUTLOOK_USER);
//console.log('OUTLOOK_PASS:', OUTLOOK_PASS ? 'Password is set' : 'Password is not set');
//
//const transporter = nodemailer.createTransport({
//  service: 'hotmail',
//  auth: {
//    user: OUTLOOK_USER,
//    pass: OUTLOOK_PASS
//  }
//});
//
//const mailOptions = {
//  from: OUTLOOK_USER,
//  to: 'daniel.komoe78@gmail.com, jdanielkom@gmail.com', // Can be a list of recipients
//  subject: 'Subject of the email',
//  text: 'Plaintext content of the email',
//  html: '<b>HTML content of the email</b>'
//};
//
//transporter.sendMail(mailOptions, (error, info) => {
//  if (error) {
//    return console.log('Error occurred:', error);
//  }
//  console.log('Message sent:', info.messageId);
//});

/////////////////////////////////////////////////////////////////////////:

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();
const serverless = require('serverless-http');
const app = express();

// Middleware
app.use(bodyParser.json());

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB connection
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('MONGODB_URI is not defined');
} else {
  console.log(`Connecting to MongoDB with URI: ${uri}`);
}
mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    console.error('Error details:', JSON.stringify(err, null, 2));
});

// Define schema and model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);

// Generate verification token
const createVerificationToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'hotmail',
  auth: {
    user: process.env.OUTLOOK_USER,
    pass: process.env.OUTLOOK_PASS,
  },
});


const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `ivoireartisans://verify/email?token=${token}`;
  console.log('Generated verification URL:', verificationUrl);

  const mailOptions = {
    from: process.env.OUTLOOK_USER,
    to: email,
    subject: 'Verify your email',
    html: `
      <html>
        <body>
          <p>Please verify your email by clicking on the following link:</p>
          <p><a href="${verificationUrl}" target="_blank" rel="noopener noreferrer">Verify Email</a></p>
          <p>If you did not request this, please ignore this email.</p>
        </body>
      </html>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Verification email sent to:', email);
    console.log('Email response:', info.response);
  } catch (error) {
    console.error('Error sending verification email:', error);
  }
};




//const sendVerificationEmail = (email,   token) => {
//    const verificationUrl = `ivoireartisans://verify/email?token=${token}`;
//    const mailOptions = {
//      from: process.env.OUTLOOK_USER,
//      to: email,
//      subject: 'Verify your email',
//      html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">Verify Email</a></p>`,
//    };
//
//    return transporter.sendMail(mailOptions);
//  };

// Routes

// users route
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({});
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error });
  }
});

app.post('/api/users', async (req, res) => {
  const saltRounds = 10;
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    const token = createVerificationToken(newUser._id);
    console.log('THE TOKEN:', token);
    await sendVerificationEmail(email, token);

    res.status(201).json({ message: 'User created successfully. Please check your email to verify your account.' });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

// end users route

// verifyroute mail
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    if (user.verified) {
      return res.status(400).json({ message: 'User already verified' });
    }

    user.verified = true;
    await user.save();

    res.status(200).json({ message: 'User verified successfully' });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(500).json({ message: 'Error verifying token', error: error.message });
  }
});

// end of verify route mail

if (process.env.NODE_ENV === 'development') {
  const PORT = process.env.PORT;
  app.listen(PORT, () => {
    console.log(`Server is running on http://192.168.1.90:${PORT}`);
  });
} else {
  module.exports.handler = serverless(app);
}
