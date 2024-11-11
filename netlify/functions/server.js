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
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    verified: { type: Boolean, default: false },
    isFirstLogin: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    isArtisan: { type: Boolean, default: false },
    isClient: { type: Boolean, default: false },
    countryCode: { type: String, required: false },
    phoneNumber: { type: String, required: false },
    artisanType: { type: String, required: false },
    isLoggedIn: { type: Boolean, default: false },
    subscription: { type: String, default: 'basic' },
    profilePicture: { type: String, required: false },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

const User = mongoose.model('User', UserSchema);

// Generate verification token
const createVerificationToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});


const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `https://ivoire-artisans-verif.netlify.app?token=${encodeURIComponent(token)}`;
  console.log('Generated verification URL:', verificationUrl);

  const mailOptions = {
    from: process.env.GMAIL_USER,
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

// Routes

// users route
app.get('/api/user', async (req, res) => {
  const userId = req.query.userId;  // Get user ID from the request query
  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  try {
    const user = await User.findById(userId);  // No need for populate if there's no transactions field
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      subscription: user.subscription,
      _id: user._id,
      profilePicture: user.profilePicture,
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user data', error });
  }
});


app.post('/api/users', async (req, res) => {
  const saltRounds = 10;
  const { firstName, lastName, email, password } = req.body; // Updated to include firstName and lastName
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ firstName, lastName, email, password: hashedPassword }); // Updated here
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

// Handling user subscription

app.post('/api/subscribe', async (req, res) => {
  const { userId, subscription } = req.body;
  try {
    // Find user by ID and update subscription field
    const user = await User.findByIdAndUpdate(userId, { subscription }, { new: true });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    // Respond with success message and updated subscription
    res.status(200).json({
      message: 'Subscription updated successfully',
      subscription: user.subscription,
    });
  } catch (error) {
    console.error('Error updating subscription:', error);
    res.status(500).json({
      message: 'Error updating subscription',
      error: error.message,
    });
  }
});


// In your backend code
app.post('/api/saveInfos', async (req, res) => {
  const { userId, countryCode, phoneNumber, artisanType } = req.body;

  // Log the incoming request data to debug
  console.log('Request Body:', req.body);

  try {
    // Fetch the user from the database
    const user = await User.findById(userId);
    if (!user) {
      console.error('User not found:', userId);  // Log if the user is not found
      return res.status(404).json({ message: 'User not found' });
    }

    // Update user info
    user.countryCode = countryCode;
    user.phoneNumber = phoneNumber;
    if (artisanType) {
      user.artisanType = artisanType; // Save artisan type if provided
    }

    // Save the updated user document
    await user.save();
    console.log('User information updated successfully:', user);  // Log the updated user

    res.json({ message: 'Phone number and artisan info saved successfully' });
  } catch (error) {
    console.error('Error saving phone number and artisan info:', error);  // Log the error details
    res.status(500).json({ message: 'Server error' });
  }
});

// handling uupdate of role

app.post('/api/updateRole', async (req, res) => {
  const { userId, role } = req.body;

  try {
    // Trouver l'utilisateur par son ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Vérifier si le rôle est valide (admin ou user)
    if (role !== 'admin' && role !== 'user') {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // Mise à jour du rôle
    user.role = role;

    // Si l'utilisateur devient artisan ou client, mettre à jour les champs correspondants
    if (role === 'user') {
      user.isArtisan = true; // Pour un artisan
      user.isClient = true;  // Pour un client
    } else if (role === 'admin') {
      // Aucune modification de isArtisan ou isClient, car admin est un rôle à part
      user.isArtisan = false;
      user.isClient = false;
    }

    // Sauvegarder les modifications dans la base de données
    await user.save();

    // Réponse réussie
    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    console.error('Error updating role:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//app.post('/api/updateRole', async (req, res) => {
//  const { userId, role } = req.body;
//
//  try {
//    const user = await User.findById(userId);
//    if (!user) {
//      return res.status(404).json({ message: 'User not found' });
//    }
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
//    // Sauvegarder les modifications
//    await user.save();
//
//    // Réponse réussie
//    res.json({ message: 'User role updated successfully' });
//  } catch (error) {
//    console.error('Error updating role:', error);
//    res.status(500).json({ message: 'Server error' });
//  }
//});

//handling login

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.verified) {
      return res.status(403).json({ message: 'Account not verified' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    const isFirstLogin = user.isFirstLogin;

    // Update `isLoggedIn` to true for both first time and subsequent logins
    user.isLoggedIn = true;

    if (isFirstLogin) {
      user.isFirstLogin = false;  // Mark the user as no longer a first-time login
    }

    await user.save();  // Save the user with updated state

    res.json({
      message: 'Login successful',
      token,
      verified: user.verified,
      isFirstLogin,
      userId: user._id,
      isArtisan: user.isArtisan || false,
      isClient: user.isClient || false,
      isLoggedIn: user.isLoggedIn  // Ensure we return the updated state
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});


// handling logout

app.post('/api/logout', async (req, res) => {
  const { userToken } = req.body;

  if (!userToken) {
    return res.status(400).send({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.decode(userToken);
    console.log('Decoded token:', decoded); // Debugging log

    if (decoded && decoded.id) {
      const user = await User.findById(decoded.id);
      if (user) {
        user.isLoggedIn = false;
        await user.save();
        return res.status(200).send({ message: 'Logged out successfully' });
      } else {
        return res.status(404).send({ message: 'User not found' });
      }
    } else {
      return res.status(400).send({ message: 'Invalid token' });
    }
  } catch (error) {
    console.error('Logout error:', error); // Debugging log
    return res.status(500).send({ message: 'An error occurred during logout' });
  }
});


// end users route

// verifyroute mail
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    console.log('Token not provided');
    return res.status(400).json({ message: 'No token provided' });
  }

  try {
    // Decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded token:', decoded); // Log decoded token

    const userId = decoded.userId;

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found for ID:', userId);
      return res.status(400).json({ message: 'Invalid token' });
    }

    // Check if the user is already verified
    if (user.verified) {
      console.log('User already verified:', userId);
      return res.status(400).json({ message: 'User already verified' });
    }

    // Verify the user
    user.verified = true;
    await user.save();

    console.log('User successfully verified:', userId);
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