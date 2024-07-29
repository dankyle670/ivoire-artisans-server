const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();
const serverless = require('serverless-http');
const app = express();

// Middleware
app.use(bodyParser.json());

//const allowedOrigins = [
//    'https://farme-manager.netlify.app',
//  'https://main--farme-manager.netlify.app',
//  'http://localhost:3000'
//];

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
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  });

const User = mongoose.model('User', UserSchema);

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
      //console.log('Database before user creation:', await User.find({}));
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUser = new User({ name, email, password: hashedPassword });
      await newUser.save();
      //console.log('Database after user creation:', await User.find({}));
      res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
      console.error('Error creating user:', error);
      res.status(500).json({ message: 'Error creating user', error: error.message });
    }
  });

//app.post('/api/users', async (req, res) => {
//    const saltRounds = 10;
//    const { name, email, password } = req.body;
//    try {
//        const hashedPassword = await bcrypt.hash(password, saltRounds);
//        const newUser = new User({ name, email, password: hashedPassword });
//    await newUser.save();
//    res.status(201).json({ message: 'User created successfully' });
//  } catch (error) {
//    res.status(500).json({ message: 'Error creating user', error });
//  }
//});

// end of users route

if (process.env.NODE_ENV === 'development') {
  const PORT = process.env.PORT;
  app.listen(PORT, () => {
    console.log(`Server is running on http://192.168.1.90:${PORT}`);
  });
} else {
  module.exports.handler = serverless(app);
}
