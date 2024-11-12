require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb'); // Import MongoClient here
const bcrypt = require('bcrypt');
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://Chelo:MjJYdu7YpYI0szHr@cluster1.e5xj4.mongodb.net/';
const client = new MongoClient(mongoUri); 
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/public"));
app.use('/node_modules', express.static("node_modules"))
app.use(helmet()); 
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// MongoDB setup 
let usersCollection;

async function connectToDatabase() {
  try {
    await client.connect();
    console.log('MongoDB connected');
    const database = client.db('test');
    usersCollection = database.collection('users'); 
  } catch (err) {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}

connectToDatabase();

// Mongoose Connection
mongoose.connect(mongoUri)
  .then(() => console.log('Mongoose connected'))
  .catch(err => console.log('Mongoose connection error:', err));

// Define Token Schema and Model
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  emaildb: { type: String, required: true },
  password: { type: String, required: true },
  resetKey: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Session Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret', 
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: mongoUri }),
  cookie: { secure: false } // Set to true for HTTPS in production
}));

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Generate Random String
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('Email is required');

  try {
    let token = await Token.findOne({ email });
    const resetToken = generateRandomString(32);

    if (token) {
      token.token = resetToken;
      await token.save();
    } else {
      await new Token({ email, token: resetToken }).save();
    }

    // Now send the reset code email as well
    await sendResetCodeEmail(email, resetToken);  // Assuming you want to use this token to reset the password

    // Send a response with a redirect URL
    res.status(200).json({
      message: 'Password reset token generated and email sent',
      redirectUrl: '/reset-password.html',  // Include the redirect URL in the response
    });

  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});


// Send Reset Code Email
async function sendResetCodeEmail(email, resetCode) {
  const msg = {
    to: email,
    from: 'balicweyjohnwell@gmail.com',
    subject: 'Your Password Reset Code',
    text: `Your password reset code is: ${resetCode}`,
    html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
  };
  try {
    await sgMail.send(msg);
    console.log(`Reset code sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Error sending reset code email');
  }
}

function isValidPassword(password) {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{};:'",.<>?\\|`~])[A-Za-z\d!@#$%^&*()_\-+=\[\]{};:'",.<>?\\|`~]{8,}$/;
  return passwordRegex.test(password);
}

// Send Password Reset Code
app.post('/send-password-reset', async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the email exists in the database
    const user = await User.findOne({ emaildb: email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'No account with that email exists' });
    }

    // Generate the reset token and save it to the user's record
    const resetCode = generateRandomString(6); // Generate a 6-character reset code
    user.resetKey = resetCode;
    user.resetExpires = new Date(Date.now() + 3600000); // Token expires in 1 hour
    await user.save();

    // Send the reset code via email
    await sendResetCodeEmail(email, resetCode);

    // Respond with a message and redirect URL
    res.json({
      success: true,
      message: 'Password reset code sent successfully',
      redirectUrl: '/reset-password.html' // Redirect user to reset-password page
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Error processing request' });
  }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
  const { resetKey, newPassword } = req.body;

  try {
    // Find the user by resetKey and check if the reset code is still valid
    const user = await User.findOne({
      resetKey,
      resetExpires: { $gt: new Date() } // Check if the reset code has not expired
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset code' });
    }

    // Hash the new password and update the user's record
    user.password = hashPassword(newPassword); 
    user.resetKey = null; 
    user.resetExpires = null; 
    await user.save();

    // Send success response
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

// Sign Up
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password must contain atleat 1 character, number, and special character' });
    }

    const hashedPassword = hashPassword(password);
    await usersCollection.insertOne({ emaildb: email, password: hashedPassword, createdAt: new Date() });

    res.json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Login Rate Limiter
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 30 minutes
  max: 500, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 5 minutes.',
  handler: function (req, res, next, options) {
    res.status(options.statusCode).json({ success: false, message: options.message });
  }
});

app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        const user = await usersCollection.findOne({ emaildb: email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        req.session.userId = user._id;
        req.session.email = user.emaildb;

        res.json({ success: true, message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});


// Serve user details (email)
app.get('/user-details', (req, res) => {
  if (req.session.email) {
    return res.json({
      success: true,
      user: {
        email: req.session.email // Send the user's email from the session
      }
    });
  } else {
    return res.json({ success: false, message: 'User not logged in.' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.json({ success: false, message: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Dashboard route (protected by authentication)
app.get('/dashboard', isAuthenticated, async (req, res) => {
  const userEmail = req.session.email;
  res.json({ message: `Welcome to your Dashboard, ${userEmail}!` });
});

app.listen(PORT, () => {
  const baseUrl = `http://localhost:${PORT}`;
    console.log(`\x1b[34mServer is running on port ${PORT}: ${baseUrl}\x1b[0m`);
});