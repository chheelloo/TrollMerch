require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet());
app.use(cors());

// Use the environment variable for MongoDB URI
const mongoUri = process.env.MONGODB_URI; 

if (!mongoUri) {
    console.error('MONGODB_URI is not defined. Check your .env file.');
    process.exit(1);
}

const client = new MongoClient(mongoUri);
let usersCollection;

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db('test'); // Replace with your actual database name
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

// Session Management with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// Helper Functions
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

// Rate Limiting for Login Route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: (req, res, next, options) => {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// Login Route Implementation
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        // Input validation
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        // Fetch user
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        // Account lockout check
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
        }

        // Password verification
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // Handle failed attempts
            let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
            let updateFields = { invalidLoginAttempts: invalidAttempts };

            if (invalidAttempts >= 3) {
                // Lock account
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
                updateFields.invalidLoginAttempts = 0;
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            } else {
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }

        // Successful login
        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
        );

        req.session.userId = user._id;
        req.session.email = user.email;
        req.session.role = user.role;
        req.session.studentIDNumber = user.studentIDNumber;

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ success: true, role: user.role, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});

// Sign Up Route Implementation
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Input validation
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.' });
            console.log('Password error: ', error)
        }

        // Check for existing user
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        // Hash password
        const hashedPassword = hashPassword(password);

        // Insert new user into database
        await usersCollection.insertOne({ email, password: hashedPassword });

        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Middleware for Authentication
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email;
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }
        // Fetch user details from the database
        const user = await usersCollection.findOne(
            { email },
            { projection: { email: 1 } }
        );
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        // Return only necessary details
        res.json({
            success: true,
            user: {
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
});
    

// Protected Routes
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Logout Route
app.post('/logout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(400).json({ success: false, message: 'No user is logged in.' });
    }
    try {
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Logout failed.' });
            }
            res.clearCookie('connect.sid');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            res.setHeader('Surrogate-Control', 'no-store');
            return res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        return res.status(500).json({ success: false, message: 'Logout failed.' });
    }
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        // Check if the email exists
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Email not found.' });
        }

        // Generate a random reset key
        const resetKey = generateRandomString(32);

        // Update the user document with the reset key and expiration time
        await usersCollection.updateOne(
            { email: email },
            { $set: { resetKey: resetKey, resetExpires: new Date(Date.now() + 3600000) } } // Set expiration to 1 hour from now
        );

        // Send the reset code to the user's email
        await sendResetCodeEmail(email, resetKey);

        res.status(200).json({ success: true, message: 'Password reset code sent to your email address.' });
    } catch (error) {
        console.error('Error sending password reset code:', error);
        res.status(500).json({ success: false, message: 'Error sending password reset code.' });
    }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { email, newPassword, resetKey } = req.body;
    try {
        // Check if the email and reset key are valid
        const user = await usersCollection.findOne({ email, resetKey });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or reset key.' });
        }

        // Check if the reset key has expired
        if (user.resetExpires < new Date()) {
            return res.status(400).json({ success: false, message: 'Reset key has expired.' });
        }

        // Hash the new password
        const hashedPassword = hashPassword(newPassword);

        // Update the user's password with the new hashed password
        await usersCollection.updateOne({ email: email }, { $set: { password: hashedPassword, resetKey: null, resetExpires: null } });

        res.json({ success: true, message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password.' });
    }
});

// Generate Random String Function
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Send Reset Code Email
async function sendResetCodeEmail(email, resetCode) {
    const msg = {
        to: email,
        from: 'chelorynmhariemilo@gmail.com', // Replace with your email
        subject: 'Password Reset Request',
        text: `Your password reset code is: ${resetCode}`,
        html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
    };
    await sgMail.send(msg);
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});