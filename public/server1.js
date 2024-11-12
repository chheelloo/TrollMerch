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
const mongoUri = process.env.MONGODB_URI; // Make sure MONGODB_URI is defined in .env

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
        const database = client.db('test'); // Change to your actual database name
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

// Session Management with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET, // Make sure SESSION_SECRET is defined in .env
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
        const user = await usersCollection.findOne({ emaildb: email });
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
        req.session.email = user.emaildb;
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

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.' });
        }

        const existingUser = await usersCollection.findOne({ emaildb: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        const hashedPassword = hashPassword(password);
        await usersCollection.insertOne({ emaildb: email, password: hashedPassword });
        
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
    { emaildb: email },
    { projection: { emaildb: 1 } }
    );
    if (!user) {
    return res.status(404).json({ success: false, message: 'User not found.' });
    }
    // Return only necessary details
    res.json({
    success: true,
    user: {
    email: user.emaildb
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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


/*require('dotenv').config();
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
        const database = client.db('test'); // Change to your actual database name
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

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

function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: (req, res, next, options) => {
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

        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
            let updateFields = { invalidLoginAttempts: invalidAttempts };

            if (invalidAttempts >= 3) {
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
                updateFields.invalidLoginAttempts = 0;
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            } else {
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }

        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
        );

        req.session.userId = user._id;
        req.session.email = user.emaildb;
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

app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.' });
        }

        const existingUser = await usersCollection.findOne({ emaildb: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        const hashedPassword = hashPassword(password);
        await usersCollection.insertOne({ emaildb: email, password: hashedPassword });
        
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

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
        return res.status(500).json({ success: false, message: 'Failed to log out.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});*/


/* server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('MongoDB connection error:', error);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());
app.use(cors());

// Session management
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// SendGrid setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// User schema and model
const userSchema = new mongoose.Schema({
    emaildb: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullname: { type: String },
    username: { type: String },
});
const User = mongoose.model('User', userSchema);

// Rate limiter for login attempts
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5,
    message: 'Too many login attempts, please try again after 30 minutes.',
});

// Helper functions
const hashPassword = (password) => bcrypt.hashSync(password, 10);

const isValidPassword = (password) => {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
};

const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
};

// Routes
app.post('/signup', async (req, res) => {
    const { email, password, fullname, username } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Invalid password format.' });
        }
        const existingUser = await User.findOne({ emaildb: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }
        const hashedPassword = hashPassword(password);
        const newUser = new User({ emaildb: email, password: hashedPassword, fullname, username });
        await newUser.save();
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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

        const user = await User.findOne({ emaildb: email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        req.session.userId = user._id;
        res.json({ success: true, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Logout failed.' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logged out successfully.' });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});*/


