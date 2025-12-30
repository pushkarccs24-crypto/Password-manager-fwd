const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/password-manager';

mongoose.connect(MONGODB_URI)
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.log('Please make sure MongoDB is running. You can start it with:');
    console.log('1. Open Command Prompt as Administrator');
    console.log('2. Run: net start MongoDB');
    console.log('\nOr install MongoDB if not installed:');
    console.log('https://www.mongodb.com/try/download/community');
});

// User Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Password Schema
const passwordSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    website: {
        type: String,
        required: [true, 'Website name is required'],
        trim: true
    },
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true
    },
    password: {
        type: String,
        required: [true, 'Password is required']
    },
    notes: {
        type: String,
        default: ''
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Models
const User = mongoose.model('User', userSchema);
const Password = mongoose.model('Password', passwordSchema);

// Simple encryption/decryption functions
const encrypt = (text) => {
    return Buffer.from(text).toString('base64');
};

const decrypt = (encryptedText) => {
    return Buffer.from(encryptedText, 'base64').toString('utf8');
};

// Authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        if (!authHeader) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided. Please login.' 
            });
        }
        
        const token = authHeader.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid token format' 
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        console.error('Authentication error:', error.message);
        res.status(401).json({ 
            success: false, 
            message: 'Please login again' 
        });
    }
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// Test route
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Test route working' 
    });
});

// Register user
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log('📝 Registration attempt received:', { 
            email: req.body.email,
            name: req.body.name 
        });
        
        const { name, email, password } = req.body;

        // Validation
        if (!name || !email || !password) {
            console.log('❌ Missing fields:', { name: !!name, email: !!email, password: !!password });
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('❌ Email already exists:', email);
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();
        console.log('✅ User registered successfully:', user.email);

        // Generate token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        });
    } catch (error) {
        console.error('❌ Registration error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed. Please try again.',
            error: error.message 
        });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('🔑 Login attempt received:', { email: req.body.email });
        
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            console.log('❌ User not found:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log('❌ Invalid password for:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('✅ User logged in successfully:', user.email);
        
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        });
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Login failed. Please try again.',
            error: error.message 
        });
    }
});

// Change password
app.post('/api/auth/change-password', authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Both passwords are required' 
            });
        }

        const isPasswordValid = await bcrypt.compare(currentPassword, req.user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        req.user.password = hashedPassword;
        await req.user.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.error('Change password error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to change password'
        });
    }
});

// Password CRUD operations

// Create password
app.post('/api/passwords', authenticate, async (req, res) => {
    try {
        const { website, username, password, notes } = req.body;

        if (!website || !username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Website, username, and password are required' 
            });
        }

        const encryptedPassword = encrypt(password);

        const newPassword = new Password({
            userId: req.user._id,
            website,
            username,
            password: encryptedPassword,
            notes: notes || ''
        });

        await newPassword.save();

        res.status(201).json({
            success: true,
            message: 'Password saved successfully',
            password: {
                ...newPassword.toObject(),
                password: password // Return decrypted version
            }
        });
    } catch (error) {
        console.error('Create password error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to save password'
        });
    }
});

// Get all passwords for user
app.get('/api/passwords', authenticate, async (req, res) => {
    try {
        const passwords = await Password.find({ userId: req.user._id })
            .sort({ createdAt: -1 });

        const decryptedPasswords = passwords.map(pwd => ({
            ...pwd.toObject(),
            password: decrypt(pwd.password)
        }));

        res.json({
            success: true,
            passwords: decryptedPasswords
        });
    } catch (error) {
        console.error('Get passwords error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch passwords'
        });
    }
});

// Update password
app.put('/api/passwords/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { website, username, password, notes } = req.body;

        const existingPassword = await Password.findOne({
            _id: id,
            userId: req.user._id
        });

        if (!existingPassword) {
            return res.status(404).json({ 
                success: false, 
                message: 'Password not found' 
            });
        }

        const encryptedPassword = encrypt(password);

        existingPassword.website = website;
        existingPassword.username = username;
        existingPassword.password = encryptedPassword;
        existingPassword.notes = notes || '';

        await existingPassword.save();

        res.json({
            success: true,
            message: 'Password updated successfully',
            password: {
                ...existingPassword.toObject(),
                password: password
            }
        });
    } catch (error) {
        console.error('Update password error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update password'
        });
    }
});

// Delete password
app.delete('/api/passwords/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        const password = await Password.findOneAndDelete({
            _id: id,
            userId: req.user._id
        });

        if (!password) {
            return res.status(404).json({ 
                success: false, 
                message: 'Password not found' 
            });
        }

        res.json({
            success: true,
            message: 'Password deleted successfully'
        });
    } catch (error) {
        console.error('Delete password error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete password'
        });
    }
});

// Get user profile
app.get('/api/auth/profile', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                createdAt: req.user.createdAt
            }
        });
    } catch (error) {
        console.error('Profile error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch profile'
        });
    }
});

// Serve static files (for frontend)
app.use(express.static('.'));

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📁 API Base URL: http://localhost:${PORT}/api`);
    console.log(`🌐 Frontend: http://localhost:${PORT}/index.html`);
    console.log(`🔧 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔧 Test route: http://localhost:${PORT}/api/test`);
});