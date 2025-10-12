// server.js (Upgraded with MongoDB and JWT)

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected successfully.'))
    .catch(err => console.error('🔴 MongoDB connection error:', err));

// --- MONGOOSE SCHEMA & MODEL ---
const OrderSchema = new mongoose.Schema({
    id: { type: String, required: true },
    date: { type: String, required: true },
    items: { type: Array, required: true },
    grandTotal: { type: Number, required: true },
    paymentMethod: { type: String, required: true },
    status: { type: String, default: 'Order Placed' },
    lastUpdate: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    orders: [OrderSchema]
});

const User = mongoose.model('User', UserSchema);

// --- IN-MEMORY OTP STORE (remains the same) ---
let otps = {};

// --- INSTANCES (remains the same) ---
const razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }});

// --- JWT AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user;
        next();
    });
};


// --- AUTHENTICATION ROUTES (Refactored for MongoDB) ---

app.post('/api/signup-request-otp', async (req, res) => {
    const { email } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(400).json({ message: "An account with this email already exists." });
    }
    // OTP logic remains the same
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };
    // Nodemailer logic remains the same
    res.status(200).json({ message: "OTP sent successfully." });
});

app.post('/api/signup-verify', async (req, res) => {
    const { name, email, password, otp } = req.body;
    const storedOtp = otps[email];
    if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires) {
        return res.status(400).json({ message: "Invalid or expired OTP." });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ name, email, password: hashedPassword, orders: [] });
        delete otps[email];
        res.status(201).json({ message: "Account created successfully." });
    } catch (error) {
        res.status(500).json({ message: "Error creating user." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ message: "User not found." });
    }
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (isPasswordCorrect) {
        // Create JWT
        const accessToken = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
        // Return user data (without password) and the token
        const { password, ...userData } = user.toObject();
        res.status(200).json({ message: "Login successful.", user: userData, token: accessToken });
    } else {
        res.status(401).json({ message: "Invalid password." });
    }
});

// Forgot Password and Reset routes would be refactored similarly to use User.findOne and user.save()

// --- PAYMENT & ORDER ROUTES (Now Protected) ---

// Create Razorpay Order (doesn't need to be protected)
app.post('/api/payment/create-order', (req, res) => { /* ... same as before ... */ });

// Verify Payment (doesn't need to be protected)
app.post('/api/payment/verify', (req, res) => { /* ... same as before ... */ });

// Place Order (PROTECTED - only logged-in users can do this)
app.post('/api/order/place', authenticateToken, async (req, res) => {
    const { orderDetails } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        user.orders.push(orderDetails);
        await user.save();
        
        res.status(201).json({ message: `Order #${orderDetails.id} has been placed.`, order: orderDetails });
    } catch (error) {
        res.status(500).json({ message: "Error placing order." });
    }
});


// --- SERVER START ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});
// Add these new routes to server.js

// GET ALL PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error fetching products." });
    }
});

// SEARCH FOR PRODUCTS (the "where" clause)
app.get('/api/products/search', async (req, res) => {
    try {
        const searchTerm = req.query.q; // Get search term from query parameter ?q=...

        if (!searchTerm) {
            return res.status(400).json({ message: "Search term is required." });
        }

        const products = await Product.find({
            // This is the "where" part: find products where the name matches the search term.
            // $regex provides "like" functionality, and 'i' makes it case-insensitive.
            name: { $regex: searchTerm, $options: 'i' }
        });

        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error searching for products." });
    }
});