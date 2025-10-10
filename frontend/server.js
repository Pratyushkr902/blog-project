// server.js (Updated for Razorpay)

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

// WARNING: In-memory data will be lost on restart. Use a database for production.
let users = [];
let otps = {};

// --- Razorpay Instance ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// --- USER & AUTH ROUTES (Unchanged) ---
// (The existing /api/signup-request-otp, /signup-verify, /login, etc. routes are here)
// ... [Previous auth routes remain the same] ...

// --- PAYMENT ROUTES ---

// 1. Create Razorpay Order
app.post('/api/payment/create-order', (req, res) => {
    const { amount, currency = 'INR' } = req.body;
    if (!amount) {
        return res.status(400).json({ message: "Amount is required." });
    }

    const options = {
        amount: amount * 100, // Amount in the smallest currency unit (paise)
        currency,
        receipt: `receipt_order_${new Date().getTime()}`
    };

    razorpay.orders.create(options, (error, order) => {
        if (error) {
            console.error("Razorpay order creation error:", error);
            return res.status(500).json({ message: "Something went wrong with payment." });
        }
        res.status(200).json(order);
    });
});

// 2. Verify Payment
app.post('/api/payment/verify', (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;

    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(body.toString())
        .digest('hex');

    if (expectedSignature === razorpay_signature) {
        // Payment is authentic
        res.status(200).json({ status: 'success' });
    } else {
        res.status(400).json({ status: 'failure' });
    }
});

// --- ORDER PLACEMENT ROUTE ---
app.post('/api/order/place', (req, res) => {
    const { userEmail, orderDetails } = req.body;
    const userIndex = users.findIndex(u => u.email === userEmail);

    if (userIndex === -1) {
        return res.status(404).json({ message: "User not found." });
    }

    if (!users[userIndex].orders) {
        users[userIndex].orders = [];
    }
    users[userIndex].orders.push(orderDetails);
    
    console.log(`Order placed for ${userEmail}: Order ID ${orderDetails.id}`);
    res.status(201).json({ message: `Order #${orderDetails.id} has been placed.`, order: orderDetails });
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});