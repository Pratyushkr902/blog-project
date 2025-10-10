const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;

// --- CORS Setup ---
const allowedOrigins = ['https://www.jovialflames.com', 'https://jovialflames.com'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.options('*', cors());
app.use(express.json());

// --- In-memory store ---
let users = [];
let otps = {};

// --- Root Route ---
app.get('/', (req, res) => {
  res.send('Welcome to Jovial Flames API! 🎉 Server is running.');
});

// --- Email Transporter ---
let transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // set in Render → Environment → GMAIL_USER
    pass: process.env.GMAIL_PASS, // set in Render → Environment → GMAIL_PASS
  },
});

// --- Request OTP Route ---
app.post('/api/signup-request-otp', (req, res) => {
  const { email } = req.body;

  console.log('OTP request received for:', email);

  if (!email) return res.status(400).json({ message: "Email is required." });
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "Email already registered." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otps[email] = otp;

  transporter.sendMail({
    from: '"Jovial Flames" <00pratyush20@gmail.com>',
    to: email,
    subject: 'Your Verification Code',
    text: `Your OTP for Jovial Flames is: ${otp}`,
  }, (error, info) => {
    if (error) {
      console.log('Email send error:', error);
      return res.status(500).json({ message: "Failed to send OTP." });
    }
    console.log('OTP Sent:', info.response);
    res.status(200).json({ message: "OTP sent successfully." });
  });
});

// --- Verify OTP & Signup ---
app.post('/api/signup-verify', (req, res) => {
  const { name, email, password, otp } = req.body;

  if (otps[email] === otp) {
    users.push({ name, email, password, orders: [] });
    delete otps[email];
    console.log('New user registered:', email);
    return res.status(201).json({ message: "User created successfully." });
  } else {
    return res.status(400).json({ message: "Invalid OTP." });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
