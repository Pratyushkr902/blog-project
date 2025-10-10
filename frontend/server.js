// server.js
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables from Render

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed origins
const allowedOrigins = [
  'https://www.jovialflames.com',
  'https://jovialflames.com'
];

// CORS configuration
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('❌ CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Handle preflight requests
app.options('*', cors());

// Parse JSON
app.use(express.json());

// In-memory stores (replace with DB in production)
let users = [];
let otps = {};

// Root route
app.get('/', (req, res) => res.send('✅ Jovial Flames API is running!'));

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // your Gmail
    pass: process.env.GMAIL_PASS  // Gmail App Password
  }
});

// Signup OTP request
app.post('/api/signup-request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = otp;
    console.log('Generated OTP for', email, otp);

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your OTP for Jovial Flames',
      text: `Your verification code is: ${otp}`
    });

    console.log('✅ OTP sent to', email);
    res.status(200).json({ message: "OTP sent successfully" });

  } catch (error) {
    console.error('❌ OTP Error:', error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

// Verify OTP & signup
app.post('/api/signup-verify', (req, res) => {
  const { name, email, password, otp } = req.body;

  if (!otps[email]) return res.status(400).json({ message: "OTP expired or not requested" });
  if (otps[email] !== otp) return res.status(400).json({ message: "Invalid OTP" });

  users.push({ name, email, password, orders: [] });
  delete otps[email];
  console.log('✅ New user registered:', email);
  res.status(201).json({ message: "User created successfully" });
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server live on port ${PORT}`));
