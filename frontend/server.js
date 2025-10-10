const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;

// --------------------
// ✅ Middleware setup
// --------------------
app.use(express.json());

// Log all incoming requests (useful for Render logs)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} | Origin: ${req.headers.origin || 'none'}`);
  next();
});

// --------------------
// ✅ CORS Configuration
// --------------------
const allowedOrigins = [
  'https://www.jovialflames.com',
  'https://jovialflames.com',
  'https://jovial-flames-api.onrender.com'  // Add this line
];


app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('❌ Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// ✅ Handle preflight requests explicitly
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(204);
});

// --------------------
// 🧠 In-memory store
// --------------------
let users = [];
let otps = {};

// --------------------
// 🌐 Root route
// --------------------
app.get('/', (req, res) => {
  res.send('Welcome to Jovial Flames API! 🎉 Server is running.');
});

// --------------------
// 📧 Email transporter
// --------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// --------------------
// 🔑 Request OTP route
// --------------------
app.post('/api/signup-request-otp', async (req, res) => {
  const { email } = req.body;
  console.log('📩 OTP request for:', email);

  if (!email) return res.status(400).json({ message: 'Email is required.' });
  if (users.find((u) => u.email === email)) {
    return res.status(400).json({ message: 'Email already registered.' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otps[email] = otp;

  try {
    const info = await transporter.sendMail({
      from: '"Jovial Flames" <00pratyush20@gmail.com>',
      to: email,
      subject: 'Your Verification Code',
      text: `Your OTP for Jovial Flames is: ${otp}`,
    });

    console.log('✅ OTP sent:', info.response);
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (error) {
    console.error('❌ Email send error:', error);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

// --------------------
// 🧾 Verify OTP route
// --------------------
app.post('/api/signup-verify', (req, res) => {
  const { name, email, password, otp } = req.body;

  if (otps[email] === otp) {
    users.push({ name, email, password, orders: [] });
    delete otps[email];
    console.log('🎉 New user registered:', email);
    return res.status(201).json({ message: 'User created successfully.' });
  } else {
    return res.status(400).json({ message: 'Invalid OTP.' });
  }
});

// --------------------
// 🚀 Start the server
// --------------------
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
