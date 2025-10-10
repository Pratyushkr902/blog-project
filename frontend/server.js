const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;

const allowedOrigins = [
  'https://www.jovialflames.com',
  'https://jovialflames.com'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('❌ CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Handle preflight requests globally
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  return res.sendStatus(200);
});

app.use(express.json());

// Simple test route
app.get('/', (req, res) => {
  res.send('✅ Jovial Flames API is running fine!');
});

// OTP sending route
app.post('/api/signup-request-otp', (req, res) => {
  const { email } = req.body;
  console.log('📩 OTP request received for:', email);

  if (!email) return res.status(400).json({ message: "Email required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  console.log('Generated OTP:', otp);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  transporter.sendMail({
    from: '"Jovial Flames" <00pratyush20@gmail.com>',
    to: email,
    subject: 'Your OTP for Jovial Flames',
    text: `Your verification code is: ${otp}`,
  }, (err, info) => {
    if (err) {
      console.error('Email send error:', err);
      return res.status(500).json({ message: "Failed to send OTP" });
    }
    console.log('✅ OTP sent successfully:', info.response);
    res.status(200).json({ message: "OTP sent successfully" });
  });
});

app.listen(PORT, () => console.log(`🚀 Server live on port ${PORT}`));
