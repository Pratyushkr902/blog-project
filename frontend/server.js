// --- IMPORTS ---
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// --- INITIALIZATIONS ---
const app = express();
const SALT_ROUNDS = 10;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
}).then(() => {
  console.log('✅ Connected to MongoDB');
}).catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1); // Exit if DB connection fails
});

// --- MONGOOSE MODELS ---
// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }] // Example reference
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// OTP Schema (with auto-expiration)
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '10m' } // OTP expires in 10 minutes
});

const Otp = mongoose.model('Otp', otpSchema);

// --- NODEMAILER TRANSPORTER ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// --- VALIDATION RULES ---
const signupValidationRules = [
  body('name').notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

const emailValidationRules = [
  body('email').isEmail().withMessage('Please provide a valid email'),
];

const passwordResetValidationRules = [
  body('email').isEmail().withMessage('Email is required'),
  body('otp').notEmpty().withMessage('OTP is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long'),
];

// --- HELPER FUNCTION TO SEND OTP ---
const sendOtpEmail = async (email, subject, text) => {
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  await Otp.findOneAndUpdate({ email }, { code: otpCode }, { upsert: true, new: true });

  const mailOptions = {
    from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: subject,
    text: `${text} ${otpCode}\nThis code will expire in 10 minutes.`,
  };

  await transporter.sendMail(mailOptions);
  console.log(`OTP sent to ${email}: ${otpCode}`);
};


// --- API ROUTES ---

// 1. SIGNUP: Request an OTP
app.post('/api/signup-request-otp', emailValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'An account with this email already exists.' });
    }

    await sendOtpEmail(email, 'Your Jovial Flames Verification Code', 'Welcome to Jovial Flames! Your One-Time Password (OTP) is:');
    res.status(200).json({ message: 'OTP sent successfully to your email.' });
  } catch (error) {
    console.error('Error in /signup-request-otp:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// 2. SIGNUP: Verify OTP and Create User
app.post('/api/signup-verify', signupValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password, otp } = req.body;

  try {
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    await Otp.deleteOne({ email }); // Clean up used OTP

    res.status(201).json({ message: 'Account created successfully. You can now log in.' });
  } catch (error) {
    console.error('Error in /signup-verify:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// 3. LOGIN
app.post('/api/login', [body('email').isEmail(), body('password').notEmpty()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found. Please check your email or sign up.' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Create and sign JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
      
    // Return user data (without password) and token
    const { password: _, ...userData } = user.toObject();
    res.status(200).json({ message: 'Login successful.', user: userData, token });
  } catch (error) {
    console.error('Error in /login:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// 4. FORGOT PASSWORD: Request an OTP
app.post('/api/forgot-password-request-otp', emailValidationRules, async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (user) {
    try {
      await sendOtpEmail(email, 'Your Password Reset Code', 'Your password reset OTP is:');
    } catch (error) {
       console.error("Error sending reset OTP:", error);
    }
  }

  // Always send a success-like message to prevent user enumeration attacks
  res.status(200).json({ message: 'If an account with this email exists, a password reset OTP has been sent.' });
});

// 5. FORGOT PASSWORD: Verify OTP and Reset Password
app.post('/api/reset-password-verify-otp', passwordResetValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, otp, newPassword } = req.body;

  try {
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await User.updateOne({ email }, { password: hashedPassword });

    await Otp.deleteOne({ email }); // Clean up

    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('Error in /reset-password-verify-otp:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});


// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 3001;

app.get('/', (req, res) => {
  res.send('Welcome to the Jovial Flames API! Server is running correctly. 🎉');
});

app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});