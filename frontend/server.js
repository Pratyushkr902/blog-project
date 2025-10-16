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
// This allows your frontend to make requests to this backend
app.use(cors({
    origin: process.env.FRONTEND_URL, // Make sure FRONTEND_URL is in your .env
    credentials: true
}));
// This allows Express to understand JSON request bodies
app.use(express.json());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1); // Exit the process if DB connection fails
  });

// --- MONGOOSE MODELS ---

// User Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }]
}, { timestamps: true });

// Middleware to automatically hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    next();
});

// Method to compare entered password with the hashed password
userSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

// OTP Model
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  // This OTP will automatically be deleted from the database after 10 minutes
  createdAt: { type: Date, default: Date.now, expires: '10m' }
});

const Otp = mongoose.model('Otp', otpSchema);

// --- NODEMAILER TRANSPORTER ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // Your Gmail address
    pass: process.env.GMAIL_PASS,   // Your Gmail App Password
  },
});

transporter.verify()
  .then(() => console.log('✅ Email transporter ready'))
  .catch(err => console.error('⚠️ Email transporter error:', err.message));

// --- HELPER FUNCTIONS ---

// Generates and sends an OTP
const sendOtpEmail = async (email, subject, text) => {
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  // Save or update the OTP in the database for the given email
  await Otp.findOneAndUpdate({ email }, { code: otpCode }, { upsert: true, new: true });
  
  const mailOptions = {
    from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
    to: email,
    subject,
    text: `${text} ${otpCode}\nThis code will expire in 10 minutes.`
  };
  
  await transporter.sendMail(mailOptions);
  console.log(`OTP sent to ${email}: ${otpCode}`);
};

// Generates a JWT token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// --- API ROUTES ---

// Root route for testing server status
app.get('/', (req, res) => {
  res.send('Welcome to the Jovial Flames API! Server is running correctly. 🎉');
});

// 1. REQUEST OTP FOR SIGNUP
app.post('/api/auth/request-otp', [body('email').isEmail()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { email } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: 'User with this email already exists.' });
  
  await sendOtpEmail(email, 'Your Jovial Flames Verification Code', 'Welcome! Your OTP is:');
  res.status(200).json({ message: 'OTP sent successfully.' });
});

// 2. REGISTER (VERIFY OTP AND CREATE USER)
app.post('/api/auth/register', [
  body('name').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { name, email, password, otp } = req.body;
  const storedOtp = await Otp.findOne({ email, code: otp });
  if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });
  
  const user = await User.create({ name, email, password });
  await Otp.deleteOne({ email }); // OTP is used, so delete it
  
  res.status(201).json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
});

// 3. LOGIN
app.post('/api/auth/login', [body('email').isEmail(), body('password').notEmpty()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && (await user.matchPassword(password))) {
    const { password, ...userData } = user.toObject(); // Send user data without the password
    res.json({ user: userData, token: generateToken(user._id) });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
});

// 4. FORGOT PASSWORD (REQUEST OTP)
app.post('/api/auth/forgot-password', [body('email').isEmail()], async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    // We send an OTP only if the user exists, but send a generic response for security
    if (user) {
        await sendOtpEmail(email, 'Your Password Reset Code', 'Your password reset OTP is:');
    }
    res.status(200).json({ message: 'If an account with that email exists, an OTP has been sent.' });
});

// 5. RESET PASSWORD (VERIFY OTP AND UPDATE PASSWORD)
app.post('/api/auth/reset-password', [
    body('email').isEmail(),
    body('otp').isLength({ min: 6, max: 6 }),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });

    const user = await User.findOne({ email });
    user.password = newPassword; // The 'pre.save' hook will hash this new password
    await user.save();
    
    await Otp.deleteOne({ email }); // OTP is used, so delete it
    res.status(200).json({ message: 'Password has been reset successfully.' });
});


// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});