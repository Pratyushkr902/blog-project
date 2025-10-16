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
app.use(cors({
    origin: process.env.FRONTEND_URL, // Make sure FRONTEND_URL is in your .env
    credentials: true
}));
app.use(express.json());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
}).then(() => {
  console.log('✅ Connected to MongoDB');
}).catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// --- MONGOOSE MODELS ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }]
}, { timestamps: true });

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    next();
});

userSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '10m' }
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
transporter.verify().then(() => console.log('✅ Email transporter ready')).catch(err => console.error('⚠️ Email transporter error:', err.message));


// --- HELPER FUNCTIONS ---
const sendOtpEmail = async (email, subject, text) => {
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  await Otp.findOneAndUpdate({ email }, { code: otpCode }, { upsert: true, new: true });
  const mailOptions = { from: `"Jovial Flames" <${process.env.GMAIL_USER}>`, to: email, subject, text: `${text} ${otpCode}\nThis code will expire in 10 minutes.` };
  await transporter.sendMail(mailOptions);
  console.log(`OTP sent to ${email}: ${otpCode}`);
};

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};


// --- API ROUTES ---


// ✅ CORRECTED: Added /auth prefix to all routes
app.post('/auth/request-otp', [body('email').isEmail()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: 'User with this email already exists.' });
  await sendOtpEmail(email, 'Your Jovial Flames Verification Code', 'Welcome! Your OTP is:');
  res.status(200).json({ message: 'OTP sent successfully.' });
});

app.post('/auth/register', [
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
  await Otp.deleteOne({ email });
  res.status(201).json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
});
 

app.post('/auth/login', [body('email').isEmail(), body('password').notEmpty()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await user.matchPassword(password))) {
    const { password, ...userData } = user.toObject();
    res.json({ user: userData, token: generateToken(user._id) });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
});

app.post('/auth/forgot-password', [body('email').isEmail()], async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (user) {
        await sendOtpEmail(email, 'Your Password Reset Code', 'Your password reset OTP is:');
    }
    res.status(200).json({ message: 'If an account exists, an OTP has been sent.' });
});

app.post('/auth/reset-password', [
    body('email').isEmail(),
    body('otp').isLength({ min: 6, max: 6 }),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });
    const user = await User.findOne({ email });
    user.password = newPassword;
    await user.save();
    await Otp.deleteOne({ email });
    res.status(200).json({ message: 'Password has been reset successfully.' });
});
// In your main server.js, you might have something like this:
const authRoutes = require('./routes/auth'); // Make sure you import the router
app.use('/api/auth', authRoutes); // Make sure the base path is correct

// Then, inside your ./routes/auth.js file, you MUST have this:
router.post('/login', (req, res) => {
  // Your logic to handle the user login goes here
});

// Root route for testing
app.get('/api', (req, res) => {
    res.send('Jovial Flames API is running...');
});


// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});
// This tells your app what to do when it gets a GET request to the root URL
app.get('/', (req, res) => {
  res.send('Welcome to the Jovial Flames API! Server is running correctly. 🎉');
});