// ================== IMPORTS ==================
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// ================== APP SETUP ==================
const app = express();
app.use(express.json());

// --- CORS Configuration ---
const allowedOrigins = [
  'https://www.jovialflames.com', // Production frontend
  'http://localhost:3000',        // Local frontend
  'http://localhost:3001',
  'https://localhost:3001'
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) callback(null, true);
      else callback(new Error('Not allowed by CORS'));
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true
  })
);

// ================== DATABASE CONNECTION ==================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully.'))
  .catch((err) => console.error('🔴 MongoDB connection error:', err));

// ================== MODELS ==================
const OrderSchema = new mongoose.Schema({
  id: String,
  date: String,
  items: Array,
  grandTotal: Number,
  paymentMethod: String,
  status: { type: String, default: 'Order Placed' },
  lastUpdate: { type: Date, default: Date.now },
  customerName: String,
  customerPhone: String,
  deliveryAddress: String,
  pincode: String
});

const ProductSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  image: String,
  category: String,
  stock: { type: Number, default: 0 }
});
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  orders: [OrderSchema]
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ================== SETUP SERVICES ==================
const otps = {};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ================== AUTH MIDDLEWARE ==================
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ================== ROUTES ==================

// --- SIGNUP OTP REQUEST ---
app.post('/api/signup-request-otp', async (req, res) => {
  const { email } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ message: 'An account with this email already exists.' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };

  try {
    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your OTP for Jovial Flames',
      text: `Your OTP is: ${otp}`
    });
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

// --- VERIFY OTP & CREATE ACCOUNT ---
app.post('/api/signup-verify', async (req, res) => {
  const { name, email, password, otp } = req.body;
  const storedOtp = otps[email];

  if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires)
    return res.status(400).json({ message: 'Invalid or expired OTP.' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword, orders: [] });
    delete otps[email];
    res.status(201).json({ message: 'Account created successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user.' });
  }
});

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect)
      return res.status(401).json({ message: 'Invalid password.' });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    const { password: _, ...userData } = user.toObject();
    res.status(200).json({ message: 'Login successful.', user: userData, token });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// --- FORGOT PASSWORD ---
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user)
    return res
      .status(200)
      .json({ message: 'If an account exists, an OTP has been sent.' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };

  try {
    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your Password Reset OTP',
      text: `Your OTP is: ${otp}`
    });
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (error) {
    console.error('Error sending reset OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

// --- RESET PASSWORD ---
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const storedOtp = otps[email];
  if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires)
    return res.status(400).json({ message: 'Invalid or expired OTP.' });

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { $set: { password: hashedPassword } });
    delete otps[email];
    res.status(200).json({ message: 'Password reset successful.' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password.' });
  }
});

// --- RAZORPAY CREATE ORDER ---
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const options = {
      amount: req.body.amount * 100, // in paise
      currency: 'INR',
      receipt: crypto.randomBytes(10).toString('hex')
    };
    const order = await razorpay.orders.create(options);
    res.status(200).json(order);
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({ message: 'Failed to create order.' });
  }
});

// --- RAZORPAY VERIFY PAYMENT ---
app.post('/api/payment/verify', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const sign = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest('hex');

    if (razorpay_signature === expectedSign)
      res.status(200).json({ message: 'Payment verified successfully.' });
    else res.status(400).json({ message: 'Invalid signature.' });
  } catch (error) {
    res.status(500).json({ message: 'Payment verification failed.' });
  }
});

// --- PAY ON DELIVERY ---
app.post('/api/pay-on-delivery', (req, res) => {
  res.json({ success: true, message: 'Order placed with Cash on Delivery.' });
});

// --- PLACE ORDER ---
app.post('/api/order/place', authenticateToken, async (req, res) => {
  const { orderDetails } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    user.orders.push(orderDetails);
    await user.save();
    res.status(201).json({ message: `Order #${orderDetails.id} placed.` });
  } catch (error) {
    res.status(500).json({ message: 'Error placing order.' });
  }
});

// --- GET ALL PRODUCTS ---
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products.' });
  }
});

// --- SEARCH PRODUCTS ---
app.get('/api/products/search', async (req, res) => {
  const searchTerm = req.query.q;
  if (!searchTerm) return res.status(400).json({ message: 'Search term is required.' });
  const products = await Product.find({ name: { $regex: searchTerm, $options: 'i' } });
  res.status(200).json(products);
});

// --- 404 Handler ---
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint Not Found.' });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
