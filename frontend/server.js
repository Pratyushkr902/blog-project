// server.js - Jovial Flames (complete)
// -----------------------------------
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// ---------- App setup ----------
const app = express();
app.use(express.json());

// ---------- CORS ----------
const allowedOrigins = [
  'https://www.jovialflames.com', // production frontend
  'http://localhost:3000',        // react dev
  'http://localhost:3001',
  'https://localhost:3001'
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true
}));

// ---------- MongoDB ----------
mongoose.connect(process.env.MONGO_URI, {
})
.then(() => console.log('✅ MongoDB connected successfully.'))
.catch(err => console.error('🔴 MongoDB connection error:', err));

// ---------- Schemas & Models ----------
const OrderSchema = new mongoose.Schema({
  id: { type: String, required: true },
  date: { type: String, required: true },
  items: { type: Array, required: true },
  grandTotal: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  status: { type: String, default: 'Order Placed' },
  lastUpdate: { type: Date, default: Date.now },
  customerName: { type: String, required: true },
  customerPhone: { type: String, required: true },
  deliveryAddress: { type: String, required: true },
  pincode: { type: String, required: true }
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  image: String,
  category: String,
  stock: { type: Number, default: 0 }
});
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  orders: [OrderSchema]
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ---------- Services ----------
const otps = {}; // in-memory OTP store (OK for small app)
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Nodemailer transporter - Gmail (use app password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // e.g. youremail@gmail.com
    pass: process.env.GMAIL_PASS  // app password
  }
});
// optional: verify transporter on startup
transporter.verify().then(() => console.log('✅ Email transporter ready')).catch(err => console.error('⚠️ Email transporter error:', err.message));

// ---------- Auth middleware ----------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ---------- Routes ----------

// --- Signup: request OTP
app.post('/api/signup-request-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "An account with this email already exists." });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your Jovial Flames OTP',
      text: `Your OTP is: ${otp}`
    });

    res.status(200).json({ message: "OTP sent successfully." });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: "Failed to send OTP." });
  }
});

// --- Signup: verify OTP & create account
app.post('/api/signup-verify', async (req, res) => {
  const { name, email, password, otp } = req.body;
  const stored = otps[email];
  if (!stored || stored.code !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ message: "Invalid or expired OTP." });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword, orders: [] });
    delete otps[email];
    res.status(201).json({ message: "Account created successfully." });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: "Error creating user." });
  }
});

// --- Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found." });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid password." });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const { password: _, ...userData } = user.toObject();
    res.status(200).json({ message: "Login successful.", user: userData, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: "Server error during login." });
  }
});

// --- Forgot password (send OTP)
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    // Always respond 200 to avoid leaking user existence
    if (!user) return res.status(200).json({ message: "If an account exists, an OTP has been sent." });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };
    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your Password Reset OTP',
      text: `Your OTP is: ${otp}`
    });
    res.status(200).json({ message: "If an account exists, an OTP has been sent." });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: "Failed to send OTP." });
  }
});

// --- Reset password
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const stored = otps[email];
  if (!stored || stored.code !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ message: "Invalid or expired OTP." });
  }
  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { $set: { password: hashed } });
    delete otps[email];
    res.status(200).json({ message: "Password has been reset successfully." });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: "Error resetting password." });
  }
});

// --- Products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.status(200).json(products);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ message: "Error fetching products." });
  }
});

app.get('/api/products/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ message: "Search term is required." });
  try {
    const products = await Product.find({ name: { $regex: q, $options: 'i' } });
    res.status(200).json(products);
  } catch (err) {
    console.error('Search products error:', err);
    res.status(500).json({ message: "Error searching products." });
  }
});

// --- Razorpay: create order
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || isNaN(amount)) return res.status(400).json({ message: "Valid amount is required." });

    const options = {
      amount: Math.round(amount * 100), // paise
      currency: 'INR',
      receipt: crypto.randomBytes(10).toString('hex')
    };
    const order = await razorpay.orders.create(options);
    res.status(200).json(order);
  } catch (err) {
    console.error('Error creating razorpay order:', err);
    res.status(500).json({ message: "Failed to create order." });
  }
});

// --- Razorpay: verify payment
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ message: "Missing verification fields." });
    }

    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

    if (expected === razorpay_signature) {
      return res.status(200).json({ message: "Payment verified successfully." });
    } else {
      return res.status(400).json({ message: "Invalid signature." });
    }
  } catch (err) {
    console.error('Payment verification error:', err);
    res.status(500).json({ message: "Payment verification failed." });
  }
});

// --- Place order (used for both online and COD) ---
/*
  Expected body:
  {
    orderDetails: { id, date, items, grandTotal, customerName, customerPhone, deliveryAddress, pincode, ... },
    paymentMethod: 'online' | 'cod'
  }
*/
app.post('/api/order/place', authenticateToken, async (req, res) => {
  try {
    const { orderDetails, paymentMethod } = req.body;
    if (!orderDetails || !orderDetails.id) return res.status(400).json({ message: "Order details required." });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found." });

    // Push order
    user.orders.push({ ...orderDetails, paymentMethod, status: (paymentMethod === 'online' ? 'Paid' : 'Order Placed') });
    await user.save();

    // Send confirmation email
    const subject = paymentMethod === 'online' ? '🎉 Order Confirmed - Jovial Flames' : '🕯️ Order Placed - Cash on Delivery';
    const html = `
      <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.4">
        <h2>Thank you, ${orderDetails.customerName}!</h2>
        <p>Your order <strong>#${orderDetails.id}</strong> has been ${paymentMethod === 'online' ? 'confirmed and paid' : 'placed (Cash on Delivery)'}.</p>
        <p><strong>Amount:</strong> ₹${orderDetails.grandTotal}</p>
        <p><strong>Address:</strong> ${orderDetails.deliveryAddress} - ${orderDetails.pincode}</p>
        <h4>Items:</h4>
        <ul>
          ${orderDetails.items.map(i => `<li>${i.name} x ${i.quantity} — ₹${i.price * i.quantity}</li>`).join('')}
        </ul>
        <p>We’ll notify you when your order ships. 🌸</p>
        <hr />
        <p style="font-size:12px;color:#666">Jovial Flames • Handcrafted with love 🕯️</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: user.email,
      subject,
      html
    });

    return res.status(201).json({ message: `Order #${orderDetails.id} placed. Confirmation email sent.` });
  } catch (err) {
    console.error('Place order error:', err);
    res.status(500).json({ message: "Error placing order." });
  }
});

// --- Pay on delivery quick route (if frontend uses it directly) ---
app.post('/api/pay-on-delivery', authenticateToken, async (req, res) => {
  // This can mirror /api/order/place but kept for compatibility if frontend expects /api/pay-on-delivery
  try {
    const { orderDetails } = req.body;
    if (!orderDetails) return res.status(400).json({ message: "Order details required." });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found." });

    user.orders.push({ ...orderDetails, paymentMethod: 'cod', status: 'Order Placed' });
    await user.save();

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: user.email,
      subject: '🕯️ Order Placed - Cash on Delivery',
      html: `<p>Hi ${orderDetails.customerName},</p><p>Your order #${orderDetails.id} has been placed and will be collected on delivery. Amount: ₹${orderDetails.grandTotal}.</p>`
    });

    return res.status(201).json({ message: 'Order placed with COD. Email sent.' });
  } catch (err) {
    console.error('COD place order error:', err);
    res.status(500).json({ message: 'Failed to place COD order.' });
  }
});

// --- 404 handler ---
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint Not Found. Check URL & Method.', requested: `${req.method} ${req.originalUrl}` });
});

// --- Global error handler (basic) ---
app.use((err, req, res, next) => {
  console.error('GLOBAL ERROR:', err.stack || err);
  res.status(err.status || 500).json({ message: err.message || 'Internal Server Error' });
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
