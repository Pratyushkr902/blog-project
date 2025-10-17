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
// --- NOTE: For better performance on large datasets, consider adding a text index for searching.
// ProductSchema.index({ name: 'text', description: 'text' });
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  orders: [OrderSchema]
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- FIX: Storing OTPs in the database instead of in-memory for reliability. ---
// This prevents OTPs from being lost if the server restarts.
const OtpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    code: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '10m' } // OTP will be auto-deleted after 10 minutes
});
const Otp = mongoose.models.Otp || mongoose.model('Otp', OtpSchema);


// ================== SETUP SERVICES ==================
// --- FIX: In-memory OTP storage is removed as it's unreliable. ---
// const otps = {}; // This is no longer needed.

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
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// ================== ROUTES ==================

// --- SIGNUP OTP REQUEST ---
app.post('/api/signup-request-otp', async (req, res) => {
  const { email } = req.body;
  // --- NOTE: It's good practice to validate inputs.
  if (!email) return res.status(400).json({ message: 'Email is required.' });

  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ message: 'An account with this email already exists.' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  try {
    // --- FIX: Save OTP to the database. ---
    await Otp.findOneAndUpdate({ email }, { code: otp, createdAt: Date.now() }, { upsert: true });

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your OTP for Jovial Flames',
      text: `Your OTP is: ${otp}. It is valid for 10 minutes.`
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
  if (!name || !email || !password || !otp) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    // --- FIX: Retrieve OTP from the database. ---
    const storedOtp = await Otp.findOne({ email, code: otp });

    if (!storedOtp)
      return res.status(400).json({ message: 'Invalid or expired OTP.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword, orders: [] });
    
    // --- FIX: Clean up the used OTP. ---
    await Otp.deleteOne({ email });

    res.status(201).json({ message: 'Account created successfully.' });
  } catch (error) {
    console.error('Error during signup verification:', error);
    res.status(500).json({ message: 'Error creating user.' });
  }
});

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    // --- FIX: Use a generic error message to prevent user enumeration attacks. ---
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect)
      return res.status(401).json({ message: 'Invalid credentials.' });

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
  // This is good practice: don't reveal if an email is registered or not.
  if (!user)
    return res
      .status(200)
      .json({ message: 'If an account exists, an OTP has been sent.' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  try {
    // --- FIX: Save OTP to the database. ---
    await Otp.findOneAndUpdate({ email }, { code: otp, createdAt: Date.now() }, { upsert: true });
    
    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`
    });
    res.status(200).json({ message: 'If an account exists, an OTP has been sent.' });
  } catch (error) {
    console.error('Error sending reset OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

// --- RESET PASSWORD ---
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  // --- NOTE: Add validation for newPassword length/complexity. ---
  if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'All fields are required.' });
  }
  
  try {
    // --- FIX: Retrieve OTP from the database. ---
    const storedOtp = await Otp.findOne({ email, code: otp });

    if (!storedOtp)
      return res.status(400).json({ message: 'Invalid or expired OTP.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { $set: { password: hashedPassword } });
    
    // --- FIX: Clean up used OTP. ---
    await Otp.deleteOne({ email });

    res.status(200).json({ message: 'Password reset successful.' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password.' });
  }
});

// --- RAZORPAY CREATE ORDER ---
app.post('/api/payment/create-order', authenticateToken, async (req, res) => {
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
app.post('/api/payment/verify', authenticateToken, (req, res) => {
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
// --- NOTE: This endpoint appears to be unused. The main order logic is in /api/order/place. ---
app.post('/api/pay-on-delivery', (req, res) => {
  res.json({ success: true, message: 'Order placed with Cash on Delivery.' });
});

// --- PLACE ORDER ---
app.post('/api/order/place', authenticateToken, async (req, res) => {
  // --- FIX: CRITICAL SECURITY FIX - Recalculate total on the server. ---
  // NEVER trust prices or totals sent from the client.
  const { customerDetails, items, paymentMethod } = req.body;
  
  if (!customerDetails || !items || !paymentMethod || items.length === 0) {
      return res.status(400).json({ message: 'Missing order details.' });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    
    let subtotal = 0;
    const finalOrderItems = [];

    for (const item of items) {
        const product = await Product.findOne({ name: item.name });
        if (!product) {
            return res.status(404).json({ message: `Product not found: ${item.name}` });
        }
        // Add stock check if necessary:
        // if (product.stock < item.quantity) {
        //     return res.status(400).json({ message: `Not enough stock for ${item.name}` });
        // }
        subtotal += product.price * item.quantity;
        finalOrderItems.push({
            name: product.name,
            price: product.price, // Use price from DB
            quantity: item.quantity
        });
    }

    // Calculate shipping based on your rules
    const shippingCharges = (subtotal < 299) ? 99 : (subtotal < 499) ? 49 : 0;
    const grandTotal = subtotal + shippingCharges;

    const finalOrder = {
        id: 'JF' + Date.now().toString().slice(-6),
        date: new Date().toLocaleDateString('en-IN'),
        items: finalOrderItems, // Use the server-verified items
        grandTotal: grandTotal, // Use the server-calculated total
        paymentMethod: paymentMethod,
        status: 'Order Placed',
        ...customerDetails
    };

    user.orders.push(finalOrder);
    await user.save();
    res.status(201).json({ message: `Order #${finalOrder.id} placed.` });
  } catch (error) {
    console.error("Error placing order:", error);
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
  try {
    const products = await Product.find({ name: { $regex: searchTerm, $options: 'i' } });
    res.status(200).json(products);
  } catch (error) {
      res.status(500).json({ message: 'Error searching products.' });
  }
});

// --- 404 Handler ---
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint Not Found.' });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));