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
  'http://127.0.0.1:5500'        // For VS Code Live Server
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
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
// --- Order Schema ---
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

// --- Product Schema ---
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: String,
  price: { type: Number, required: true },
  image: String,
  category: String,
  stock: { type: Number, default: 0 }
});
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);

// --- User Schema ---
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  orders: [OrderSchema]
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ✅ FIX: Storing OTPs in the database for reliability.
const OtpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    code: { type: String, required: true },
    // This 'expires' option will automatically delete the OTP document from the database after 10 minutes.
    createdAt: { type: Date, default: Date.now, expires: '10m' }
});
const Otp = mongoose.models.Otp || mongoose.model('Otp', OtpSchema);


// ================== SETUP SERVICES ==================
// You can delete this old code
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

// --- USER & AUTH ROUTES ---

// ✅ FIX: Corrected route path to match frontend calls.
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required.' });

  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ message: 'An account with this email already exists.' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  try {
    // ✅ FIX: Save OTP to the database instead of a temporary variable.
    await Otp.findOneAndUpdate({ email }, { code: otp, createdAt: Date.now() }, { upsert: true });

    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`, to: email,
      subject: 'Your OTP for Jovial Flames',
      text: `Your OTP is: ${otp}. It is valid for 10 minutes.`
    });
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

// ✅ FIX: Corrected route path.
app.post('/api/users/verify-otp', async (req, res) => {
  const { name, email, password, otp } = req.body;
  if (!name || !email || !password || !otp) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    // ✅ FIX: Retrieve OTP from the database.
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword, orders: [] });
    
    // ✅ FIX: Clean up the used OTP from the database.
    await Otp.deleteOne({ email });

    res.status(201).json({ message: 'Account created successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user.' });
  }
});

// ✅ FIX: Corrected route path.
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    // ✅ FIX: Use a generic error message for security.
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) return res.status(401).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });

    const { password: _, ...userData } = user.toObject();
    res.status(200).json({ message: 'Login successful.', user: userData, token });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login.' });
  }
});


// --- ORDER & PAYMENT ROUTES ---

// ✅ FIX: Corrected route path and secured with authentication.
app.post('/api/orders/create-payment-order', authenticateToken, async (req, res) => {
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

// ✅ FIX: Corrected route path and secured with authentication.
app.post('/api/orders/verify-payment', authenticateToken, (req, res) => {
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

// ✅ FIX: CRITICAL SECURITY FIX - Recalculate total on the server.
// Also corrected route path and secured with authentication.
app.post('/api/orders/place', authenticateToken, async (req, res) => {
  const { items, customerDetails, paymentMethod } = req.body;
  
  if (!items || !customerDetails || !paymentMethod || items.length === 0) {
      return res.status(400).json({ message: 'Missing order details.' });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    
    let subtotal = 0;
    const finalOrderItems = [];

    // Loop through items sent from the client
    for (const item of items) {
        // Find the product in YOUR database to get the REAL price
        const product = await Product.findOne({ name: item.name });
        if (!product) {
            return res.status(404).json({ message: `Product not found: ${item.name}` });
        }
        // Add the database price to the subtotal
        subtotal += product.price * item.quantity;
        finalOrderItems.push({
            name: product.name,
            price: product.price, // Use price from DB, not from client
            quantity: item.quantity
        });
    }

    // Securely recalculate shipping and grand total on the server
    const shippingCharges = (subtotal < 299) ? 99 : (subtotal < 499) ? 49 : 0;
    const grandTotal = subtotal + shippingCharges;

    const finalOrder = {
        id: 'JF' + Date.now().toString().slice(-6),
        date: new Date().toLocaleDateString('en-IN'),
        items: finalOrderItems,
        grandTotal: grandTotal, // Use the server-calculated total
        paymentMethod: paymentMethod,
        status: 'Order Placed',
        ...customerDetails
    };

    user.orders.push(finalOrder);
    await user.save();
    
    // Send back the updated user object so the frontend knows about the new order
    const { password: _, ...userData } = user.toObject();
    res.status(201).json({ message: `Order #${finalOrder.id} placed.`, user: userData });
    
  } catch (error) {
    console.error("Error placing order:", error);
    res.status(500).json({ message: 'Error placing order.' });
  }
});


// --- 404 Handler ---
// This will catch any request that doesn't match a route above
app.use((req, res) => {
  res.status(404).json({ message: `Endpoint Not Found: ${req.method} ${req.originalUrl}` });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));