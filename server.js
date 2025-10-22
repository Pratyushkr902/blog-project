// ================== IMPORTS ==================
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
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

// --- OTP Schema ---
const OtpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    code: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '10m' }
});
const Otp = mongoose.models.Otp || mongoose.model('Otp', OtpSchema);

// --- ⭐️ FIX 1: ADDED MISSING CONTACT QUERY MODEL ---
const ContactQuerySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
// This will save to the 'contactqueries' collection
const ContactQuery = mongoose.models.ContactQuery || mongoose.model('ContactQuery', ContactQuerySchema);


// ================== SETUP SERVICES ==================
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendEmail = async (to, subject, text) => {
  const msg = {
    to: to,
    from: 'noreply@jovialflames.com', // ❗️ Ensure this is your SendGrid Verified Sender
    subject: subject,
    text: text,
  };
  console.log(`Attempting to send email to ${to} via SendGrid...`);
  try {
    await sgMail.send(msg);
    console.log(`✅ Email sent successfully to ${to}`);
  } catch (error) {
    console.error(`🔴 Failed to send email to ${to}:`, error);
    if (error.response) {
      console.error('SendGrid Error Body:', error.response.body);
    }
    throw new Error('Failed to send email.');
  }
};

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

app.post('/api/signup-request-otp', async (req, res) => { 
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required.' });
  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ message: 'An account with this email already exists.' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try {
    await Otp.findOneAndUpdate({ email }, { code: otp, createdAt: Date.now() }, { upsert: true });
    await sendEmail(
      email,
      'Your OTP for Jovial Flames',
      `Your OTP is: ${otp}. It is valid for 10 minutes.`
    );
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

app.post('/api/signup-verify', async (req, res) => {
  const { name, email, password, otp } = req.body;
  if (!name || !email || !password || !otp) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword, orders: [] });
    await Otp.deleteOne({ email });
    res.status(201).json({ message: 'Account created successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
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

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(200).json({ message: 'If an account exists, an OTP has been sent.' });
  }
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try {
    await Otp.findOneAndUpdate({ email }, { code: otp, createdAt: Date.now() }, { upsert: true });
    await sendEmail(
      email,
      'Password Reset OTP',
      `Your password reset OTP is: ${otp}. It is valid for 10 minutes.`
    );
    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to send OTP.' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    const storedOtp = await Otp.findOne({ email, code: otp });
    if (!storedOtp) return res.status(400).json({ message: 'Invalid or expired OTP.' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { password: hashedPassword });
    await Otp.deleteOne({ email, code: otp });
    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password.' });
  }
});

// --- ⭐️ FIX 2: MOVED CONTACT & SUBSCRIBE ROUTES TO THEIR OWN SECTION ---

// --- CONTACT & SUBSCRIBE ROUTES ---

app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    // This now works because the Model is defined above
    await ContactQuery.create({ name, email, message });

    const adminEmail = 'jovialflames@gmail.com';
    const subject = `New Contact Message from ${name}`;
    const text = `You have a new message from:\nName: ${name}\nEmail: ${email}\nMessage:\n${message}`;
    
    await sendEmail(adminEmail, subject, text);
    res.status(200).json({ message: 'Message sent successfully!' });
  } catch (error) {
    console.error('Error sending contact email:', error);
    res.status(500).json({ message: 'Failed to send message.' });
  }
});

app.post('/api/subscribe', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }
  try {
    // You could also save this email to a 'Subscribers' collection if you want
    const subject = 'Your 10% Discount Code from Jovial Flames!';
    const text = `Thank you for subscribing!\n\nUse this discount code for 10% off your next order: JOVIAL10\n\nWe're happy to have you!`;
    
    await sendEmail(email, subject, text);
    res.status(200).json({ message: `Discount code sent to ${email}!` });
  } catch (error) {
    console.error('Error sending subscribe email:', error);
    res.status(500).json({ message: 'Failed to send email.' });
  }
});


// --- ORDER & PAYMENT ROUTES ---

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

    for (const item of items) {
        const product = await Product.findOne({ name: item.name });
        if (!product) {
            return res.status(404).json({ message: `Product not found: ${item.name}` });
        }
        subtotal += product.price * item.quantity;
        finalOrderItems.push({
            name: product.name,
            price: product.price,
            quantity: item.quantity
        });
    }

    const shippingCharges = (subtotal < 299) ? 99 : (subtotal < 499) ? 49 : 0;
    const grandTotal = subtotal + shippingCharges;

    const finalOrder = {
        id: 'JF' + Date.now().toString().slice(-6),
        date: new Date().toLocaleDateString('en-IN'),
        items: finalOrderItems,
        grandTotal: grandTotal,
        paymentMethod: paymentMethod,
        status: 'Order Placed',
        ...customerDetails
    };

    user.orders.push(finalOrder);
    await user.save();
    
    const { password: _, ...userData } = user.toObject();
    res.status(201).json({ message: `Order #${finalOrder.id} placed.`, user: userData });
  } catch (error) {
    console.error("Error placing order:", error);
    res.status(500).json({ message: 'Error placing order.' });
  }
});

app.get('/api/orders/track/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  if (!orderId) {
    return res.status(400).json({ message: 'Order ID is required.' });
  }
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    const order = user.orders.id(orderId) || user.orders.find(o => o.id === orderId);
    if (!order) {
      console.log(`Order tracking attempt: Order ${orderId} not found for user ${user.email}`);
      return res.status(404).json({ message: `Order ${orderId} not found.` });
    }
    console.log(`Order tracking success: Found order ${orderId} for user ${user.email}`);
    res.status(200).json({ order: order });
  } catch (error) {
    console.error(`🔴 Error tracking order ${orderId} for user ${req.user?.email}:`, error);
    res.status(500).json({ message: 'Error tracking order.' });
  }
});

// --- 404 Handler ---
app.use((req, res) => {
  res.status(404).json({ message: `Endpoint Not Found: ${req.method} ${req.originalUrl}` });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));