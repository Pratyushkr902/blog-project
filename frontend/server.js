// server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
app.use(express.json()); // Middleware to parse JSON bodies

// --- CORS Configuration ---
const allowedOrigins = [
    'https://www.jovialflames.com', // Your public frontend domain
    'https://localhost:3001', 
    'http://localhost:3001'   
];

const corsOptions = {
  origin: (origin, callback) => {
    // Allows requests from approved origins or origins with no specified origin (e.g., Postman)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));


// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected successfully.'))
    .catch(err => console.error('🔴 MongoDB connection error:', err));
   
    
// --- MONGOOSE SCHEMA & MODEL DEFINITION (Using Existence Check to prevent OverwriteModelError) ---

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
    description: { type: String },
    price: { type: Number, required: true },
    image: { type: String },
    category: { type: String },
    stock: { type: Number, default: 0 }
});
// Existence check: prevents OverwriteModelError
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);


const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    orders: [OrderSchema]
});
// Existence check: prevents OverwriteModelError
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- IN-MEMORY OTP STORE & INSTANCES ---
let otps = {};
const razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }});

// --- JWT AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user; 
        next();
    });
};


// ====================================================================
// --- API ROUTE SECTION (ALL WORKING ROUTES DEFINED HERE IN ORDER) ---
// ====================================================================


// --- AUTHENTICATION ROUTES ---

app.post('/api/signup-request-otp', async (req, res) => {
  const { email } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "An account with this email already exists." });
  }
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };
  try {
    await transporter.sendMail({
      from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Your OTP for Jovial Flames",
      text: `Your OTP is: ${otp}`
    });
    res.status(200).json({ message: "OTP sent successfully." });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ message: "Failed to send OTP." });
  }
});


app.post('/api/signup-verify', async (req, res) => {
    const { name, email, password, otp } = req.body;
    const storedOtp = otps[email];
    if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires) {
        return res.status(400).json({ message: "Invalid or expired OTP." });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ name, email, password: hashedPassword, orders: [] });
        delete otps[email];
        res.status(201).json({ message: "Account created successfully." });
    } catch (error) {
        res.status(500).json({ message: "Error creating user." });
    }
});

// ➡️ LOGIN ROUTE (Fixed 404 issue by correct placement)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Return 404 only if user not found; generic login failure is 401
      return res.status(404).json({ message: "User not found." }); 
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Invalid password." });
    }

    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    const { password: _, ...userData } = user.toObject();

    res.status(200).json({
      message: "Login successful.",
      user: userData,
      token: accessToken
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login." });
  }
});


app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(200).json({ message: "If an account with this email exists, an OTP has been sent." });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 };
        await transporter.sendMail({
            from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: "Your Password Reset OTP",
            text: `Your OTP to reset your password is: ${otp}`
        });

        res.status(200).json({ message: "If an account with this email exists, an OTP has been sent." });
    } catch (err) {
        console.error("Forgot password error:", err);
        res.status(500).json({ message: "Failed to send OTP." });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const storedOtp = otps[email];
    if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires) {
        return res.status(400).json({ message: "Invalid or expired OTP." });
    }
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.updateOne({ email: email }, { $set: { password: hashedPassword } });
        delete otps[email];
        res.status(200).json({ message: "Password has been reset successfully." });
    } catch (error) {
        console.error("Reset password error:", error);
        res.status(500).json({ message: "Error resetting password." });
    }
});


// --- PAYMENT & ORDER ROUTES ---

app.post('/api/payment/create-order', async (req, res) => {
  try {
    const options = {
      amount: req.body.amount * 100, // amount in paise
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

// server.js or app.js
app.post("/api/pay-online", (req, res) => {
  // your Razorpay / Stripe logic here
  res.json({ success: true, message: "Payment initiated" });
});

app.post("/api/pay-on-delivery", (req, res) => {
  // Save order as COD
  res.json({ success: true, message: "Order placed with COD" });
});


app.post('/api/payment/verify', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (razorpay_signature === expectedSign) {
      res.status(200).json({ message: "Payment verified successfully." });
    } else {
      res.status(400).json({ message: "Invalid signature." });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ message: "Payment verification failed." });
  }
});



// ➡️ ORDER PLACEMENT ROUTE (Fixed 404 issue by correct placement)
app.post('/api/order/place', authenticateToken, async (req, res) => {
    const { orderDetails } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        user.orders.push(orderDetails);
        await user.save();
        
        res.status(201).json({ message: `Order #${orderDetails.id} has been placed.`, order: orderDetails });
    } catch (error) {
        console.error("SERVER-SIDE ERROR PLACING ORDER:", error); 
        res.status(500).json({ message: "Error placing order." });
    }
});


// --- PRODUCT ROUTES (Placed before 404 handler) ---

// ➡️ GET ALL PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error fetching products." });
    }
});

// ➡️ SEARCH FOR PRODUCTS
app.get('/api/products/search', async (req, res) => {
    try {
        const searchTerm = req.query.q;

        if (!searchTerm) {
            return res.status(400).json({ message: "Search term is required." });
        }

        const products = await Product.find({
            name: { $regex: searchTerm, $options: 'i' }
        });

        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error searching for products." });
    }
});


// ====================================================================
// --- ERROR HANDLERS (MUST BE DEFINED AFTER ALL WORKING ROUTES) ---
// ====================================================================


// --- 404 NOT FOUND HANDLER (CATCH-ALL) ---
// ⚠️ This must be the last app.use() before the global error handler
app.use((req, res, next) => {
    // This runs if no route above has responded.
    res.status(404).json({
        message: 'Endpoint Not Found. Check URL and Method.',
        requested: `${req.method} ${req.originalUrl}`
    });
});


// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
    console.error("GLOBAL SERVER ERROR STACK:", err.stack);
    // Send 500 status code
    res.status(err.status || 500).json({
        message: err.message || "Internal Server Error. Please check server logs.",
        error: process.env.NODE_ENV === 'development' ? err.stack : undefined 
    });
});


// --- SERVER START ---
const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`⚠️ Port ${PORT} is busy. Trying next port...`);
    server.listen(PORT + 1);
  } else {
    console.error(err);
  }
});