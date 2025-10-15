// server.js (Upgraded with MongoDB and JWT)

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
app.use(cors());
app.use(express.json());

const allowedOrigins = [
    'https://www.jovialflames.com', // ⬅️ Your public frontend domain
    // You can keep local origins for testing, but they should be removed in final production deployment
    'https://localhost:3001', 
    'http://localhost:3001'   
];

const corsOptions = {
  // Use the dynamic origin check to whitelist only approved domains
  origin: (origin, callback) => {
    // Allow requests from the approved list
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS')); // Block unauthorized domains
    }
  },
  // Ensure you allow the necessary methods and headers
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true, // Needed if you are sending cookies or session info
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));


// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected successfully.'))
    .catch(err => console.error('🔴 MongoDB connection error:', err));
   
    
// --- MONGOOSE SCHEMA & MODEL & product  ---

const OrderSchema = new mongoose.Schema({
    id: { type: String, required: true },
    date: { type: String, required: true },
    items: { type: Array, required: true },
    grandTotal: { type: Number, required: true },
    paymentMethod: { type: String, required: true },
    status: { type: String, default: 'Order Placed' },
    lastUpdate: { type: Date, default: Date.now },
    // ADD THESE NEW FIELDS
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
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);


const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    orders: [OrderSchema]
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);
// --- IN-MEMORY OTP STORE (remains the same) ---
let otps = {};

// --- INSTANCES (remains the same) ---
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


// --- AUTHENTICATION ROUTES (Refactored for MongoDB) ---
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

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1️⃣ Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // 2️⃣ Compare passwords using bcrypt
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Invalid password." });
    }

    // 3️⃣ Create JWT token (expires in 1 day)
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // 4️⃣ Remove password before sending user data
    const { password: _, ...userData } = user.toObject();

    // 5️⃣ Respond with user data + token
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

// server.js

// ... after your /api/login route

// FORGOT PASSWORD - STEP 1: REQUEST OTP
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        // 1. Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            // Send a generic message for security - don't reveal if an email exists
            return res.status(200).json({ message: "If an account with this email exists, an OTP has been sent." });
        }

        // 2. Generate OTP and store it
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otps[email] = { code: otp, expires: Date.now() + 10 * 60 * 1000 }; // Expires in 10 mins

        // 3. Send the OTP email
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

// FORGOT PASSWORD - STEP 2: RESET WITH OTP
app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    // 1. Verify the OTP
    const storedOtp = otps[email];
    if (!storedOtp || storedOtp.code !== otp || Date.now() > storedOtp.expires) {
        return res.status(400).json({ message: "Invalid or expired OTP." });
    }

    try {
        // 2. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // 3. Find user and update their password
        await User.updateOne({ email: email }, { $set: { password: hashedPassword } });

        // 4. Clean up the used OTP
        delete otps[email];

        res.status(200).json({ message: "Password has been reset successfully." });
    } catch (error) {
        console.error("Reset password error:", error);
        res.status(500).json({ message: "Error resetting password." });
    }
});
// Forgot Password and Reset routes would be refactored similarly to use User.findOne and user.save()

// --- PAYMENT & ORDER ROUTES (Now Protected) ---
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


// Create Razorpay Order (doesn't need to be protected)

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


// Verify Payment (doesn't need to be protected)


// Place Order (PROTECTED - only logged-in users can do this)
// This is the corrected code
app.post('/api/order/place', authenticateToken, async (req, res) => {
    const { orderDetails } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        user.orders.push(orderDetails);
        await user.save();
        
        res.status(201).json({ message: `Order #${orderDetails.id} has been placed.`, order: orderDetails });
    } catch (error) {
        // ADD THIS LINE TO PRINT THE REAL ERROR
        console.error("SERVER-SIDE ERROR PLACING ORDER:", error); 
        res.status(500).json({ message: "Error placing order." });
    }
});

// server.js

// ... after all your app.post, app.get, and other route definitions

// --- 404 NOT FOUND HANDLER (MUST BE THE LAST ROUTE) ---
app.use((req, res, next) => {
    // If the request makes it here, no route matched.
    // Respond with 404 and a JSON body to prevent the frontend SyntaxError.
    res.status(404).json({
        message: 'Endpoint Not Found. Check URL and Method.',
        requested: `${req.method} ${req.originalUrl}`
    });
});
// -----------------------------------------------------


// --- GLOBAL ERROR HANDLER (Optional, but recommended for clean errors) ---
app.use((err, req, res, next) => {
    // This catches errors thrown synchronously from any middleware/route
    console.error("GLOBAL SERVER ERROR STACK:", err.stack);
    res.status(err.status || 500).json({
        message: err.message || "Internal Server Error. Please check server logs.",
        error: err.stack // Only include stack trace in development for security
    });
});
// -----------------------------------------------------------------------


// --- SERVER START ---
const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});

// If port is in use, automatically pick a free port
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`⚠️ Port ${PORT} is busy. Trying next port...`);
    server.listen(PORT + 1);
  } else {
    console.error(err);
  }
});

// Add these new routes to server.js

// GET ALL PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error fetching products." });
    }
});

// SEARCH FOR PRODUCTS (the "where" clause)
app.get('/api/products/search', async (req, res) => {
    try {
        const searchTerm = req.query.q; // Get search term from query parameter ?q=...

        if (!searchTerm) {
            return res.status(400).json({ message: "Search term is required." });
        }

        const products = await Product.find({
            // This is the "where" part: find products where the name matches the search term.
            // $regex provides "like" functionality, and 'i' makes it case-insensitive.
            name: { $regex: searchTerm, $options: 'i' }
        });

        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ message: "Error searching for products." });
    }
});