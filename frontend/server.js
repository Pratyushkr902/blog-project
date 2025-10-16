// Import necessary packages
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
require('dotenv').config(); // Load environment variables from .env file

const app = express();

// --- MIDDLEWARE ---
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(express.json()); // Enable parsing of JSON request bodies

// --- IN-MEMORY DATABASE (FOR DEVELOPMENT ONLY!) ---
// WARNING: This data will be lost when the server restarts.
// For production, use a real database like MongoDB, PostgreSQL, etc.
let users = [];
let otps = {};

const SALT_ROUNDS = 10; // For hashing passwords

// --- NODEMAILER TRANSPORTER ---
// This uses your Gmail credentials from the .env file to send emails
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// --- API ROUTES ---

// 1. SIGNUP: Request an OTP
app.post('/api/signup-request-otp', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "An account with this email already exists." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes
  otps[email] = { code: otp, expires };

  const mailOptions = {
    from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'Your Jovial Flames Verification Code',
    text: `Welcome to Jovial Flames! Your One-Time Password (OTP) is: ${otp}\nThis code will expire in 10 minutes.`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending OTP:", error);
      return res.status(500).json({ message: "Failed to send OTP. Please try again later." });
    }
    console.log(`OTP sent to ${email}: ${otp}`);
    res.status(200).json({ message: "OTP sent successfully to your email." });
  });
});

// 2. SIGNUP: Verify OTP and Create User
app.post('/api/signup-verify', async (req, res) => {
  const { name, email, password, otp } = req.body;
  const storedOtp = otps[email];

  if (!storedOtp) {
    return res.status(400).json({ message: "OTP not requested or expired. Please sign up again." });
  }
  if (Date.now() > storedOtp.expires) {
    delete otps[email];
    return res.status(400).json({ message: "OTP has expired. Please try signing up again." });
  }
  if (storedOtp.code !== otp) {
    return res.status(400).json({ message: "Invalid OTP." });
  }

  // Hash the password before storing it
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  
  users.push({ name, email, password: hashedPassword, orders: [] });
  delete otps[email]; // Clean up used OTP

  console.log(`User created successfully: ${email}`);
  res.status(201).json({ message: "Account created successfully. You can now log in." });
});

// 3. LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ message: "User not found. Please check your email or sign up." });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (isPasswordCorrect) {
        // In a real app, you would return a JWT (JSON Web Token) here for authentication
        console.log(`Login successful for: ${email}`);
        // Return user data (without the password)
        const { password: _, ...userData } = user;
        res.status(200).json({ message: "Login successful.", user: userData });
    } else {
        res.status(401).json({ message: "Invalid password." });
    }
});

// 4. FORGOT PASSWORD: Request an OTP
app.post('/api/forgot-password-request-otp', (req, res) => {
    const { email } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) {
        // Send a generic message to prevent exposing which emails are registered
        return res.status(200).json({ message: "If an account with this email exists, a password reset OTP has been sent." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
    otps[email] = { code: otp, expires };

    const mailOptions = {
        from: `"Jovial Flames" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: 'Your Password Reset Code',
        text: `Your password reset OTP is: ${otp}\nThis code will expire in 10 minutes.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error sending reset OTP:", error);
        }
        console.log(`Password reset OTP sent to ${email}`);
        res.status(200).json({ message: "If an account with this email exists, a password reset OTP has been sent." });
    });
});

// 5. FORGOT PASSWORD: Verify OTP and Reset Password
app.post('/api/reset-password-verify-otp', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const storedOtp = otps[email];

    if (!storedOtp || Date.now() > storedOtp.expires || storedOtp.code !== otp) {
        return res.status(400).json({ message: "Invalid or expired OTP." });
    }

    const userIndex = users.findIndex(u => u.email === email);
    if (userIndex === -1) {
        return res.status(404).json({ message: "User not found." }); // Should not happen if OTP is valid
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    users[userIndex].password = hashedPassword;
    delete otps[email]; // Clean up

    console.log(`Password reset for ${email}`);
    res.status(200).json({ message: "Password has been reset successfully." });
});


// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 3001;

app.get('/', (req, res) => {
  res.send('Welcome to the Jovial Flames API! Server is running correctly. 🎉');
});

app.listen(PORT, () => {
  console.log(`🔥 Server is running on http://localhost:${PORT}`);
});