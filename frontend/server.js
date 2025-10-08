const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors()); 
app.use(express.json()); 

let users = [];
let otps = {}; 


const PORT = 3001;
// Root route
app.get('/', (req, res) => {
  res.send('Welcome to Jovial Flames API! 🎉 Server is running.');
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
// server.js -> The CORRECT way

// Use an "App Password" from Google, not your real password.
// We will set these values in the Render dashboard later.
let transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // Use environment variable
    pass: process.env.GMAIL_PASS  // Use environment variable
  }
});
// Inside server.js
app.post('/api/signup-request-otp', (req, res) => {
  const { email } = req.body;
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "Email already registered." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate 6-digit OTP
  otps[email] = otp;

  transporter.sendMail({
    from: '"Jovial Flames" <00pratyush20@gmail.com>',
    to: email,
    subject: 'Your Verification Code',
    text: `Your OTP for Jovial Flames is: ${otp}`
  }, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ message: "Failed to send OTP." });
    }
    console.log('OTP Sent: ' + info.response);
    res.status(200).json({ message: "OTP sent successfully." });
  });
});
// Inside server.js
app.post('/api/signup-verify', (req, res) => {
    const { name, email, password, otp } = req.body;
    if (otps[email] === otp) {
        users.push({ name, email, password, orders: [] });
        delete otps[email]; // OTP used, so remove it
        // In a real app, you would save the user to a database here
        res.status(201).json({ message: "User created successfully." });
    } else {
        res.status(400).json({ message: "Invalid OTP." });
    }
});
