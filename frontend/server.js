const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const allowedOrigins = ['https://www.jovialflames.com'];
const app = express();
app.use(cors({ 
 origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true 
}));

// Important: allow preflight requests
app.options('*', cors());
app.use(express.json()); 

let users = [];
let otps = {}; 


const PORT = 3001;
// Root route
app.get('/', (req, res) => {
  res.send('Welcome to Jovial Flames API! 🎉 Server is running.');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
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
app.get('/', (req, res) => {
  res.send('Welcome to Jovial Flames API! 🎉 Server is running.');
});

// --- THIS IS YOUR SIGNUP ROUTE WITH THE DEBUGGING LOGS ---
app.post('/api/signup-request-otp', (req, res) => {
  
  // --- LOG 1 ---
  console.log('1. Signup request received for:', req.body.email);

  // Your logic to generate and send the OTP email would go here.
  // This is the part that might be slow.
  
  // --- LOG 2 ---
  console.log('2. Now sending response back to the browser.');

  // This sends a response back to the browser immediately.
  res.json({ message: "OTP request received by server." });
});
// --- END OF THE SIGNUP ROUTE ---


// Add any other API routes here...


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 

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