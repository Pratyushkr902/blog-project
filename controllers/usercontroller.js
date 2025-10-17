const User = require('../models/userModel');
const Otp = require('../models/otpModel'); // You'll need an OTP model
const asyncHandler = require('express-async-handler');
const generateToken = require('../utils/generateToken');
const sendEmail = require('../utils/sendEmail'); // You'll need an email utility

// @desc    Request an OTP for new user registration
// @route   POST /api/auth/request-otp
// @access  Public
const requestOtp = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error('User with this email already exists');
    }

    // Generate a 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP to the database with an expiration time
    await Otp.create({ email, otp: otpCode });
    
    // Send OTP to user's email
    await sendEmail({
        to: email,
        subject: 'Your OTP for Jovial Flames',
        text: `Your verification code is: ${otpCode}. It is valid for 10 minutes.`
    });

    res.status(200).json({ message: 'OTP sent to email' });
});

// @desc    Register a new user after OTP verification
// @route   POST /api/auth/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, otp } = req.body;

    // Find the most recent OTP for this email
    const validOtp = await Otp.findOne({ email, otp }).sort({ createdAt: -1 });

    if (!validOtp) {
        res.status(400);
        throw new Error('Invalid or expired OTP');
    }

    // OTP is valid, so create the user
    const user = await User.create({ name, email, password });

    if (user) {
        // Delete the used OTP
        await Otp.deleteMany({ email });
        res.status(201).json({ message: "User registered successfully." });
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }
});

// @desc    Auth user & get token (Login)
// @route   POST /api/auth/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await user.matchPassword(password))) {
        res.json({
            _id: user._id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(401); // Unauthorized
        throw new Error('Invalid email or password');
    }
});


module.exports = {
    requestOtp,
    registerUser,
    loginUser,
    // You would add functions for forgotPassword and resetPassword here as well
};