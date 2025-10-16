const express = require("express");
const router = express.Router();
const { requestOtp } = require("../controllers/authcontroller");

// @desc    Request an OTP for registration
// @route   POST /api/auth/request-otp
// @access  Public
router.post("/request-otp", requestOtp);

module.exports = router;