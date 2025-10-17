const mongoose = require('mongoose');
const { OrderSchema } = require('./Order'); // Import the OrderSchema

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  orders: [OrderSchema] // Use the imported OrderSchema here
});

const OtpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    code: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '10m' } // OTP auto-deletes after 10 mins
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Otp = mongoose.models.Otp || mongoose.model('Otp', OtpSchema);

module.exports = { User, Otp };