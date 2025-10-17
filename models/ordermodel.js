const mongoose = require('mongoose');

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

// We only export the schema here because it's embedded in the User model.
// If you wanted a separate 'orders' collection, you would create and export a model here.
module.exports = { OrderSchema };