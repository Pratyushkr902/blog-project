const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: String,
  price: { type: Number, required: true },
  image: String,
  category: String,
  stock: { type: Number, default: 0 }
});

const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);

module.exports = { Product };