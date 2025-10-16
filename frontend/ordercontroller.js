const Order = require('../models/orderModel');
const asyncHandler = require('express-async-handler');

// @desc    Create a new order
// @route   POST /api/orders
// @access  Private
const createOrder = asyncHandler(async (req, res) => {
    const { orderItems, deliveryDetails, paymentMethod, shippingPrice, grandTotal } = req.body;

    if (!orderItems || orderItems.length === 0) {
        res.status(400);
        throw new Error('No order items');
    }

    const order = new Order({
        user: req.user._id, // This comes from the 'protect' middleware
        orderItems,
        deliveryDetails,
        paymentMethod,
        shippingPrice,
        grandTotal,
    });

    const createdOrder = await order.save();
    res.status(201).json(createdOrder);
});

// @desc    Get logged in user's orders
// @route   GET /api/orders/myorders
// @access  Private
const getMyOrders = asyncHandler(async (req, res) => {
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.status(200).json(orders);
});

module.exports = {
    createOrder,
    getMyOrders,
};