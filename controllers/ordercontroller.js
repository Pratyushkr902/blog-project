const Order = require('../models/orderModel');

// @desc    Create a new order
// @route   POST /api/orders
const createOrder = async (req, res) => {
    const { orderItems, deliveryDetails, paymentMethod, shippingPrice, grandTotal } = req.body;

    if (orderItems && orderItems.length === 0) {
        return res.status(400).json({ message: 'No order items' });
    }

    const order = new Order({
        user: req.user._id, // From authMiddleware
        orderItems,
        deliveryDetails,
        paymentMethod,
        shippingPrice,
        grandTotal,
    });

    const createdOrder = await order.save();
    res.status(201).json(createdOrder);
};

// @desc    Get logged in user's orders
// @route   GET /api/orders/myorders
const getMyOrders = async (req, res) => {
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(orders);
};

module.exports = { createOrder, getMyOrders };