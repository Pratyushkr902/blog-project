const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  // Get token from the 'Authorization' header, which is in the format "Bearer TOKEN"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    // Attach the decoded user payload (e.g., { id: '...', email: '...' }) to the request object
    req.user = user;
    next(); // Proceed to the next middleware or the route handler
  });
};

module.exports = { authenticateToken };