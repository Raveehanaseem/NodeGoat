const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  // 1. Get token from cookie
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  console.log('Incoming token:', token); // Before verification

  // 2. Verify token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect('/login');
    
    // 3. Attach user data to request
    req.userId = decoded.id;
    req.isAdmin = decoded.isAdmin;
    next();
  });
};