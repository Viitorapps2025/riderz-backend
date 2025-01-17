const jwt = require('jsonwebtoken');

// exports.identifier = (req, res, next) => {
//     const token = req.cookies.Authorization?.split(' ')[1]; // Extract token from cookie

//     if (!token) {
//         return res.status(401).json({ success: false, message: 'No token provided' });
//     }

//     try {
//         const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
//         req.user = decoded; // Attach user info to the request
//         next(); // Proceed to the next middleware or route handler
//     } catch (error) {
//         return res.status(401).json({ success: false, message: 'Invalid or expired token' });
//     }
// };




exports.identifier = (req, res, next) => {
    const authCookie = req.cookies.Authorization;
    console.log('Authorization Cookie:', authCookie); // Debug log
    const token = req.cookies.Authorization?.split(' ')[1]; // Extract token from cookie

    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        console.log('Decoded Token:', decoded); // Log the decoded token to inspect its contents
        req.user = decoded; // Attach user info to the request
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        console.error('Token Verification Error:', error); // Debug log
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
};



