const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true }); // Create the directory if it doesn't exist
}

// Set up multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Save files to the 'uploads' directory
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Create a unique filename with the current timestamp
  }
});

// Initialize multer with the storage configuration
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // Limit file size to 10MB (optional)
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // Allowed file types
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'));
    }
    cb(null, true); // Accept the file
  }
});

module.exports = upload;
