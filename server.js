const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const XLSX = require('xlsx');
const fs = require('fs');
const cors = require('cors');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.json());
app.use(cors());

let users = [
  { id: 1, username: 'admin', password: bcrypt.hashSync('admin123', 8), isAdmin: true },
];

let data = [];

// Middleware to authenticate users
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  
  if (token) {
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Admin middleware
const checkAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.sendStatus(403);
  }
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, secretKey);
    res.json({ token });
  } else {
    res.status(401).send('Username or password incorrect');
  }
});

// Register endpoint (admin only)
app.post('/register', authenticateJWT, checkAdmin, (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  const newUser = { id: users.length + 1, username, password: hashedPassword, isAdmin: false };
  users.push(newUser);
  res.status(201).send('User registered');
});

// Password reset endpoint
app.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;
  const user = users.find(u => u.username === username);

  if (user) {
    user.password = bcrypt.hashSync(newPassword, 8);
    res.send('Password reset successful');
  } else {
    res.status(404).send('User not found');
  }
});

// Upload and parse Excel file
app.post('/upload', authenticateJWT, upload.single('file'), (req, res) => {
  const file = XLSX.readFile(req.file.path);
  const sheetName = file.SheetNames[0];
  data = XLSX.utils.sheet_to_json(file.Sheets[sheetName], { header: 1 }); // Read all data including headers
  fs.unlinkSync(req.file.path); // Delete the file after processing
  res.send('File uploaded and data parsed');
});

// Get data
app.get('/data', authenticateJWT, (req, res) => {
  res.json(data);
});

// Export data to Excel
app.get('/export', authenticateJWT, (req, res) => {
  const ws = XLSX.utils.aoa_to_sheet(data);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Data');
  const filePath = 'data.xlsx';
  XLSX.writeFile(wb, filePath);
  res.download(filePath, () => {
    fs.unlinkSync(filePath); // Delete the file after sending
  });
});

// Update data
app.post('/data', authenticateJWT, (req, res) => {
  data = req.body.data;
  res.send('Data updated');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});