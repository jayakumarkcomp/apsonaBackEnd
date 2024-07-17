const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

const users = [];

// Register user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  const user = { username, password: hashedPassword };
  users.push(user);
  res.send(`User created successfully!`);
});

// Login user
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(401).send('Invalid username or password');
  }
  const isValid = bcrypt.compareSync(password, user.password);
  if (!isValid) {
    return res.status(401).send('Invalid username or password');
  }
  const token = jwt.sign({ username }, 'ecretkey', { expiresIn: '1h' });
  res.send({ token });
});

// Get user profile
app.get('/profile', authenticate, (req, res) => {
  const user = users.find((user) => user.username === req.username);
  res.send(user);
});

// Middleware to authenticate requests
function authenticate(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).send('Unauthorized');
  }
  jwt.verify(token, 'ecretkey', (err, decoded) => {
    if (err) {
      return res.status(401).send('Invalid token');
    }
    req.username = decoded.username;
    next();
  });
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});