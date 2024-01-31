const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = process.env.PORT || 3000;

// Anslut till MongoDB-databasen
mongoose.connect('mongodb://localhost/serverhosting', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// Schemas för databasen
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  servers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Server' }],
  paymentInfo: { type: mongoose.Schema.Types.ObjectId, ref: 'PaymentInfo' },
});

const serverSchema = new mongoose.Schema({
  serverName: String,
  operatingSystem: String,
  configuration: String,
  status: String,
});

const paymentInfoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  encryptedCardNumber: String,
  encryptedExpirationDate: String,
  encryptedCVV: String,
});

const User = mongoose.model('User', userSchema);
const Server = mongoose.model('Server', serverSchema);
const PaymentInfo = mongoose.model('PaymentInfo', paymentInfoSchema);

// Middleware för att hantera JSON-data
app.use(bodyParser.json());

// Auth middleware
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, 'your_secret_key');
    req.userData = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Auth failed' });
  }
};

// Användarautentisering och hantering
app.post('/api/auth/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
      email: req.body.email,
    });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      return res.status(401).json({ message: 'Auth failed' });
    }
    const isPasswordValid = await bcrypt.compare(req.body.password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Auth failed' });
    }
    const token = jwt.sign({ username: user.username, userId: user._id }, 'your_secret_key', { expiresIn: '1h' });
    res.status(200).json({ token: token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serverhantering
app.post('/api/servers', authenticateUser, async (req, res) => {
  try {
    const server = new Server(req.body);
    await server.save();
    const user = await User.findById(req.userData.userId);
    user.servers.push(server);
    await user.save();
    res.status(201).json(server);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/servers', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.userData.userId).populate('servers');
    res.status(200).json(user.servers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Betalningslösning
app.post('/api/payments', authenticateUser, async (req, res) => {
  try {
    const paymentInfo = new PaymentInfo({
      userId: req.userData.userId,
      encryptedCardNumber: req.body.encryptedCardNumber,
      encryptedExpirationDate: req.body.encryptedExpirationDate,
      encryptedCVV: req.body.encryptedCVV,
    });
    await paymentInfo.save();
    const user = await User.findById(req.userData.userId);
    user.paymentInfo = paymentInfo;
    await user.save();
    res.status(201).json(paymentInfo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Starta servern
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});