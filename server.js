const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const secretKey = 'yNzI4LCJleHAiOjE3MjYzMzYzMjh9.NUGcS_pdrkl4v4MHG';
let users = []; // In-memory user storage (use a DB in production)
let bankAccounts = []; // In-memory bank accounts storage (use a DB in production)

// Middleware to verify JWT
function verifyToken(req, res, next) {
    let token = req.headers['authorization'];
    if (!token) return res.status(403).send({ message: 'A token is required' });
    if (token.includes('Bearer ')) {
        token = token.replace('Bearer ', '');
    }
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(401).send({ message: 'Invalid token' });
        req.user = decoded; 
        next();
    });
}

// POST: Register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password: hashedPassword });
    res.status(201).send({ message: 'User registered successfully' });
});

// POST: Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send({ message: 'Invalid username or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send({ message: 'Invalid username or password' });

    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.status(200).send({ token, expiresIn: '1h' });
});

// GET: Protected route
app.get('/me', verifyToken, (req, res) => {
    res.status(200).send({ message: `Hello, ${req.user.username}`, info: mapBankAccount(req.user) });
});

// POST: Create a bank account (protected)
app.post('/bankAccounts', verifyToken, (req, res) => {
    const { accountNumber, balance } = req.body;

    if (!accountNumber || balance === undefined) {
        return res.status(400).send({ message: 'Account number and balance are required' });
    }

    const newAccount = { accountNumber, balance, owner: req.user.username };
    bankAccounts.push(newAccount);

    res.status(201).send({ message: 'Bank account created', account: newAccount });
});

// PUT: Update a bank account (protected)
app.put('/bankAccounts/:accountNumber', verifyToken, (req, res) => {
    const { accountNumber } = req.params;
    const { balance } = req.body;

    if (balance === undefined) {
        return res.status(400).send({ message: 'Balance is required' });
    }

    const account = bankAccounts.find(acc => acc.accountNumber === accountNumber && acc.owner === req.user.username);
    if (!account) return res.status(404).send({ message: 'Bank account not found or access denied' });

    account.balance = balance;
    res.status(200).send({ message: 'Bank account updated', account });
});

// DELETE: Delete a bank account (protected)
app.delete('/bankAccounts/:accountNumber', verifyToken, (req, res) => {
    const { accountNumber } = req.params;

    const index = bankAccounts.findIndex(acc => acc.accountNumber === accountNumber && acc.owner === req.user.username);
    if (index === -1) return res.status(404).send({ message: 'Bank account not found or access denied' });

    bankAccounts.splice(index, 1);
    res.status(200).send({ message: 'Bank account deleted' });
});

// GET: Retrieve all users with their bank accounts (protected)
app.get('/users', verifyToken, (req, res) => {
    // Retrieve all users with their associated bank accounts
    let usersWithBankAccounts = users.map(user => mapBankAccount(user));
    res.status(200).send(usersWithBankAccounts);
});

function mapBankAccount(user) {
    let userBankAccounts = bankAccounts.filter(acc => acc.owner === user.username);

    // Return user object with their bank accounts
    return {
        username: user.username,
        bankAccounts: userBankAccounts
    };
}

// GET: Retrieve all bank accounts (protected)
app.get('/bankAccounts', verifyToken, (req, res) => {
    // Assuming all authenticated users can see all bank accounts
    res.status(200).send(bankAccounts);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
