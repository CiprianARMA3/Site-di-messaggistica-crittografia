const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const { db } = require('./db');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const SECRET_KEY = "0d22afefa92681b26e9d9525ab3e4a13e575e5ae5598c7ae030d6fd9ae51a9c9"; // AES key

// --- Helper functions ---
function encrypt(text) {
    return CryptoJS.AES.encrypt(text, SECRET_KEY).toString();
}
function decrypt(cipher) {
    return CryptoJS.AES.decrypt(cipher, SECRET_KEY).toString(CryptoJS.enc.Utf8);
}

// --- Routes ---

// Home page
app.get('/', (req, res) => res.render('home', { user: null }));

// Signup
app.get('/signup', (req, res) => res.render('signup'));
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    const encryptedUsername = encrypt(username);
    const encryptedEmail = encrypt(email);

    db.run(
        "INSERT INTO database_utenti(username, password, email) VALUES(?,?,?)",
        [encryptedUsername, hashedPassword, encryptedEmail],
        (err) => {
            if (err) return res.send("Error: " + err.message);
            res.redirect('/login');
        }
    );
});

// Login
app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Encrypt input email for comparison
    const encryptedEmail = encrypt(email);

    db.get("SELECT * FROM database_utenti WHERE email=?", [encryptedEmail], (err, user) => {
        if (err) return res.send("DB error: " + err.message);
        if (!user) return res.send("Invalid login");

        const hashedInput = crypto.createHash('md5').update(password).digest('hex');
        if (hashedInput !== user.password) return res.send("Invalid login");

        const decryptedUsername = decrypt(user.username);
        const decryptedEmail = decrypt(user.email);

        res.render('home', { user: { username: decryptedUsername, email: decryptedEmail } });
    });
});

// Start server
app.listen(3000, () => console.log("Server running at http://localhost:3000"));
